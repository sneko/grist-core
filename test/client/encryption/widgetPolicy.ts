import { canAddWidgetsByUrlInEncryptedDoc, isWidgetAllowedInEncryptedDoc } from "app/client/encryption/widgetPolicy";

import { assert } from "chai";

describe("encryption/widgetPolicy", function() {
  let prevWindow: any;

  function setConfig(gristConfig: object) {
    (global as any).window = { location: { href: "https://grist.example.com/o/docs/doc/abc" }, gristConfig };
  }

  before(function() { prevWindow = (global as any).window; });
  after(function() { (global as any).window = prevWindow; });

  it("allows only widgets served by Grist itself by default", function() {
    setConfig({ homeUrl: "https://grist.example.com/", pluginUrl: "https://plugins.example.com/" });
    assert.isTrue(isWidgetAllowedInEncryptedDoc("https://grist.example.com/widgets/calendar/index.html"));
    assert.isTrue(isWidgetAllowedInEncryptedDoc("/custom-widget.html"));
    assert.isTrue(isWidgetAllowedInEncryptedDoc("https://plugins.example.com/plugins/grist-widgets/map.html"));
    assert.isFalse(isWidgetAllowedInEncryptedDoc("https://gristlabs.github.io/grist-widget/map/"));
    assert.isFalse(isWidgetAllowedInEncryptedDoc("https://grist.example.com.evil.com/widget"));
    assert.isFalse(isWidgetAllowedInEncryptedDoc("http://[invalid"));
    assert.isFalse(canAddWidgetsByUrlInEncryptedDoc());
  });

  it("allows widgets under the prefixes the server's configuration allows", function() {
    setConfig({
      homeUrl: "https://grist.example.com/",
      encryption: { mockVault: true, allowedWidgets: ["https://widgets.example.com/trusted/"] },
    });
    assert.isTrue(isWidgetAllowedInEncryptedDoc("https://widgets.example.com/trusted/chart.html"));
    assert.isFalse(isWidgetAllowedInEncryptedDoc("https://widgets.example.com/other/chart.html"));
    assert.isFalse(isWidgetAllowedInEncryptedDoc("https://widgets.example.com.evil.com/trusted/chart.html"));
    assert.isTrue(canAddWidgetsByUrlInEncryptedDoc());
  });
});
