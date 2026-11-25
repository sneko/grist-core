import { pickDocLocale } from "app/common/Locales";

import { assert } from "chai";

describe("Locales", function() {
  describe("pickDocLocale", function() {
    it("takes the first language-REGION that Grist knows", function() {
      assert.equal(pickDocLocale(["fr-FR", "en-US"]), "fr-FR");
      assert.equal(pickDocLocale(["fr", "de-DE", "en-US"]), "de-DE");
      assert.equal(pickDocLocale(["en_gb"]), "en-GB");
    });

    it("passes over what Intl would refuse, such as a POSIX modifier", function() {
      assert.equal(pickDocLocale(["en-US@posix"]), "en-US");
      assert.equal(pickDocLocale(["en-US@posix", "fr-FR"]), "fr-FR");
      assert.equal(pickDocLocale(["C", "POSIX", ""]), "en-US");
      assert.equal(pickDocLocale(["xx-ZZ"]), "en-US");
      assert.equal(pickDocLocale([]), "en-US");
      assert.equal(pickDocLocale(["en-US@posix"], "fr-FR"), "fr-FR");
    });

    it("gives a locale Intl accepts", function() {
      for (const languages of [["en-US@posix"], ["fr-FR"], ["en_gb"], []]) {
        assert.doesNotThrow(() => new Intl.NumberFormat(pickDocLocale(languages)));
      }
    });
  });
});
