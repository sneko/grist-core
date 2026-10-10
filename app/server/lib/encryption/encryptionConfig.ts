/**
 * Configuration of encrypted documents (named as for LaSuite Docs and Drive):
 *  - GRIST_ENCRYPTION_FEATURE_ENABLED: set to "true" to let users create encrypted documents.
 *  - GRIST_ENCRYPTION_VAULT_URL, GRIST_ENCRYPTION_INTERFACE_URL: the two origins of the LaSuite
 *    encryption service (the vault, which holds users' keys, and its interface), as for Docs'
 *    ENCRYPTION_VAULT_URL and ENCRYPTION_INTERFACE_URL.
 *  - GRIST_ENCRYPTION_MOCK_VAULT: set to "true" to use a stand-in for the encryption service, with a
 *    hardcoded key (GRIST_ENCRYPTION_MOCK_KEY, 64 hex characters, if set). Provides no security: for
 *    tests and development only, and refused when NODE_ENV is "production" (as in Grist's images).
 *  - GRIST_ENCRYPTION_ALLOWED_WIDGETS: comma-separated URL prefixes of custom widgets that may be
 *    used in encrypted documents (they get to see the document's content). By default, only
 *    widgets served by Grist itself.
 *  - GRIST_ENCRYPTION_MAX_DOC_SIZE_MB: the most an encrypted document (its history, snapshots
 *    and attachments, all encrypted) may take on the server, when the site's plan sets no limit.
 *
 * The configuration is checked when the server starts (see FlexServer), so that a mistake is
 * reported then, rather than on each page.
 */
import { EncryptionClientConfig } from "app/common/gristUrls";
import { appSettings } from "app/server/lib/AppSettings";
import log from "app/server/lib/log";

const ENV_VARS = [
  "GRIST_ENCRYPTION_FEATURE_ENABLED", "GRIST_ENCRYPTION_VAULT_URL", "GRIST_ENCRYPTION_INTERFACE_URL",
  "GRIST_ENCRYPTION_MOCK_VAULT", "GRIST_ENCRYPTION_MOCK_KEY", "GRIST_ENCRYPTION_ALLOWED_WIDGETS", "NODE_ENV",
];

let _cached: { key: string, result: EncryptionClientConfig | undefined } | undefined;
let _warnedAboutMock = false;

/**
 * The configuration browsers need, or undefined if encrypted documents aren't enabled. Throws if
 * the configuration is invalid.
 */
export function getEncryptionClientConfig(): EncryptionClientConfig | undefined {
  // Only read (and check) the settings again if the environment changed (as in tests).
  const key = ENV_VARS.map(name => process.env[name] ?? "").join("\n");
  if (_cached?.key !== key) {
    _cached = { key, result: readEncryptionConfig() };
  }
  return _cached.result;
}

export function isEncryptionEnabled(): boolean {
  return Boolean(getEncryptionClientConfig());
}

/** The most an encrypted document may take on the server, in bytes, if limited by configuration. */
export function getMaxEncryptedDocSize(): number | undefined {
  const mb = appSettings.section("encryption").flag("maxDocSizeMb").readInt({
    envVar: "GRIST_ENCRYPTION_MAX_DOC_SIZE_MB",
  });
  return mb ? mb * 1024 * 1024 : undefined;
}

function readEncryptionConfig(): EncryptionClientConfig | undefined {
  const section = appSettings.section("encryption");
  const enabled = section.flag("enabled").readBool({
    envVar: "GRIST_ENCRYPTION_FEATURE_ENABLED", defaultValue: false,
  });
  if (!enabled) { return undefined; }
  const allowedWidgetsSetting = section.flag("allowedWidgets")
    .readString({ envVar: "GRIST_ENCRYPTION_ALLOWED_WIDGETS" });
  const allowedWidgets = (allowedWidgetsSetting || "").split(",").map(s => s.trim()).filter(Boolean);
  for (const prefix of allowedWidgets) {
    if (!/^https?:\/\/[^/]+\//.test(prefix)) {
      throw new Error(`GRIST_ENCRYPTION_ALLOWED_WIDGETS: "${prefix}" must be a URL prefix ending with a path, ` +
        `e.g. "https://widgets.example.com/"`);
    }
  }
  const common = allowedWidgets.length > 0 ? { allowedWidgets } : {};
  const mock = section.flag("mockVault").readBool({ envVar: "GRIST_ENCRYPTION_MOCK_VAULT", defaultValue: false });
  const vaultUrl = section.flag("vaultUrl").readString({ envVar: "GRIST_ENCRYPTION_VAULT_URL" });
  const interfaceUrl = section.flag("interfaceUrl").readString({ envVar: "GRIST_ENCRYPTION_INTERFACE_URL" });
  if (mock) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("GRIST_ENCRYPTION_MOCK_VAULT provides no security, and can't be used in production " +
        "(NODE_ENV=production): set GRIST_ENCRYPTION_VAULT_URL and GRIST_ENCRYPTION_INTERFACE_URL instead");
    }
    if (!_warnedAboutMock) {
      _warnedAboutMock = true;
      log.warn("Encrypted documents use GRIST_ENCRYPTION_MOCK_VAULT: a hardcoded key, NOT secure (tests only)");
    }
    const mockKey = section.flag("mockKey").readString({ envVar: "GRIST_ENCRYPTION_MOCK_KEY" });
    if (mockKey && !/^[0-9a-fA-F]{64}$/.test(mockKey)) {
      throw new Error("GRIST_ENCRYPTION_MOCK_KEY must be 64 hex characters");
    }
    return { mockVault: true, ...(mockKey ? { mockKey } : {}), ...common };
  }
  if (!vaultUrl || !interfaceUrl) {
    throw new Error("GRIST_ENCRYPTION_FEATURE_ENABLED requires GRIST_ENCRYPTION_VAULT_URL and " +
      "GRIST_ENCRYPTION_INTERFACE_URL (or GRIST_ENCRYPTION_MOCK_VAULT for testing)");
  }
  return { vaultUrl, interfaceUrl, ...common };
}
