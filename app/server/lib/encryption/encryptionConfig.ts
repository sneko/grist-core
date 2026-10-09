/**
 * Configuration of encrypted documents (named as for LaSuite Docs and Drive):
 *  - GRIST_ENCRYPTION_FEATURE_ENABLED: set to "true" to let users create encrypted documents.
 *  - GRIST_ENCRYPTION_VAULT_URL, GRIST_ENCRYPTION_INTERFACE_URL: the two origins of the LaSuite
 *    encryption service (the vault, which holds users' keys, and its interface), as for Docs'
 *    ENCRYPTION_VAULT_URL and ENCRYPTION_INTERFACE_URL.
 *  - GRIST_ENCRYPTION_MOCK_VAULT: set to "true" to use a stand-in for the encryption service, with a
 *    hardcoded key (GRIST_ENCRYPTION_MOCK_KEY, 64 hex characters, if set). Provides no security: for
 *    tests and development only, and refused when NODE_ENV is "production" (as in Grist's images).
 */
import { EncryptionClientConfig } from "app/common/gristUrls";
import { appSettings } from "app/server/lib/AppSettings";
import log from "app/server/lib/log";

let _warnedAboutMock = false;

export function getEncryptionClientConfig(): EncryptionClientConfig | undefined {
  const section = appSettings.section("encryption");
  const enabled = section.flag("enabled").readBool({
    envVar: "GRIST_ENCRYPTION_FEATURE_ENABLED", defaultValue: false,
  });
  if (!enabled) { return undefined; }
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
    return { mockVault: true, ...(mockKey ? { mockKey } : {}) };
  }
  if (!vaultUrl || !interfaceUrl) {
    throw new Error("GRIST_ENCRYPTION_FEATURE_ENABLED requires GRIST_ENCRYPTION_VAULT_URL and " +
      "GRIST_ENCRYPTION_INTERFACE_URL (or GRIST_ENCRYPTION_MOCK_VAULT for testing)");
  }
  return { vaultUrl, interfaceUrl };
}

export function isEncryptionEnabled(): boolean {
  return Boolean(getEncryptionClientConfig());
}
