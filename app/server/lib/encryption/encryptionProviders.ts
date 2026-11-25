/**
 * The providers of users' encryption keys, as the server knows them (see EncryptionProviderConfig
 * in app/common/gristUrls.ts, and app/client/encryption/providers for what browsers do with them).
 *
 * The server never holds keys: it stores documents' keys only as the provider wrapped them for each
 * member, and relays ciphertext. What it needs from a provider is little:
 *  - its settings, read and checked when the server starts, then handed to browsers;
 *  - how the provider knows a Grist user (`userIdFor`), which browsers use to give them keys.
 *
 * Adding a provider: an entry here, its settings in EncryptionProviderConfig, and its key vault in
 * app/client/encryption/providers (registered in app/client/encryption/keyVaults.ts), each tested.
 */
import { EncryptionProviderConfig } from "app/common/gristUrls";
import { UserOptions } from "app/common/UserAPI";
import { AppSettings } from "app/server/lib/AppSettings";
import log from "app/server/lib/log";

/** The user record the server knows, as far as identifying them to a provider goes. */
export interface ProviderUser {
  id: number;
  options?: UserOptions | null;
}

export interface ServerEncryptionProvider {
  /**
   * Reads and checks the provider's settings (in GRIST_ENCRYPTION_* variables, or the "encryption"
   * section of the settings). Throws when they're missing or wrong.
   */
  readConfig(section: AppSettings): EncryptionProviderConfig;
  /**
   * How the provider identifies a user: the id under which it knows their keys. Null when the
   * provider can't know them (yet), e.g. a user who never signed in the way it requires.
   */
  userIdFor(user: ProviderUser): string | null;
}

let _warnedAboutMock = false;

export const encryptionProviders: Record<EncryptionProviderConfig["kind"], ServerEncryptionProvider> = {
  /**
   * The LaSuite encryption service. Users are known to it by their OIDC subject (`sub`), which
   * Grist links to the user on their first OIDC sign-in, so Grist and the service must share the
   * identity provider, as LaSuite Docs and Drive do.
   */
  lasuite: {
    readConfig(section) {
      // (GRIST_ENCRYPTION_VAULT_URL and GRIST_ENCRYPTION_INTERFACE_URL are their former names.)
      const settings = section.section("lasuite");
      const vaultUrl = settings.flag("vaultUrl").readString({
        envVar: ["GRIST_ENCRYPTION_LASUITE_VAULT_URL", "GRIST_ENCRYPTION_VAULT_URL"],
        preferredEnvVar: "GRIST_ENCRYPTION_LASUITE_VAULT_URL",
      });
      const interfaceUrl = settings.flag("interfaceUrl").readString({
        envVar: ["GRIST_ENCRYPTION_LASUITE_INTERFACE_URL", "GRIST_ENCRYPTION_INTERFACE_URL"],
        preferredEnvVar: "GRIST_ENCRYPTION_LASUITE_INTERFACE_URL",
      });
      if (!vaultUrl || !interfaceUrl) {
        throw new Error("The \"lasuite\" encryption provider requires GRIST_ENCRYPTION_LASUITE_VAULT_URL and " +
          "GRIST_ENCRYPTION_LASUITE_INTERFACE_URL (the origins of the LaSuite encryption service's vault and " +
          "interface)");
      }
      const origins = [
        ["GRIST_ENCRYPTION_LASUITE_VAULT_URL", vaultUrl], ["GRIST_ENCRYPTION_LASUITE_INTERFACE_URL", interfaceUrl],
      ];
      for (const [name, url] of origins) {
        if (!/^https?:\/\/[^/]+\/?$/.test(url)) {
          throw new Error(`${name} must be an origin, such as https://vault.example.com (got "${url}")`);
        }
      }
      return { kind: "lasuite", vaultUrl, interfaceUrl };
    },
    userIdFor(user) {
      return user.options?.authSubject ?? null;
    },
  },

  /**
   * A stand-in with a hardcoded key: it exercises the whole flow (document keys, column keys,
   * rotation) but protects nothing. Refused in production. Users are known by their OIDC subject
   * when they have one, else by their Grist id, so that any sign-in works in tests.
   */
  mock: {
    readConfig(section) {
      if (process.env.NODE_ENV === "production") {
        throw new Error("The \"mock\" encryption provider provides no security, and can't be used in " +
          "production (NODE_ENV=production): use a real provider, such as \"lasuite\"");
      }
      if (!_warnedAboutMock) {
        _warnedAboutMock = true;
        log.warn("Encrypted documents use the \"mock\" encryption provider: a hardcoded key, NOT secure (tests only)");
      }
      const key = section.flag("mockKey").readString({ envVar: "GRIST_ENCRYPTION_MOCK_KEY" });
      if (key && !/^[0-9a-fA-F]{64}$/.test(key)) {
        throw new Error("GRIST_ENCRYPTION_MOCK_KEY must be 64 hex characters");
      }
      return { kind: "mock", ...(key ? { key } : {}) };
    },
    userIdFor(user) {
      return user.options?.authSubject ?? `grist-user-${user.id}`;
    },
  },
};

export function isEncryptionProviderKind(kind: string): kind is EncryptionProviderConfig["kind"] {
  return Object.prototype.hasOwnProperty.call(encryptionProviders, kind);
}
