/**
 * The providers of users' encryption keys, as the server knows them (see EncryptionProviderConfig
 * in app/common/gristUrls.ts, and app/client/encryption/providers for what browsers do with them).
 *
 * The server never holds keys: it stores documents' keys only as the provider wrapped them for each
 * member, and relays ciphertext. What it needs from a provider is little:
 *  - its settings, read and checked when the server starts, then handed to browsers;
 *  - whether it requires users to sign in with OIDC (checked when the server starts);
 *  - how the provider knows a Grist user (`userIdFor`), which browsers use to give them keys;
 *  - pages of its own, if any (e.g. where a sign-in to the provider comes back).
 *
 * Adding a provider: an entry here, its settings in EncryptionProviderConfig, and its key vault in
 * app/client/encryption/providers (registered in app/client/encryption/keyVaults.ts), each tested.
 */
import { OPENBAO_CALLBACK_CHANNEL, OPENBAO_CALLBACK_PATH } from "app/common/encryption/OpenBaoKeyVault";
import { EncryptionProviderConfig } from "app/common/gristUrls";
import { UserOptions } from "app/common/UserAPI";
import { AppSettings } from "app/server/lib/AppSettings";
import log from "app/server/lib/log";

import * as express from "express";

/** The user record the server knows, as far as identifying them to a provider goes. */
export interface ProviderUser {
  id: number;
  options?: UserOptions | null;
}

export interface ServerEncryptionProvider {
  /**
   * Whether users must sign in to Grist with OIDC (GRIST_OIDC_IDP_*): the provider knows them by
   * their OIDC subject, and signs them in with the same identity provider.
   */
  requiresOidc: boolean;
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
  /** Serves the provider's own pages, if any. */
  addEndpoints?(app: express.Application): void;
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
    requiresOidc: true,
  },

  /**
   * OpenBao (or HashiCorp Vault), with a key for each user in its transit secrets engine (see
   * app/common/encryption/OpenBaoKeyVault.ts). Users are known by their OIDC subject, their key
   * being named after it, and sign in to OpenBao with the identity provider Grist uses.
   */
  openbao: {
    readConfig(section) {
      const settings = section.section("openbao");
      const url = settings.flag("url").readString({ envVar: "GRIST_ENCRYPTION_OPENBAO_URL" });
      if (!url) {
        throw new Error("The \"openbao\" encryption provider requires GRIST_ENCRYPTION_OPENBAO_URL (OpenBao's origin)");
      }
      if (!/^https?:\/\/[^/]+\/?$/.test(url)) {
        throw new Error(`GRIST_ENCRYPTION_OPENBAO_URL must be an origin, such as https://openbao.example.com (got "${url}")`);
      }
      if (url.startsWith("http:") && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?\/?$/.test(url)) {
        // (Tokens and document keys would go over it in the clear.)
        log.warn(`GRIST_ENCRYPTION_OPENBAO_URL is not https (${url}): only for trying things out`);
      }
      const read = (flag: string, envVar: string, defaultValue: string, pattern: RegExp) => {
        const value = settings.flag(flag).readString({ envVar, defaultValue })!;
        if (!pattern.test(value)) { throw new Error(`${envVar}: "${value}" is not a valid name`); }
        return value;
      };
      const mount = /^[A-Za-z0-9](?:[A-Za-z0-9_\-/]*[A-Za-z0-9])?$/;
      return {
        kind: "openbao",
        url: url.replace(/\/$/, ""),
        authMount: read("authMount", "GRIST_ENCRYPTION_OPENBAO_AUTH_MOUNT", "oidc", mount),
        role: read("role", "GRIST_ENCRYPTION_OPENBAO_ROLE", "grist", /^[A-Za-z0-9_-]+$/),
        transitMount: read("transitMount", "GRIST_ENCRYPTION_OPENBAO_TRANSIT_MOUNT", "transit", mount),
        // (Not empty: the policy gives everyone access to the keys it names, and only those must be Grist's.)
        keyPrefix: read("keyPrefix", "GRIST_ENCRYPTION_OPENBAO_KEY_PREFIX", "grist-user-", /^\w[\w.-]*$/),
      };
    },
    userIdFor(user) {
      return user.options?.authSubject ?? null;
    },
    requiresOidc: true,
    // Where the sign-in tab comes back (the OIDC role's allowed redirect URI): it hands what it
    // came back with to the page that opened it, on Grist's origin, which finishes the sign-in with
    // OpenBao (its script is a file of its own, for pages under a Content-Security-Policy).
    addEndpoints(app) {
      app.get(OPENBAO_CALLBACK_PATH, (_req, res) => {
        res.set("Cache-Control", "no-store");
        res.set("Referrer-Policy", "no-referrer");
        res.type("html").send(OPENBAO_CALLBACK_PAGE);
      });
      app.get(`${OPENBAO_CALLBACK_PATH}.js`, (_req, res) => {
        res.set("Cache-Control", "no-cache");
        res.type("js").send(OPENBAO_CALLBACK_SCRIPT);
      });
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
      const key = section.section("mock").flag("key").readString({ envVar: "GRIST_ENCRYPTION_MOCK_KEY" });
      if (key && !/^[0-9a-fA-F]{64}$/.test(key)) {
        throw new Error("GRIST_ENCRYPTION_MOCK_KEY must be 64 hex characters");
      }
      return { kind: "mock", ...(key ? { key } : {}) };
    },
    userIdFor(user) {
      return user.options?.authSubject ?? `grist-user-${user.id}`;
    },
    requiresOidc: false,
  },
};

const OPENBAO_CALLBACK_PAGE = `<!doctype html>
<html><head><meta charset="utf-8"><title>Grist</title>
<script src="${OPENBAO_CALLBACK_PATH}.js"></script></head>
<body><p>Signed in to the key service. You can close this window.</p></body></html>
`;

// Hands the query string to the page that opened the tab, and on a channel between Grist's pages
// for when the identity provider severed the tab from it (Cross-Origin-Opener-Policy).
const OPENBAO_CALLBACK_SCRIPT = `(function () {
  var message = { gristOpenBaoCallback: window.location.search };
  try {
    if (window.opener) { window.opener.postMessage(message, window.location.origin); }
  } catch (e) { /* Severed from it. */ }
  try {
    var channel = new BroadcastChannel(${JSON.stringify(OPENBAO_CALLBACK_CHANNEL)});
    channel.postMessage(message);
    channel.close();
  } catch (e) { /* No BroadcastChannel. */ }
  window.close();
})();
`;

export function isEncryptionProviderKind(kind: string): kind is EncryptionProviderConfig["kind"] {
  return Object.prototype.hasOwnProperty.call(encryptionProviders, kind);
}
