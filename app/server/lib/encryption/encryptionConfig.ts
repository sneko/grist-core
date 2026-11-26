/**
 * Configuration of encrypted documents:
 *  - GRIST_ENCRYPTION_FEATURE_ENABLED: set to "true" to let users create encrypted documents.
 *  - GRIST_ENCRYPTION_PROVIDER: who holds users' keys (see encryptionProviders.ts), with its own
 *    settings:
 *    - "lasuite", the LaSuite encryption service: GRIST_ENCRYPTION_LASUITE_VAULT_URL and
 *      GRIST_ENCRYPTION_LASUITE_INTERFACE_URL, the origins of its vault (which holds users' keys) and
 *      of its interface, as for LaSuite Docs' ENCRYPTION_VAULT_URL and ENCRYPTION_INTERFACE_URL
 *      (GRIST_ENCRYPTION_VAULT_URL and GRIST_ENCRYPTION_INTERFACE_URL, their former names, still work);
 *    - "openbao", OpenBao or HashiCorp Vault (see encryptionProviders.ts): GRIST_ENCRYPTION_OPENBAO_URL,
 *      and optionally GRIST_ENCRYPTION_OPENBAO_AUTH_MOUNT, _ROLE, _TRANSIT_MOUNT and _KEY_PREFIX;
 *    - "mock", a stand-in with a hardcoded key (GRIST_ENCRYPTION_MOCK_KEY, 64 hex characters, if
 *      set). Provides no security: for tests and development only, and refused when NODE_ENV is
 *      "production" (as in Grist's images).
 *    When unset: "mock" if GRIST_ENCRYPTION_MOCK_VAULT is "true" (its former setting), else "lasuite".
 *  - GRIST_ENCRYPTION_ALLOWED_WIDGETS: comma-separated URL prefixes of custom widgets that may be
 *    used in encrypted documents (they get to see the document's content). By default, only
 *    widgets served by Grist itself.
 *  - GRIST_ENCRYPTION_MAX_DOC_SIZE_MB: the most an encrypted document (its history, snapshots
 *    and attachments, all encrypted) may take on the server, when the site's plan sets no limit.
 *  - GRIST_ENCRYPTION_ASSISTANT: an AI service for the formula assistant of encrypted documents,
 *    which browsers call directly (with each user's consent), as JSON (see
 *    EncryptionAssistantConfig), e.g. {"endpoint": "https://albert.api.etalab.gouv.fr/v1/chat/completions",
 *    "model": "albert-large", "provider": "Albert (DINUM)", "sovereign": true, "auth": "user-key"}.
 *
 * The configuration is checked when the server starts (see FlexServer), so that a mistake is
 * reported then, rather than on each page.
 */
import { EncryptionAssistantConfig, EncryptionClientConfig } from "app/common/gristUrls";
import { isAffirmative } from "app/common/gutil";
import { GETGRIST_COM_PROVIDER_KEY, OIDC_PROVIDER_KEY } from "app/common/loginProviders";
import { appSettings } from "app/server/lib/AppSettings";
import {
  encryptionProviders, isEncryptionProviderKind, ProviderUser,
} from "app/server/lib/encryption/encryptionProviders";
import { getActiveLoginSystemType } from "app/server/lib/loginSystemHelpers";

import * as express from "express";

const ENV_VARS = [
  "GRIST_ENCRYPTION_FEATURE_ENABLED", "GRIST_ENCRYPTION_PROVIDER",
  "GRIST_ENCRYPTION_LASUITE_VAULT_URL", "GRIST_ENCRYPTION_LASUITE_INTERFACE_URL",
  "GRIST_ENCRYPTION_VAULT_URL", "GRIST_ENCRYPTION_INTERFACE_URL",
  "GRIST_ENCRYPTION_OPENBAO_URL", "GRIST_ENCRYPTION_OPENBAO_AUTH_MOUNT", "GRIST_ENCRYPTION_OPENBAO_ROLE",
  "GRIST_ENCRYPTION_OPENBAO_TRANSIT_MOUNT", "GRIST_ENCRYPTION_OPENBAO_KEY_PREFIX", "GRIST_OIDC_IDP_ISSUER",
  "GRIST_LOGIN_SYSTEM_TYPE", "GRIST_TEST_LOGIN", "GRIST_GETGRISTCOM_SECRET",
  "GRIST_ENCRYPTION_MOCK_VAULT", "GRIST_ENCRYPTION_MOCK_KEY", "GRIST_ENCRYPTION_ALLOWED_WIDGETS",
  "GRIST_ENCRYPTION_ASSISTANT", "NODE_ENV",
];

let _cached: { key: string, result: EncryptionClientConfig | undefined } | undefined;

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

/**
 * How the configured provider identifies a user, to give them keys (null if it can't, or if
 * encrypted documents aren't enabled).
 */
export function encryptionUserIdFor(user: ProviderUser | null | undefined): string | null {
  const config = getEncryptionClientConfig();
  if (!config || !user) { return null; }
  return encryptionProviders[config.provider.kind].userIdFor(user);
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
  const assistant = readAssistantConfig(section.flag("assistant").readString({ envVar: "GRIST_ENCRYPTION_ASSISTANT" }));
  const common = {
    ...(allowedWidgets.length > 0 ? { allowedWidgets } : {}),
    ...(assistant ? { assistant } : {}),
  };
  const mock = section.flag("mockVault").readBool({ envVar: "GRIST_ENCRYPTION_MOCK_VAULT", defaultValue: false });
  const kind = section.flag("provider").readString({ envVar: "GRIST_ENCRYPTION_PROVIDER" }) ||
    (mock ? "mock" : "lasuite");
  if (!isEncryptionProviderKind(kind)) {
    throw new Error(`GRIST_ENCRYPTION_PROVIDER: unknown provider "${kind}" ` +
      `(known: ${Object.keys(encryptionProviders).join(", ")})`);
  }
  const provider = encryptionProviders[kind];
  const config = provider.readConfig(section);
  if (provider.requiresOidc && !isOidcTheLoginSystem()) {
    throw new Error(`The "${kind}" encryption provider requires users to sign in with OIDC ` +
      "(GRIST_OIDC_IDP_ISSUER and the other GRIST_OIDC_* settings, and no other login system: " +
      "GRIST_LOGIN_SYSTEM_TYPE unset or \"oidc\", no GRIST_TEST_LOGIN, and when unset, no " +
      "GRIST_GETGRISTCOM_SECRET): it knows them by their OIDC subject");
  }
  return { provider: config, ...common };
}

/** Serves the configured provider's own pages, if any (e.g. where a sign-in to it comes back). */
export function addEncryptionProviderEndpoints(app: express.Application) {
  const config = getEncryptionClientConfig();
  if (config) { encryptionProviders[config.provider.kind].addEndpoints?.(app); }
}

// Whether users sign in with OIDC: configured, and not replaced by another login system.
function isOidcTheLoginSystem() {
  if (isAffirmative(process.env.GRIST_TEST_LOGIN)) { return false; }
  const type = getActiveLoginSystemType(appSettings);
  if (type && type !== OIDC_PROVIDER_KEY) { return false; }
  // (Unless another one is chosen, getgrist.com's sign-in comes first when configured.)
  if (!type && isGetGristComConfigured()) { return false; }
  return Boolean(appSettings.section("login").section("system").section(OIDC_PROVIDER_KEY)
    .flag("issuer").readString({ envVar: "GRIST_OIDC_IDP_ISSUER" }));
}

// (As GetGristComConfig.ts reads it, which can't be imported here: it would make a cycle.)
function isGetGristComConfigured() {
  return Boolean(appSettings.section("login").section("system").section(GETGRIST_COM_PROVIDER_KEY)
    .flag("secret").readString({ envVar: "GRIST_GETGRISTCOM_SECRET", censor: true }));
}

function readAssistantConfig(setting: string | undefined): EncryptionAssistantConfig | undefined {
  if (!setting) { return undefined; }
  const fail = (why: string) => {
    throw new Error(`GRIST_ENCRYPTION_ASSISTANT: ${why} (expected JSON like {"endpoint": "https://...", ` +
      `"model": "...", "provider": "...", "sovereign": true, "auth": "user-key"})`);
  };
  let value: any;
  try {
    value = JSON.parse(setting);
  } catch (e) {
    return fail("invalid JSON");
  }
  if (typeof value?.endpoint !== "string" || !/^https:\/\/[^/]+\//.test(value.endpoint)) {
    fail("endpoint must be an https URL");
  }
  if (typeof value.provider !== "string" || !value.provider) { fail("provider must say who runs the service"); }
  if (typeof value.sovereign !== "boolean") { fail("sovereign must be true or false"); }
  if (value.auth !== "user-key" && value.auth !== "none") { fail(`auth must be "user-key" or "none"`); }
  if (value.model !== undefined && typeof value.model !== "string") { fail("model must be a string"); }
  return {
    endpoint: value.endpoint, provider: value.provider, sovereign: value.sovereign, auth: value.auth,
    ...(value.model ? { model: value.model } : {}),
  };
}
