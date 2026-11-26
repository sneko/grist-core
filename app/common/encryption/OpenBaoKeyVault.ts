/**
 * The "openbao" key provider: OpenBao (https://openbao.org, or HashiCorp Vault, whose API it
 * shares), with a key of its own for each user in its transit secrets engine.
 *
 * - A member's copy of a document key is the key encrypted by OpenBao with that member's key
 *   (named `<keyPrefix><vaultUserId>`, their OIDC subject): OpenBao's ciphertext, which says the
 *   version of the key it was made with (`vault:v3:...`), so that keys can be rotated in OpenBao
 *   and older copies still be unwrapped.
 * - Each user creates their own key (a plain AES-GCM key, as the policy imposes) when they sign in;
 *   anyone signed in may then wrap a key for them, giving nothing but the key to wrap, and only
 *   they can unwrap with it. OpenBao's policy (openBaoPolicy() below) enforces all of it, so a copy
 *   is of no use to anyone else, and nobody can create or tamper with someone else's key.
 * - Users sign in to OpenBao with the identity provider Grist uses: OpenBao runs the OIDC sign-in
 *   itself (as a confidential client), in a window of its own (a pop-up), and gives the browser a token. Grist's
 *   server never gets it, nor the document keys.
 * - Content is encrypted in the page with the document keys (see LocalCryptoKeyVault).
 *
 * What it protects against: Grist's server, its administrators, its database and storage, which
 * only get ciphertext and wrapped keys. Not against OpenBao's operators (who can use any user's
 * key), nor the identity provider's (who can sign in as anyone), nor against a Grist server
 * serving pages modified to take the token (see documentation/encryption.md).
 *
 * Used in browsers (app/client/encryption/providers/openbao.ts) and in Node tests alike.
 */
import {
  base64ToBytes, bytesToBase64, KeyRecipient, KeySetupKind, LocalCryptoKeyVault, utf8Decode, utf8Encode, WrappedKey,
} from "app/common/encryption/EncryptionCrypto";
import { OpenBaoEncryptionProviderConfig } from "app/common/gristUrls";

/** The page of Grist where the sign-in tab comes back, as the OpenBao role's allowed redirect URI. */
export const OPENBAO_CALLBACK_PATH = "/encryption/openbao-callback";

/** The channel the callback page also hands the result on (see the callback page's script). */
export const OPENBAO_CALLBACK_CHANNEL = "grist-openbao-sign-in";

/** The only kind of key users may create for themselves (as openBaoPolicy() imposes). */
const KEY_TYPE = "aes256-gcm96";

/**
 * The policy to give users in OpenBao (their role's only token policy, without OpenBao's `default`
 * one, which also lets them store data in OpenBao), for the given settings and the accessor of its
 * OIDC auth method: create one's own key (of the plain kind only), see whose keys exist, wrap a
 * key for anyone (only giving the key to wrap), unwrap with one's own key only, and look up, renew
 * and revoke one's own token. Keys are named after the alias the OIDC role gives users (their
 * `sub`, with user_claim=sub). (No `max_wrapping_ttl` against answers kept in OpenBao by response
 * wrapping: OpenBao would then require wrapping. See documentation/encryption.md for the limits.)
 */
export function openBaoPolicy(config: Pick<OpenBaoEncryptionProviderConfig, "transitMount" | "keyPrefix">,
  oidcAccessor: string) {
  const keys = `${config.transitMount}/keys/${config.keyPrefix}`;
  const own = `{{identity.entity.aliases.${oidcAccessor}.name}}`;
  return [
    // (Exact paths win over globs, without merging: one's own key's path also says `read`.)
    `path "${keys}${own}" { capabilities = ["create", "read", "update"] ` +
    `allowed_parameters = { "type" = ["${KEY_TYPE}"] } }`,
    `path "${keys}*" { capabilities = ["read"] }`,
    `path "${config.transitMount}/encrypt/${config.keyPrefix}*" { capabilities = ["update"] ` +
    `allowed_parameters = { "plaintext" = [] } }`,
    `path "${config.transitMount}/decrypt/${config.keyPrefix}${own}" { capabilities = ["update"] ` +
    `allowed_parameters = { "ciphertext" = [] } }`,
    `path "auth/token/lookup-self" { capabilities = ["read"] }`,
    `path "auth/token/renew-self" { capabilities = ["update"] }`,
    `path "auth/token/revoke-self" { capabilities = ["update"] }`,
  ].join("\n") + "\n";
}

/** What a sign-in to OpenBao gives: its token, until when (null: no expiry), and who it's for. */
export interface OpenBaoSession {
  token: string;
  expiresAt: number | null;  // Epoch milliseconds.
  subject: string;           // The user's OIDC subject (the role maps `sub` to `subject`).
}

export class OpenBaoError extends Error {
  constructor(message: string, public readonly status?: number) { super(message); }
}

/** No sign-in to OpenBao (any longer): none kept, or one expired or revoked. */
export class NotSignedInToOpenBaoError extends Error {
  constructor() {
    super("Not signed in to the key service (or the sign-in expired): reload the page to sign in again");
  }
}

/** Calls OpenBao's HTTP API. */
export class OpenBaoClient {
  constructor(private _config: OpenBaoEncryptionProviderConfig) {}

  public async request(method: "GET" | "POST", path: string, options: { token?: string, body?: object } = {}) {
    let response: Response;
    try {
      response = await fetch(`${this._config.url.replace(/\/$/, "")}/v1/${path}`, {
        method,
        headers: {
          ...(options.token ? { "X-Vault-Token": options.token } : {}),
          ...(options.body ? { "Content-Type": "application/json" } : {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
      });
    } catch (e) {
      throw new OpenBaoError(`The key service (${this._config.url}) can't be reached: ${(e as Error).message}`);
    }
    const text = await response.text();
    let json: any = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* Reported below. */ }
    if (!response.ok) {
      const detail = (json?.errors ?? []).join("; ").replace(/\s+/g, " ").trim() || response.statusText;
      throw new OpenBaoError(`The key service refused (${response.status}): ${detail}`, response.status);
    }
    return json;
  }
}

/**
 * Starts a sign-in to OpenBao: the URL of the identity provider to open in a window, the `state` the
 * tab will come back with, and a secret the caller keeps to finish it (OpenBao refuses the
 * callback without it, so a code that leaks from the tab is of no use).
 */
export async function startOpenBaoSignIn(config: OpenBaoEncryptionProviderConfig, redirectUri: string) {
  const clientNonce = bytesToBase64(crypto.getRandomValues(new Uint8Array(24))).replace(/[^A-Za-z0-9]/g, "");
  const result = await new OpenBaoClient(config).request("POST", `auth/${config.authMount}/oidc/auth_url`, {
    body: { role: config.role, redirect_uri: redirectUri, client_nonce: clientNonce },
  });
  const authUrl: string | undefined = result?.data?.auth_url;
  if (!authUrl) {
    throw new OpenBaoError("The key service gave no sign-in URL: check that the OIDC role allows " +
      `${redirectUri} as a redirect URI`);
  }
  return { authUrl, clientNonce, state: new URL(authUrl).searchParams.get("state") ?? "" };
}

/** Finishes a sign-in to OpenBao, from the query string the tab came back with. */
export async function finishOpenBaoSignIn(config: OpenBaoEncryptionProviderConfig, callbackSearch: string,
  clientNonce: string): Promise<OpenBaoSession> {
  const params = new URLSearchParams(callbackSearch);
  if (params.get("error")) {
    throw new OpenBaoError(
      `The sign-in to the key service failed: ${params.get("error_description") || params.get("error")}`);
  }
  const query = new URLSearchParams({
    state: params.get("state") ?? "", code: params.get("code") ?? "", client_nonce: clientNonce,
  });
  const result = await new OpenBaoClient(config).request("GET", `auth/${config.authMount}/oidc/callback?${query}`);
  const auth = result?.auth;
  if (!auth?.client_token) { throw new OpenBaoError("The key service gave no token"); }
  if (!auth.metadata?.subject) {
    // (Without it, a sign-in as someone else in the tab would go unnoticed until every call fails.)
    throw new OpenBaoError("The key service didn't say who signed in: its OIDC role must map the `sub` " +
      "claim to `subject` (claim_mappings=sub=subject)");
  }
  return {
    token: auth.client_token, expiresAt: expiryOf(auth.lease_duration), subject: String(auth.metadata.subject),
  };
}

/**
 * Whether OpenBao can name a key after this OIDC subject: letters, digits and `_`, with `.` and `-`
 * inside (it refuses `:`, `|`, `@`, spaces..., and a `.` or `-` at either end).
 */
export function isValidOpenBaoKeyName(vaultUserId: string) {
  return /^\w(?:[\w.-]*\w)?$/.test(vaultUserId);
}

export function hasExpired(session: OpenBaoSession) {
  return session.expiresAt !== null && session.expiresAt <= Date.now();
}

export class OpenBaoKeyVault extends LocalCryptoKeyVault {
  private _client: OpenBaoClient;

  constructor(private _options: {
    config: OpenBaoEncryptionProviderConfig,
    // Who the current user is to OpenBao (their OIDC subject), as Grist knows it.
    vaultUserId: string | null,
    // The current sign-in to OpenBao, if any (as kept, e.g. renewed by another tab meanwhile), where
    // to keep it when renewed, and how to forget it (only that one: not a newer one kept since).
    session: () => OpenBaoSession | null,
    saveSession: (session: OpenBaoSession) => void,
    forgetSession: (session: OpenBaoSession) => void,
    // Whether the user signed in to OpenBao before (in this browser), and how to remember it.
    signedInBefore?: () => boolean,
    rememberSignedIn?: () => void,
    // Signs in to OpenBao (in the browser, through a tab): resolves with whether it was done.
    signIn?: () => Promise<boolean>,
  }) {
    super();
    this._client = new OpenBaoClient(_options.config);
  }

  /**
   * Whether the user is signed in to OpenBao, as themselves, with a token still valid; their key is
   * then made sure to exist (created on their first sign-in).
   */
  public async hasKeys() {
    try {
      await this._ensureOwnKey();
      this._options.rememberSignedIn?.();
      return true;
    } catch (e) {
      if (e instanceof NotSignedInToOpenBaoError) { return false; }
      throw e;
    }
  }

  /**
   * OpenBao keeps the users' keys: once a user signed in (as remembered in this browser, or as
   * holding a document's key), setting up is only signing in again.
   */
  public setupKind(hints: { holdsDocKey?: boolean } = {}): KeySetupKind {
    return (hints.holdsDocKey || this._options.signedInBefore?.()) ? "signInAgain" : "enable";
  }

  public openOnboarding(): Promise<boolean> {
    return this._options.signIn ? this._options.signIn() : Promise.resolve(false);
  }

  /** The users who have a key in OpenBao (they signed in at least once): only they can be given keys. */
  public async getRegisteredUsers(vaultUserIds: string[]) {
    const ids = vaultUserIds.filter(isValidOpenBaoKeyName);
    if (ids.length === 0) { return new Set<string>(); }
    const exists = await this._withToken(token => Promise.all(ids.map(id => this._keyExists(id, token))));
    return new Set(ids.filter((_id, i) => exists[i]));
  }

  /** Signs out of OpenBao: forgets the token, and revokes it. */
  public async signOut() {
    const session = this._options.session();
    if (session) { await this._forget(session); }
  }

  /**
   * When the sign-in kept is to be renewed (its expiry, less RENEW_BEFORE_MS), or null if there's
   * none to renew (none kept, or one that doesn't expire).
   */
  public renewalTime(): number | null {
    const expiresAt = this._options.session()?.expiresAt;
    return typeof expiresAt === "number" ? expiresAt - RENEW_BEFORE_MS : null;
  }

  /**
   * Renews the sign-in if it nears its expiry, asking OpenBao nothing otherwise: for when its
   * renewal time comes (renewalTime()), as an open document makes few calls to OpenBao (its keys
   * are kept in the page). Never fails: a sign-in that can't be renewed is found out at the next call.
   */
  public async keepAlive(): Promise<void> {
    try {
      const renewalTime = this.renewalTime();
      if (renewalTime !== null && renewalTime <= Date.now()) { await this._freshSession(); }
    } catch {
      // (E.g. OpenBao unreachable for now: tried again later.)
    }
  }

  /** Revokes a sign-in's token (e.g. of a sign-in as someone else). Never fails. */
  public async revoke(session: OpenBaoSession) {
    await this._client.request("POST", "auth/token/revoke-self", { token: session.token, body: {} }).catch(() => {});
  }

  protected async wrapFor(rawKey: Uint8Array, recipients: KeyRecipient[]) {
    const named = recipients.filter(r => isValidOpenBaoKeyName(r.vaultUserId));
    const wraps = await this._withToken(token => Promise.all(named.map(async (r) => {
      try {
        const response = await this._client.request("POST", this._transitPath("encrypt", r.vaultUserId), {
          token, body: { plaintext: bytesToBase64(rawKey) },
        });
        const ciphertext: string = response?.data?.ciphertext;
        const wrap: WrappedKey = { wrappedKey: utf8Encode(ciphertext), keyVersion: parseKeyVersion(ciphertext) };
        return [r.vaultUserId, wrap] as const;
      } catch (e) {
        // A user without a key (who never signed in to OpenBao) can't be given one. OpenBao refuses
        // that with a 403 (the policy doesn't let one create keys by encrypting), as it refuses a
        // revoked token or a policy that doesn't match the settings: only skip users whose key
        // OpenBao says doesn't exist, never oneself.
        if (e instanceof OpenBaoError && (e.status === 403 || e.status === 404) &&
          r.vaultUserId !== this._options.vaultUserId && !await this._keyExists(r.vaultUserId, token)) {
          return null;
        }
        throw e;
      }
    })));
    return new Map(wraps.filter(w => w !== null));
  }

  protected async unwrap(myKey: WrappedKey): Promise<Uint8Array> {
    const name = this._ownName();
    const response = await this._withToken(token => this._client.request("POST", this._transitPath("decrypt", name), {
      token, body: { ciphertext: utf8Decode(myKey.wrappedKey) },
    }));
    const rawKey = base64ToBytes(response?.data?.plaintext ?? "");
    if (rawKey.length !== 32) { throw new OpenBaoError("The key service returned no document key"); }
    return rawKey;
  }

  private async _keyExists(vaultUserId: string, token: string) {
    try {
      await this._client.request("GET", this._transitPath("keys", vaultUserId), { token });
      return true;
    } catch (e) {
      if (e instanceof OpenBaoError && e.status === 404) { return false; }
      throw e;
    }
  }

  // Forgets the session (only it), and revokes its token.
  private async _forget(session: OpenBaoSession) {
    this._options.forgetSession(session);
    await this.revoke(session);
  }

  private _ownName() {
    const vaultUserId = this._options.vaultUserId;
    if (!vaultUserId) {
      throw new Error("Your account is not known to the key service (no identity provider subject)");
    }
    if (!isValidOpenBaoKeyName(vaultUserId)) {
      throw new Error(`Your account's identifier (${vaultUserId}) can't name a key in the key service ` +
        "(only letters, digits, '_', and '.' or '-' inside, can): encrypted documents aren't available to you");
    }
    return vaultUserId;
  }

  private async _ensureOwnKey() {
    // (Idempotent: OpenBao keeps an existing key as it is.)
    const name = this._ownName();
    await this._withToken(token => this._client.request("POST", this._transitPath("keys", name), {
      token, body: { type: KEY_TYPE },
    }));
  }

  private _transitPath(operation: "keys" | "encrypt" | "decrypt", vaultUserId: string) {
    return `${this._options.config.transitMount}/${operation}/${this._options.config.keyPrefix}${vaultUserId}`;
  }

  /**
   * The current session, if it's the user's and not expired, renewed when it nears its expiry (so
   * that a document left open keeps working). A session that has expired, can't be renewed or is
   * someone else's (signed in to the identity provider as another user in the window) is
   * forgotten. Whether it was revoked is only found out when using it (see _withToken()).
   */
  private async _freshSession(): Promise<OpenBaoSession | null> {
    const session = this._options.session();
    if (!session) { return null; }
    if (session.subject !== this._options.vaultUserId) {
      // (Someone else's: of no use here, and not to be left behind either.)
      await this._forget(session);
      return null;
    }
    if (hasExpired(session)) {
      this._options.forgetSession(session);
      return null;
    }
    if (session.expiresAt === null || session.expiresAt - RENEW_BEFORE_MS > Date.now()) { return session; }
    try {
      const result = await this._client.request("POST", "auth/token/renew-self", { token: session.token, body: {} });
      const renewed = { ...session, expiresAt: expiryOf(result?.auth?.lease_duration) };
      this._options.saveSession(renewed);
      return renewed;
    } catch (e) {
      if (e instanceof OpenBaoError && e.status === 403) {
        this._options.forgetSession(session);
        return null;
      }
      throw e;
    }
  }

  /**
   * Calls OpenBao with the user's token. When it refuses (403: also what it says of a token
   * revoked, e.g. by signing out in another tab), whether the token is still valid is checked: if
   * not, the sign-in is forgotten (NotSignedInToOpenBaoError), for the user to sign in again.
   */
  private async _withToken<T>(call: (token: string) => Promise<T>): Promise<T> {
    const session = await this._freshSession();
    if (!session) { throw new NotSignedInToOpenBaoError(); }
    try {
      return await call(session.token);
    } catch (e) {
      if (e instanceof OpenBaoError && e.status === 403 && !await this._isValid(session)) {
        this._options.forgetSession(session);
        throw new NotSignedInToOpenBaoError();
      }
      throw e;
    }
  }

  private async _isValid(session: OpenBaoSession) {
    try {
      await this._client.request("GET", "auth/token/lookup-self", { token: session.token });
      return true;
    } catch (e) {
      if (e instanceof OpenBaoError && e.status === 403) { return false; }
      throw e;
    }
  }
}

// Renews a token this long before it expires.
const RENEW_BEFORE_MS = 10 * 60 * 1000;

// OpenBao gives a lease of 0 seconds for tokens that don't expire.
function expiryOf(leaseSeconds: unknown): number | null {
  const seconds = Number(leaseSeconds || 0);
  return seconds > 0 ? Date.now() + seconds * 1000 : null;
}

function parseKeyVersion(ciphertext: string): number {
  const match = /^vault:v(\d+):/.exec(ciphertext ?? "");
  if (!match) { throw new OpenBaoError("The key service returned no ciphertext"); }
  return Number(match[1]);
}
