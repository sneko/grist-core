/**
 * The "openbao" key provider against a real OpenBao (in dev mode) and an identity provider of the
 * test's own: signing in through it (the browser part of the provider, with a stand-in tab that
 * follows the redirects), each member's copy of a document key that only they can unwrap, keys
 * nobody else can create or tamper with, sharing, rotation, attachments, renewed, expired and
 * revoked tokens, signing out, other mounts, and the page of Grist the sign-in comes back to.
 *
 * Only run when asked, so that running the server tests needs no Docker:
 *  - TEST_OPENBAO=docker starts OpenBao in Docker (on the host's network, to reach this process's
 *    identity provider on 127.0.0.1: Linux, or Docker Desktop with host networking);
 *    (TEST_OPENBAO_IMAGE names another image than the one below);
 *  - or TEST_OPENBAO_URL and TEST_OPENBAO_TOKEN (a root token) name an OpenBao already running: a
 *    throwaway one, as the test sets it up for itself (a transit engine at `transit` and
 *    `kms/transit`, an OIDC auth method at `oidc` signing in at this process's identity provider on
 *    127.0.0.1, its policies and roles, users' keys), and leaves it so.
 * The CI sets TEST_OPENBAO=docker. What needs no OpenBao is checked always: the policy's
 * consistency with the documentation, and the page the sign-in comes back to.
 */
import { createOpenBaoKeyVault, OpenBaoBrowser, SignInTab } from "app/client/encryption/providers/openbao";
import { forgetOpenBaoSessions, sessionStorageKey } from "app/client/encryption/providers/openbaoSessions";
import { utf8Decode, utf8Encode } from "app/common/encryption/EncryptionCrypto";
import { OPENBAO_CALLBACK_PATH, openBaoPolicy, OpenBaoSession } from "app/common/encryption/OpenBaoKeyVault";
import { OpenBaoEncryptionProviderConfig } from "app/common/gristUrls";
import { addEncryptionProviderEndpoints, getEncryptionClientConfig } from "app/server/lib/encryption/encryptionConfig";
import { EnvironmentSnapshot } from "test/server/testUtils";

import { execFile } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as http from "http";
import { AddressInfo } from "net";
import * as path from "path";
import { promisify } from "util";

import { assert } from "chai";
import express from "express";

const OPENBAO_IMAGE = process.env.TEST_OPENBAO_IMAGE || "openbao/openbao:2.7.2";
const GRIST_ORIGIN = "https://grist.test";
const REDIRECT_URI = GRIST_ORIGIN + OPENBAO_CALLBACK_PATH;
const DEFAULTS = { transitMount: "transit", keyPrefix: "grist-user-" };
// What the test uses: in an OpenBao it didn't start, keys named apart from those of previous runs.
const KEYS = process.env.TEST_OPENBAO_URL ?
  { ...DEFAULTS, keyPrefix: `${DEFAULTS.keyPrefix}${Date.now().toString(36)}-` } : DEFAULTS;
const P = KEYS.keyPrefix;

/** An OIDC provider that signs in whoever `currentSub` says, at once (no form). */
class TestIdentityProvider {
  public currentSub = "alice";
  public authorizeParams: string[] = [];
  private _server!: http.Server;
  private _keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  private _codes = new Map<string, { nonce: string | null, sub: string, clientId: string | null }>();

  public get issuer() { return `http://127.0.0.1:${(this._server.address() as AddressInfo).port}`; }

  public async start() {
    this._server = http.createServer((req, res) => { this._handle(req, res).catch(e => res.destroy(e)); });
    await new Promise<void>(resolve => this._server.listen(0, "127.0.0.1", resolve));
  }

  public async stop() { await new Promise(resolve => this._server.close(resolve)); }

  private async _handle(req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url!, this.issuer);
    const json = (body: object) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    };
    switch (url.pathname) {
      case "/.well-known/openid-configuration":
        return json({
          issuer: this.issuer, authorization_endpoint: `${this.issuer}/authorize`, token_endpoint: `${this.issuer}/token`,
          jwks_uri: `${this.issuer}/jwks`, userinfo_endpoint: `${this.issuer}/userinfo`,
          response_types_supported: ["code"], subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
        });
      case "/jwks":
        return json({
          keys: [{ ...this._keys.publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" }],
        });
      case "/authorize": {
        this.authorizeParams = [...url.searchParams.keys()].sort();
        const code = crypto.randomBytes(12).toString("hex");
        this._codes.set(code, {
          nonce: url.searchParams.get("nonce"), sub: this.currentSub, clientId: url.searchParams.get("client_id"),
        });
        const back = new URL(url.searchParams.get("redirect_uri")!);
        back.searchParams.set("code", code);
        back.searchParams.set("state", url.searchParams.get("state")!);
        res.statusCode = 302;
        res.setHeader("location", back.href);
        return res.end();
      }
      case "/token": {
        let body = "";
        for await (const chunk of req) { body += chunk; }
        const code = new URLSearchParams(body).get("code")!;
        const grant = this._codes.get(code);
        if (!grant) { res.statusCode = 400; return json({ error: "invalid_grant" }); }
        this._codes.delete(code);
        const now = Math.floor(Date.now() / 1000);
        const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
        const input = `${b64({ alg: "RS256", typ: "JWT", kid: "k1" })}.` +
          b64({ iss: this.issuer, sub: grant.sub, aud: grant.clientId, nonce: grant.nonce, iat: now, exp: now + 300 });
        const idToken = `${input}.${crypto.sign("sha256", Buffer.from(input), this._keys.privateKey).toString("base64url")}`;
        return json({ access_token: `at-${grant.sub}`, token_type: "Bearer", expires_in: 300, id_token: idToken });
      }
      case "/userinfo":
        return json({ sub: this.currentSub });
    }
    res.statusCode = 404;
    res.end();
  }
}

/** OpenBao, in Docker unless given, administered with its root token. */
class TestOpenBao {
  public url = process.env.TEST_OPENBAO_URL || "";
  public rootToken = process.env.TEST_OPENBAO_TOKEN || "root";
  private _container?: string;

  public async start() {
    if (this.url) { return; }
    // (The image is pulled first, apart from the start-up wait.)
    await promisify(execFile)("docker", ["pull", "-q", OPENBAO_IMAGE], { timeout: 300_000 });
    // A port may be taken between choosing it and OpenBao listening on it: try a few.
    for (let attempt = 0; ; attempt++) {
      const port = await freePort();
      this._container = `grist-test-openbao-${process.pid}-${port}`;
      await promisify(execFile)("docker", ["run", "-d", "--rm", "--name", this._container, "--network", "host",
        "-e", `BAO_DEV_ROOT_TOKEN_ID=${this.rootToken}`, "-e", `BAO_DEV_LISTEN_ADDRESS=127.0.0.1:${port}`,
        OPENBAO_IMAGE, "server", "-dev"], { timeout: 60_000 });
      this.url = `http://127.0.0.1:${port}`;
      if (await this._waitHealthy()) { return; }
      await this.stop();
      if (attempt >= 2) { throw new Error("OpenBao did not start"); }
    }
  }

  public async stop() {
    if (this._container) { await promisify(execFile)("docker", ["rm", "-f", this._container]).catch(() => {}); }
    this._container = undefined;
  }

  public async call(method: string, urlPath: string, body?: object, token = this.rootToken) {
    const response = await fetch(`${this.url}/v1/${urlPath}`, {
      method, headers: { "X-Vault-Token": token, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  }

  public async admin(method: string, urlPath: string, body?: object) {
    const { status, body: result } = await this.call(method, urlPath, body);
    if (status >= 300) { throw new Error(`OpenBao ${method} ${urlPath}: ${status} ${JSON.stringify(result)}`); }
    return result;
  }

  /** Sets it up as the documentation says (documentation/encryption.md, "The openbao provider"). */
  public async configure(idp: TestIdentityProvider) {
    await this.mount("transit");
    if ((await this.call("GET", "sys/auth/oidc")).status !== 200) {
      await this.admin("POST", "sys/auth/oidc", { type: "oidc" });
    }
    await this.admin("POST", "auth/oidc/config", {
      oidc_discovery_url: idp.issuer, oidc_client_id: "openbao", oidc_client_secret: "openbao-secret",
      default_role: "grist",
    });
    await this.admin("PUT", "sys/policies/acl/grist", { policy: openBaoPolicy(KEYS, await this.oidcAccessor()) });
    await this.addRole("grist", "grist");
  }

  /** Mounts a transit engine, unless there's one already (in an OpenBao set up by a previous run). */
  public async mount(mountPath: string) {
    if ((await this.call("GET", `sys/mounts/${mountPath}`)).status !== 200) {
      await this.admin("POST", `sys/mounts/${mountPath}`, { type: "transit" });
    }
  }

  public async oidcAccessor(): Promise<string> {
    return (await this.admin("GET", "sys/auth")).data["oidc/"].accessor;
  }

  public async addRole(role: string, policy: string, options: { subject?: boolean } = {}) {
    await this.admin("POST", `auth/oidc/role/${role}`, {
      role_type: "oidc", user_claim: "sub", bound_audiences: ["openbao"], allowed_redirect_uris: [REDIRECT_URI],
      ...(options.subject === false ? {} : { claim_mappings: { sub: "subject" } }),
      oidc_scopes: ["openid"], token_policies: [policy], token_no_default_policy: true,
      token_type: "service", token_ttl: "1h",
    });
  }

  private async _waitHealthy() {
    for (let i = 0; i < 120; i++) {
      try {
        if ((await fetch(`${this.url}/v1/sys/health`)).ok) { return true; }
      } catch { /* Not yet. */ }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    return false;
  }
}

/** A browser for the provider's sign-in: a "tab" that follows the redirects, as a browser would. */
class TestBrowser implements OpenBaoBrowser {
  public origin = GRIST_ORIGIN;
  public storage: any;
  public timeoutMs = 30_000;
  public blockTabs = false;
  // The tab never comes back (the user left it, or closed it).
  public abandonTabs = false;
  // The identity provider severs the tab from the page (Cross-Origin-Opener-Policy): it looks
  // closed from the page, and the result only arrives over the channel.
  public severTabs = false;
  public tabsOpened = 0;
  // Called as a tab navigates to the identity provider (once the page listens for the result).
  public onNavigate?: () => void;
  private _listeners = new Set<(search: string) => void>();
  private _map = new Map<string, string>();

  constructor() {
    const map = this._map;
    this.storage = {
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => { map.set(k, v); },
      removeItem: (k: string) => { map.delete(k); },
      key: (i: number) => [...map.keys()][i] ?? null,
      get length() { return map.size; },
    };
  }

  public entries() { return [...this._map.entries()]; }

  /** As if a callback page (this sign-in's, or another one's) handed its result. */
  public deliver(search: string) { for (const listener of [...this._listeners]) { listener(search); } }

  public openTab(): SignInTab | null {
    if (this.blockTabs) { return null; }
    this.tabsOpened++;
    const tab = {
      closed: false,
      close: () => { tab.closed = true; },
      navigate: (url: string) => {
        this.onNavigate?.();
        if (this.severTabs) { tab.closed = true; }
        if (this.abandonTabs) { return; }
        const state = new URL(url).searchParams.get("state") ?? "";
        // To the identity provider, which signs the user in at once and sends the tab back to Grist.
        fetch(url, { redirect: "manual" }).then((response) => {
          const back = new URL(response.headers.get("location")!);
          if (back.origin + back.pathname !== REDIRECT_URI) { throw new Error(`Unexpected redirect to ${back.href}`); }
          this.deliver(back.search);
        }).catch((e) => {
          // (Reported by the sign-in, rather than left as an unhandled rejection.)
          this.deliver(`?${new URLSearchParams({ state, error: "test_browser", error_description: String(e) })}`);
        });
      },
    };
    return tab;
  }

  public onCallback(_tab: SignInTab, listener: (search: string) => void) {
    this._listeners.add(listener);
    return () => { this._listeners.delete(listener); };
  }
}

async function freePort(): Promise<number> {
  const server = http.createServer();
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function hasDocker() {
  try {
    await promisify(execFile)("docker", ["info"], { timeout: 20_000 });
    return true;
  } catch {
    return false;
  }
}

describe("encryption/OpenBaoProvider", function() {
  // Always: the policy users are given is the same in the code, the documentation and the
  // development setup.
  it("documents the very policy openBaoPolicy() makes", function() {
    const policy = openBaoPolicy(DEFAULTS, "$ACCESSOR").trim();
    const root = path.resolve(__dirname, "../../../../..");
    for (const file of ["documentation/encryption.md", "docker/encryption-dev/openbao-setup.sh"]) {
      const text = fs.readFileSync(path.join(root, file), "utf8");
      assert.include(text, `<<POLICY\n${policy}\nPOLICY`, file);
    }
  });

  it("serves the page the sign-in comes back to, handing the result to Grist's origin only", async function() {
    const env = new EnvironmentSnapshot();
    try {
      process.env.GRIST_ENCRYPTION_FEATURE_ENABLED = "true";
      process.env.GRIST_ENCRYPTION_PROVIDER = "openbao";
      process.env.GRIST_ENCRYPTION_OPENBAO_URL = "https://openbao.example.com";
      process.env.GRIST_OIDC_IDP_ISSUER = "https://idp.example.com";
      assert.deepEqual(getEncryptionClientConfig()?.provider, {
        kind: "openbao", url: "https://openbao.example.com", authMount: "oidc", role: "grist", ...DEFAULTS,
      });
      const app = express();
      addEncryptionProviderEndpoints(app);
      const server = app.listen(0, "127.0.0.1");
      await new Promise(resolve => server.once("listening", resolve));
      try {
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}${OPENBAO_CALLBACK_PATH}`;
        const response = await fetch(`${base}?code=x`);
        assert.equal(response.status, 200);
        assert.equal(response.headers.get("cache-control"), "no-store");
        assert.equal(response.headers.get("referrer-policy"), "no-referrer");
        // (No inline script, for pages under a Content-Security-Policy.)
        const page = await response.text();
        assert.include(page, `<script src="${OPENBAO_CALLBACK_PATH}.js"></script>`);
        assert.notMatch(page, /<script>/);
        const script = await (await fetch(`${base}.js`)).text();
        assert.include(script, "window.opener.postMessage(message, window.location.origin)");
        assert.include(script, `new BroadcastChannel("grist-openbao-sign-in")`);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    } finally {
      env.restore();
    }
  });

  describe("against OpenBao", function() {
    this.timeout(120_000);
    const idp = new TestIdentityProvider();
    const openBao = new TestOpenBao();
    let config: OpenBaoEncryptionProviderConfig;

    before(async function() {
      if (!process.env.TEST_OPENBAO_URL && process.env.TEST_OPENBAO !== "docker") {
        // (Opt-in: TEST_OPENBAO=docker, or TEST_OPENBAO_URL; the CI sets it.)
        this.skip();
      }
      if (!process.env.TEST_OPENBAO_URL && !await hasDocker()) {
        throw new Error("TEST_OPENBAO=docker needs Docker");
      }
      this.timeout(600_000);   // (The image may need pulling.)
      await idp.start();
      await openBao.start();
      await openBao.configure(idp);
      config = { kind: "openbao", url: openBao.url, authMount: "oidc", role: "grist", ...KEYS };
    });

    after(async function() {
      await openBao.stop();
      await idp.stop().catch(() => {});
    });

    /** A user's vault in a browser of their own, signed in to OpenBao through the identity provider. */
    async function signedIn(sub: string, browser = new TestBrowser(), cfg = config) {
      const vault = await createOpenBaoKeyVault(cfg, sub, browser);
      idp.currentSub = sub;
      assert.isTrue(await vault.openOnboarding());
      assert.isTrue(await vault.hasKeys());    // (Which creates their key, as when they open a document.)
      const key = sessionStorageKey(cfg.url, sub);
      return { vault, browser, session: JSON.parse(browser.storage.getItem(key)) as OpenBaoSession };
    }

    const member = (sub: string) => ({ vaultUserId: sub, email: `${sub}@example.com` });

    it("signs in through the identity provider, as the user Grist knows", async function() {
      const browser = new TestBrowser();
      const vault = await createOpenBaoKeyVault(config, "alice", browser);
      assert.isFalse(await vault.hasKeys());
      idp.currentSub = "alice";
      assert.isTrue(await vault.openOnboarding());
      assert.isTrue(await vault.hasKeys());
      assert.equal(browser.tabsOpened, 1);
      // OpenBao ran the sign-in itself, with PKCE: no secret of the provider reached the browser.
      assert.includeMembers(idp.authorizeParams, ["code_challenge", "code_challenge_method", "nonce", "state"]);
      // Kept for the next pages of this browser, until it expires.
      const [[key, value]] = browser.entries();
      assert.equal(key, sessionStorageKey(openBao.url, "alice"));
      assert.include(JSON.parse(value), { subject: "alice" });
      const again = await createOpenBaoKeyVault(config, "alice", browser);
      assert.isTrue(await again.hasKeys());
    });

    it("refuses a sign-in as someone else than the user Grist knows", async function() {
      const vault = await createOpenBaoKeyVault(config, "alice", new TestBrowser());
      idp.currentSub = "mallory";
      await assert.isRejected(vault.openOnboarding(), /signed in to the key service as another user/);
      assert.isFalse(await vault.hasKeys());
    });

    it("refuses a sign-in that doesn't say who signed in", async function() {
      await openBao.addRole("nosubject", "grist", { subject: false });
      const vault = await createOpenBaoKeyVault({ ...config, role: "nosubject" }, "alice", new TestBrowser());
      idp.currentSub = "alice";
      await assert.isRejected(vault.openOnboarding(), /must map the `sub` claim to `subject`/);
    });

    it("reports a blocked window, a sign-in that never comes back, and users it can't name", async function() {
      const browser = new TestBrowser();
      const vault = await createOpenBaoKeyVault(config, "alice", browser);
      browser.blockTabs = true;
      await assert.isRejected(vault.openOnboarding(), /blocked the window for signing in/);
      browser.blockTabs = false;
      browser.abandonTabs = true;
      browser.timeoutMs = 300;
      assert.isFalse(await vault.openOnboarding());
      assert.isFalse(await vault.hasKeys());
      await assert.isRejected(createOpenBaoKeyVault(config, null, browser), /not known to the key service/);
      // (OpenBao names no key with `:`, `|`, `@`... as some identity providers' subjects have.)
      await assert.isRejected(createOpenBaoKeyVault(config, "f:3c5a:jdupont", browser), /can't name a key/);
    });

    it("signs in when the identity provider severs the tab from the page", async function() {
      const browser = new TestBrowser();
      browser.severTabs = true;
      const vault = await createOpenBaoKeyVault(config, "alice", browser);
      idp.currentSub = "alice";
      assert.isTrue(await vault.openOnboarding());
      assert.isTrue(await vault.hasKeys());
    });

    it("only takes the result of its own sign-in", async function() {
      const browser = new TestBrowser();
      browser.abandonTabs = true;
      browser.timeoutMs = 1000;
      const vault = await createOpenBaoKeyVault(config, "alice", browser);
      // Another sign-in's result (another state), e.g. from a tab opened elsewhere: ignored.
      let delivered = false;
      browser.onNavigate = () => { browser.deliver("?code=xyz&state=st_someone_elses"); delivered = true; };
      assert.isFalse(await vault.openOnboarding());
      assert.isTrue(delivered);
      assert.isFalse(await vault.hasKeys());
    });

    it("gives each member their own copy of a document key, which only they can unwrap", async function() {
      const alice = (await signedIn("alice")).vault;
      const bob = (await signedIn("bob")).vault;
      const carol = (await signedIn("carol")).vault;
      const wraps = await alice.createDocumentKey([member("alice"), member("bob")]);
      const aliceKey = wraps.get("alice")!;
      const bobKey = wraps.get("bob")!;
      assert.match(utf8Decode(aliceKey.wrappedKey), /^vault:v1:/);
      assert.equal(aliceKey.keyVersion, 1);
      assert.notEqual(utf8Decode(aliceKey.wrappedKey), utf8Decode(bobKey.wrappedKey));
      // The same document key behind both copies.
      const ciphertext = await alice.encrypt(utf8Encode("secret value"), aliceKey);
      assert.equal(utf8Decode(await bob.decrypt(ciphertext, bobKey)), "secret value");
      // Someone else's copy is of no use, whoever holds it.
      await assert.isRejected(bob.decrypt(ciphertext, aliceKey), /The key service refused/);
      await assert.isRejected(carol.decrypt(ciphertext, bobKey), /The key service refused/);
    });

    it("only gives keys to users who signed in once (and so have a key)", async function() {
      const alice = (await signedIn("alice")).vault;
      assert.deepEqual([...await alice.getRegisteredUsers(["alice", "newcomer", "a:b"])], ["alice"]);
      const wraps = await alice.createDocumentKey([member("alice"), member("newcomer")]);
      assert.deepEqual([...wraps.keys()], ["alice"]);
      await signedIn("newcomer");
      assert.deepEqual([...await alice.getRegisteredUsers(["alice", "newcomer"])].sort(), ["alice", "newcomer"]);
      const shared = await alice.shareDocumentKey(wraps.get("alice")!, [member("newcomer")]);
      assert.deepEqual([...shared.keys()], ["newcomer"]);
    });

    it("lets nobody create, nor tamper with, someone else's key", async function() {
      const mallory = (await signedIn("mallory")).session.token;
      const victim = "victim";   // (Who hasn't signed in yet.)
      // Creating the victim's key, possibly of a kind that would break it later: refused.
      for (const body of [{ type: "aes256-gcm96" }, { convergent_encryption: true, derived: true }]) {
        assert.equal((await openBao.call("POST", `transit/keys/${P}${victim}`, body, mallory)).status, 403);
      }
      for (const body of [{ plaintext: "YQ==" }, { plaintext: "YQ==", convergent_encryption: true, context: "YQ==" }]) {
        assert.equal((await openBao.call("POST", `transit/encrypt/${P}${victim}`, body, mallory)).status, 403);
      }
      // Nor one's own key of another kind, nor any other parameter than the key to wrap.
      assert.equal((await openBao.call("POST", `transit/keys/${P}mallory`,
        { type: "aes256-gcm96", derived: true }, mallory)).status, 403);
      await signedIn(victim);
      assert.equal((await openBao.call("POST", `transit/encrypt/${P}${victim}`,
        { plaintext: "YQ==", key_version: 1 }, mallory)).status, 403);
      assert.equal((await openBao.call("POST", `transit/encrypt/${P}${victim}`, { plaintext: "YQ==" },
        mallory)).status, 200);
      // The victim's key is intact: they still get and use keys.
      const victimVault = (await signedIn(victim)).vault;
      const key = (await victimVault.createDocumentKey([member(victim)])).get(victim)!;
      const ciphertext = await victimVault.encrypt(utf8Encode("still fine"), key);
      assert.equal(utf8Decode(await victimVault.decrypt(ciphertext, key)), "still fine");
    });

    it("lets users keep nothing in OpenBao, nor do more with their token", async function() {
      const { session } = await signedIn("mallory");
      const token = session.token;
      // Without OpenBao's `default` policy: no storage, no wrapping of data of one's own, no child tokens.
      assert.equal((await openBao.call("POST", "cubbyhole/stash", { data: "x" }, token)).status, 403);
      assert.equal((await openBao.call("POST", "sys/wrapping/wrap", { data: "x" }, token)).status, 403);
      assert.equal((await openBao.call("POST", "auth/token/create", {}, token)).status, 403);
      assert.equal((await openBao.call("GET", "sys/policies/acl/grist", undefined, token)).status, 403);
      // What the provider needs of its token still works.
      assert.equal((await openBao.call("GET", "auth/token/lookup-self", undefined, token)).status, 200);
      assert.equal((await openBao.call("POST", "auth/token/renew-self", {}, token)).status, 200);
      assert.deepEqual((await openBao.call("GET", "auth/token/lookup-self", undefined, token)).body.data.policies,
        ["grist"]);
    });

    it("shares a document key with more members", async function() {
      const alice = (await signedIn("alice")).vault;
      const dave = (await signedIn("dave")).vault;
      const aliceKey = (await alice.createDocumentKey([member("alice")])).get("alice")!;
      const ciphertext = await alice.encrypt(utf8Encode("shared later"), aliceKey);
      const daveKey = (await alice.shareDocumentKey(aliceKey, [member("dave")])).get("dave")!;
      assert.equal(utf8Decode(await dave.decrypt(ciphertext, daveKey)), "shared later");
    });

    it("still unwraps older copies after a member's key is rotated in OpenBao", async function() {
      const alice = (await signedIn("alice")).vault;
      const erin = (await signedIn("erin")).vault;
      const wraps = await alice.createDocumentKey([member("alice"), member("erin")]);
      const ciphertext = await alice.encrypt(utf8Encode("before rotation"), wraps.get("alice")!);
      await openBao.admin("POST", `transit/keys/${P}erin/rotate`);
      // Erin's copy made with version 1 still unwraps (a new vault, without unwrapped keys cached),
      // and signing in again keeps her key as it is.
      const erinAgain = (await signedIn("erin")).vault;
      assert.equal(utf8Decode(await erinAgain.decrypt(ciphertext, wraps.get("erin")!)), "before rotation");
      // New copies use the new version, and say so.
      const newer = (await alice.shareDocumentKey(wraps.get("alice")!, [member("erin")])).get("erin")!;
      assert.equal(newer.keyVersion, 2);
      assert.match(utf8Decode(newer.wrappedKey), /^vault:v2:/);
      assert.equal(utf8Decode(await erin.decrypt(ciphertext, newer)), "before rotation");
    });

    it("encrypts attachments with keys of their own, wrapped with the document's", async function() {
      const alice = (await signedIn("alice")).vault;
      const bob = (await signedIn("bob")).vault;
      const wraps = await alice.createDocumentKey([member("alice"), member("bob")]);
      const { ciphertext, nestedKey } = await alice.encryptWithNewKey(utf8Encode("file content"), wraps.get("alice")!);
      const plaintext = await bob.decryptWithNestedKey(ciphertext, wraps.get("bob")!, nestedKey);
      assert.equal(utf8Decode(plaintext), "file content");
    });

    it("renews a token nearing its expiry, and doesn't count a revoked or expired one", async function() {
      const { browser, session } = await signedIn("alice");
      const key = sessionStorageKey(openBao.url, "alice");
      // Close to its expiry: renewed (for the role's TTL) when next used.
      browser.storage.setItem(key, JSON.stringify({ ...session, expiresAt: Date.now() + 60_000 }));
      assert.isTrue(await (await createOpenBaoKeyVault(config, "alice", browser)).hasKeys());
      assert.isAbove(JSON.parse(browser.storage.getItem(key)).expiresAt, Date.now() + 30 * 60_000);
      // Revoked: no longer a sign-in, and forgotten.
      await openBao.admin("POST", "auth/token/revoke", { token: session.token });
      assert.isFalse(await (await createOpenBaoKeyVault(config, "alice", browser)).hasKeys());
      assert.isNull(browser.storage.getItem(key));
      // Expired: dropped without asking OpenBao.
      browser.storage.setItem(key, JSON.stringify({ ...session, expiresAt: Date.now() - 1000 }));
      assert.isFalse(await (await createOpenBaoKeyVault(config, "alice", browser)).hasKeys());
      assert.isNull(browser.storage.getItem(key));
      // Someone else's (in this user's place): ignored.
      browser.storage.setItem(key, JSON.stringify({ ...session, subject: "bob" }));
      assert.isFalse(await (await createOpenBaoKeyVault(config, "alice", browser)).hasKeys());
    });

    it("signs out of OpenBao when signing out of Grist", async function() {
      const { browser, session } = await signedIn("alice");
      const other = await signedIn("bob", browser);
      forgetOpenBaoSessions(browser.storage);
      assert.deepEqual(browser.entries(), []);
      // Both tokens revoked (asynchronously, as the page unloads).
      for (const token of [session.token, other.session.token]) {
        let status = 200;
        for (let i = 0; i < 20 && status === 200; i++) {
          await new Promise(resolve => setTimeout(resolve, 100));
          status = (await openBao.call("GET", "auth/token/lookup-self", undefined, token)).status;
        }
        assert.equal(status, 403);
      }
      // Also from the vault itself.
      const { vault, session: third } = await signedIn("carol");
      await vault.signOut();
      assert.equal((await openBao.call("GET", "auth/token/lookup-self", undefined, third.token)).status, 403);
    });

    it("works with other mounts and key names, with the policy made for them", async function() {
      const custom = { transitMount: "kms/transit", keyPrefix: "docs." };
      await openBao.mount("kms/transit");
      await openBao.admin("PUT", "sys/policies/acl/grist-docs",
        { policy: openBaoPolicy(custom, await openBao.oidcAccessor()) });
      await openBao.addRole("grist-docs", "grist-docs");
      const cfg = { ...config, role: "grist-docs", ...custom };
      const frank = (await signedIn("frank", new TestBrowser(), cfg)).vault;
      const key = (await frank.createDocumentKey([member("frank")])).get("frank")!;
      assert.equal(utf8Decode(await frank.decrypt(await frank.encrypt(utf8Encode("x"), key), key)), "x");
      assert.equal((await openBao.admin("GET", "kms/transit/keys/docs.frank")).data.name, "docs.frank");
    });
  });
});
