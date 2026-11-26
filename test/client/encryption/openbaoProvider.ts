/**
 * The "openbao" provider's parts that need no OpenBao (see test/server/lib/encryption/OpenBaoProvider.ts
 * for the rest), against answers made up here: how the browser listens for the sign-in's result,
 * how a sign-in is started and finished, which members are skipped when wrapping keys, how
 * sign-ins are kept, renewed and forgotten (alongside other tabs), and when signing out of Grist.
 */
import { createOpenBaoKeyVault, OpenBaoBrowser, realBrowser, SignInTab } from "app/client/encryption/providers/openbao";
import {
  forgetOpenBaoSessions, forgetSession, loadSession, sessionStorageKey,
} from "app/client/encryption/providers/openbaoSessions";
import { utf8Encode } from "app/common/encryption/EncryptionCrypto";
import {
  finishOpenBaoSignIn, isValidOpenBaoKeyName, OPENBAO_CALLBACK_CHANNEL, OpenBaoKeyVault, OpenBaoSession,
  startOpenBaoSignIn,
} from "app/common/encryption/OpenBaoKeyVault";

import { assert } from "chai";

const config = {
  kind: "openbao" as const, url: "https://openbao.example.com", authMount: "oidc", role: "grist",
  transitMount: "transit", keyPrefix: "grist-user-",
};

/** Replaces fetch with answers given in turn, recording the requests. */
function stubFetch(...answers: object[]) {
  const requests: { url: string, init: any }[] = [];
  const prev = global.fetch;
  global.fetch = (async (url: string, init: any) => {
    requests.push({ url, init });
    const answer = answers.shift() ?? {};
    return new Response(JSON.stringify(answer), { status: 200, headers: { "content-type": "application/json" } });
  }) as any;
  return { requests, restore: () => { global.fetch = prev; } };
}

/** Replaces fetch with OpenBao's answers by request ("POST transit/encrypt/grist-user-bob": [status, body]). */
function routeFetch(route: (request: string, body: any) => [number, object?]) {
  const requests: string[] = [];
  const prev = global.fetch;
  global.fetch = (async (url: string, init: any) => {
    const request = `${init?.method ?? "GET"} ${url.replace(/^.*?\/v1\//, "")}`;
    requests.push(request);
    const [status, body] = route(request, init?.body ? JSON.parse(init.body) : undefined);
    return new Response(JSON.stringify(body ?? {}), { status, headers: { "content-type": "application/json" } });
  }) as any;
  return { requests, restore: () => { global.fetch = prev; } };
}

const SOON = () => Date.now() + 60_000;            // Within the time a token gets renewed before it expires.
const LATER = () => Date.now() + 3600_000;

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => { map.set(k, v); },
    removeItem: (k: string) => { map.delete(k); },
    key: (i: number) => [...map.keys()][i] ?? null,
    get length() { return map.size; },
  };
}

describe("encryption/providers/openbao", function() {
  describe("finishOpenBaoSignIn", function() {
    it("keeps who signed in, and until when (a lease of 0: no expiry)", async function() {
      const fetch1 = stubFetch({ auth: { client_token: "t1", lease_duration: 3600, metadata: { subject: "alice" } } });
      try {
        const session = await finishOpenBaoSignIn(config, "?code=c&state=s", "nonce");
        assert.include(session, { token: "t1", subject: "alice" });
        assert.closeTo(session.expiresAt!, Date.now() + 3600_000, 5000);
        // The code goes to OpenBao with the secret only the page kept.
        assert.equal(fetch1.requests[0].url,
          "https://openbao.example.com/v1/auth/oidc/oidc/callback?state=s&code=c&client_nonce=nonce");
      } finally {
        fetch1.restore();
      }
      const fetch2 = stubFetch({ auth: { client_token: "t2", lease_duration: 0, metadata: { subject: "alice" } } });
      try {
        assert.isNull((await finishOpenBaoSignIn(config, "?code=c&state=s", "nonce")).expiresAt);
      } finally {
        fetch2.restore();
      }
    });

    it("refuses a sign-in that doesn't say who signed in, and reports the provider's errors", async function() {
      const fetch1 = stubFetch({ auth: { client_token: "t1", lease_duration: 3600, metadata: {} } });
      try {
        await assert.isRejected(finishOpenBaoSignIn(config, "?code=c&state=s", "nonce"), /claim_mappings=sub=subject/);
      } finally {
        fetch1.restore();
      }
      await assert.isRejected(finishOpenBaoSignIn(config, "?error=access_denied&error_description=Nope&state=s", "n"),
        /sign-in to the key service failed: Nope/);
    });
  });

  describe("realBrowser", function() {
    let prevWindow: any;
    const listeners = new Set<(event: any) => void>();
    const opened: { name: string, win: any }[] = [];

    before(function() {
      prevWindow = (global as any).window;
      (global as any).window = {
        location: { origin: "https://grist.example.com" },
        localStorage: memoryStorage(),
        open: (_url: string, name: string) => {
          const win = { closed: false, location: { href: "" }, close() { win.closed = true; } };
          opened.push({ name, win });
          return win;
        },
        addEventListener: (_type: string, l: any) => listeners.add(l),
        removeEventListener: (_type: string, l: any) => listeners.delete(l),
      };
    });
    after(function() { (global as any).window = prevWindow; });

    it("opens a window of its own for each sign-in", function() {
      const browser = realBrowser();
      const tab1 = browser.openTab()!;
      const tab2 = browser.openTab()!;
      assert.notEqual(opened[0].name, opened[1].name);
      tab1.navigate("https://idp.example.com/authorize");
      assert.equal(opened[0].win.location.href, "https://idp.example.com/authorize");
      tab2.close();
      assert.isTrue(tab2.closed);
    });

    it("takes the result from its own tab on Grist's origin, or over the channel", async function() {
      const browser = realBrowser();
      const tab: SignInTab = browser.openTab()!;
      const win = opened.at(-1)!.win;
      const received: string[] = [];
      const stop = browser.onCallback(tab, s => received.push(s));
      const send = (event: object) => { for (const l of [...listeners]) { l(event); } };
      const data = { gristOpenBaoCallback: "?code=c&state=s" };
      send({ origin: "https://evil.example.com", source: win, data });           // Another origin.
      send({ origin: "https://grist.example.com", source: {}, data });           // Another window.
      send({ origin: "https://grist.example.com", source: win, data: { x: 1 } }); // Not a result.
      assert.deepEqual(received, []);
      send({ origin: "https://grist.example.com", source: win, data });
      assert.deepEqual(received, ["?code=c&state=s"]);
      // When the identity provider severed the tab from the page: over the channel.
      let stop2 = () => {};
      const viaChannel = new Promise<void>((resolve) => {
        stop2 = browser.onCallback(tab, (s) => { if (s === "?code=d&state=t") { resolve(); } });
      });
      const channel = new BroadcastChannel(OPENBAO_CALLBACK_CHANNEL);
      channel.postMessage({ gristOpenBaoCallback: "?code=d&state=t" });
      channel.close();
      await viaChannel;
      assert.deepEqual(received, ["?code=c&state=s", "?code=d&state=t"]);
      stop();
      stop2();
      assert.equal(listeners.size, 0);
    });

    it("can't open a window when the browser blocks it, nor keep sign-ins without storage", function() {
      const win = (global as any).window;
      const { open, localStorage } = win;
      try {
        win.open = () => null;
        Object.defineProperty(win, "localStorage", { configurable: true, get() { throw new Error("blocked"); } });
        const browser = realBrowser();
        assert.isNull(browser.openTab());
        assert.isNull(browser.storage);
      } finally {
        Object.defineProperty(win, "localStorage", { configurable: true, writable: true, value: localStorage });
        win.open = open;
      }
    });
  });

  describe("startOpenBaoSignIn", function() {
    it("says what to check when OpenBao gives no sign-in URL", async function() {
      // (What OpenBao answers when the role doesn't allow the redirect URI.)
      const stub = routeFetch(() => [200, { data: {} }]);
      try {
        await assert.isRejected(startOpenBaoSignIn(config, "https://grist.example.com/encryption/openbao-callback"),
          /allows https:\/\/grist\.example\.com\/encryption\/openbao-callback as a redirect URI/);
      } finally {
        stub.restore();
      }
    });
  });

  describe("key names", function() {
    it("only takes subjects OpenBao can name keys after", function() {
      for (const ok of ["alice", "5f1c-42.ab_c", "_x", "a"]) { assert.isTrue(isValidOpenBaoKeyName(ok), ok); }
      for (const bad of ["", "f:3c5a:jdupont", "a@b", "a b", "a*", "-a", "a-", "a.", ".a"]) {
        assert.isFalse(isValidOpenBaoKeyName(bad), bad);
      }
    });
  });

  describe("OpenBaoKeyVault", function() {
    function makeVault(session: OpenBaoSession | null) {
      const kept = { session };
      const vault = new OpenBaoKeyVault({
        config, vaultUserId: "alice",
        session: () => kept.session,
        saveSession: (s) => { kept.session = s; },
        forgetSession: (s) => { if (kept.session?.token === s.token) { kept.session = null; } },
      });
      return { vault, kept };
    }
    const signedIn = () => ({ token: "t-alice", expiresAt: LATER(), subject: "alice" });
    const member = (sub: string) => ({ vaultUserId: sub, email: `${sub}@example.com` });

    it("only skips members whose key OpenBao says doesn't exist", async function() {
      const { vault } = makeVault(signedIn());
      const refused = new Set<string>();
      const stub = routeFetch((request) => {
        if (request === "GET auth/token/lookup-self") { return [200]; }
        const [, op, name] = /^\w+ transit\/(\w+)\/grist-user-(.*)$/.exec(request) ?? [];
        if (op === "encrypt") {
          return refused.has(name) ? [403, { errors: ["permission denied"] }] :
            [200, { data: { ciphertext: "vault:v1:x" } }];
        }
        if (op === "keys") { return name === "carol" ? [404, { errors: [] }] : [200, { data: {} }]; }
        return [500];
      });
      try {
        // Carol never signed in to OpenBao: skipped.
        refused.add("carol");
        const wraps = await vault.createDocumentKey([member("alice"), member("bob"), member("carol")]);
        assert.sameMembers([...wraps.keys()], ["alice", "bob"]);
        // Bob has a key, but OpenBao refuses (e.g. a policy not matching the settings): not skipped.
        refused.add("bob");
        await assert.isRejected(vault.createDocumentKey([member("alice"), member("bob")]), /refused \(403\)/);
        // Nor oneself, ever (e.g. a token revoked meanwhile from another tab).
        refused.add("alice");
        stub.requests.length = 0;
        await assert.isRejected(vault.createDocumentKey([member("alice")]), /refused \(403\)/);
        assert.notInclude(stub.requests, "GET transit/keys/grist-user-alice");
      } finally {
        stub.restore();
      }
      // Nor members when asking whether they have keys fails otherwise than with a 404.
      const failing = routeFetch(request => request.startsWith("GET transit/keys/") ? [503] : [200]);
      try {
        await assert.isRejected(vault.getRegisteredUsers(["bob"]), /refused \(503\)/);
      } finally {
        failing.restore();
      }
    });

    it("refuses what isn't a document key, or OpenBao's ciphertext", async function() {
      const { vault } = makeVault(signedIn());
      const stub = routeFetch((request) => {
        if (request.startsWith("POST transit/decrypt/")) { return [200, { data: { plaintext: "AAAA" } }]; }
        if (request.startsWith("POST transit/encrypt/")) { return [200, { data: { ciphertext: "nope" } }]; }
        return [200];
      });
      try {
        const myKey = { wrappedKey: utf8Encode("vault:v1:x"), keyVersion: 1 };
        await assert.isRejected(vault.decrypt(new Uint8Array(40), myKey), /no document key/);
        await assert.isRejected(vault.createDocumentKey([member("bob")]), /returned no ciphertext/);
      } finally {
        stub.restore();
      }
    });

    it("renews a sign-in nearing its expiry when kept alive, and forgets one OpenBao refuses", async function() {
      const { vault, kept } = makeVault({ token: "t-alice", expiresAt: SOON(), subject: "alice" });
      let tokenValid = true;
      const stub = routeFetch((request) => {
        if (!tokenValid) { return [403, { errors: ["permission denied"] }]; }
        if (request === "POST auth/token/renew-self") { return [200, { auth: { lease_duration: 3600 } }]; }
        return [200];
      });
      try {
        await vault.keepAlive();
        assert.deepEqual(stub.requests, ["POST auth/token/renew-self"]);
        assert.isAbove(kept.session!.expiresAt!, Date.now() + 30 * 60_000);
        // Not near its expiry: OpenBao isn't asked anything.
        await vault.keepAlive();
        assert.lengthOf(stub.requests, 1);
        // Revoked elsewhere: forgotten when renewing (and keepAlive() doesn't fail).
        kept.session = { ...kept.session!, expiresAt: SOON() };
        tokenValid = false;
        await vault.keepAlive();
        assert.isNull(kept.session);
        assert.isFalse(await vault.hasKeys());
      } finally {
        stub.restore();
      }
      // A session that isn't the user's is forgotten, and its token revoked.
      const other = makeVault({ token: "t-mallory", expiresAt: LATER(), subject: "mallory" });
      const stub2 = routeFetch(() => [200]);
      try {
        assert.isFalse(await other.vault.hasKeys());
        assert.isNull(other.kept.session);
        assert.deepEqual(stub2.requests, ["POST auth/token/revoke-self"]);
      } finally {
        stub2.restore();
      }
    });
  });

  describe("createOpenBaoKeyVault", function() {
    function testBrowser(storage: ReturnType<typeof memoryStorage> | null = memoryStorage()) {
      // Timers planned (cancelled ones removed), and listeners to other tabs' changes.
      const timers = new Map<() => void, number>();
      const storageListeners: (() => void)[] = [];
      const closedTabs: boolean[] = [];
      const browser: OpenBaoBrowser & {
        timers: typeof timers, storageListeners: typeof storageListeners, closedTabs: typeof closedTabs,
      } = {
        origin: "https://grist.example.com", storage, timers, storageListeners, closedTabs,
        after: (ms, callback) => {
          timers.set(callback, ms);
          return () => { timers.delete(callback); };
        },
        onStorageChange: (callback) => { storageListeners.push(callback); },
        openTab() {
          const index = closedTabs.push(false) - 1;
          return {
            get closed() { return closedTabs[index]; },
            navigate() {},
            close() { closedTabs[index] = true; },
          };
        },
        // (A result for the state OpenBao gave, as soon as asked.)
        onCallback(_tab, listener) { setTimeout(() => listener("?code=c&state=st1"), 0); return () => {}; },
      };
      return browser;
    }
    const aliceKey = sessionStorageKey(config.url, "alice");

    it("renews the sign-in when it nears its expiry, as kept by any tab", async function() {
      const browser = testBrowser();
      const timer = () => {
        assert.equal(browser.timers.size, 1, "one renewal planned");
        return [...browser.timers.entries()][0];
      };
      browser.storage!.setItem(aliceKey, JSON.stringify({ token: "t1", expiresAt: LATER(), subject: "alice" }));
      await createOpenBaoKeyVault(config, "alice", browser);
      const requests: string[] = [];
      const stub = routeFetch((request) => {
        requests.push(request);
        return request === "POST auth/token/renew-self" ? [200, { auth: { lease_duration: 3600 } }] : [200];
      });
      try {
        // Planned for 10 minutes before it expires.
        assert.closeTo(timer()[1], 50 * 60_000, 5000);
        // Another tab signed in again (or renewed it): planned again, for that sign-in.
        browser.storage!.setItem(aliceKey, JSON.stringify({ token: "t2", expiresAt: Date.now() + 30 * 60_000,
          subject: "alice" }));
        browser.storageListeners.forEach(l => l());
        assert.closeTo(timer()[1], 20 * 60_000, 5000);
        // Its time comes: renewed (with the sign-in kept now), and planned again.
        browser.storage!.setItem(aliceKey, JSON.stringify({ token: "t2", expiresAt: SOON(), subject: "alice" }));
        timer()[0]();
        await new Promise(resolve => setTimeout(resolve, 10));
        assert.deepEqual(requests, ["POST auth/token/renew-self"]);
        assert.closeTo(timer()[1], 50 * 60_000, 5000);
        // Until OpenBao refuses it (e.g. revoked): forgotten, and nothing planned.
        browser.storage!.setItem(aliceKey, JSON.stringify({ token: "t2", expiresAt: SOON(), subject: "alice" }));
        stub.restore();
        const refusing = routeFetch(() => [403, { errors: ["permission denied"] }]);
        try {
          timer()[0]();
          await new Promise(resolve => setTimeout(resolve, 10));
          assert.isNull(browser.storage!.getItem(aliceKey));
          assert.equal(browser.timers.size, 0);
        } finally {
          refusing.restore();
        }
      } finally {
        stub.restore();
      }
    });

    it("uses the sign-in kept at each call, as another tab may have replaced it", async function() {
      const browser = testBrowser();
      browser.storage!.setItem(aliceKey, JSON.stringify({ token: "t1", expiresAt: LATER(), subject: "alice" }));
      const vault = await createOpenBaoKeyVault(config, "alice", browser);
      browser.storage!.setItem(aliceKey, JSON.stringify({ token: "t2", expiresAt: LATER(), subject: "alice" }));
      const stub = stubFetch({}, {});
      try {
        assert.isTrue(await vault.hasKeys());
        assert.deepEqual([...new Set(stub.requests.map(r => r.init.headers["X-Vault-Token"]))], ["t2"]);
      } finally {
        stub.restore();
      }
    });

    it("only forgets the sign-in it was given, not a newer one", function() {
      const storage = memoryStorage();
      storage.setItem(aliceKey, JSON.stringify({ token: "t2", expiresAt: LATER(), subject: "alice" }));
      forgetSession(storage, aliceKey, { token: "t1", expiresAt: LATER(), subject: "alice" });
      assert.equal(loadSession(storage, aliceKey)?.token, "t2");
      forgetSession(storage, aliceKey, { token: "t2", expiresAt: LATER(), subject: "alice" });
      assert.isNull(storage.getItem(aliceKey));
    });

    it("forgets (and revokes) sign-ins other users left in the browser", async function() {
      const browser = testBrowser();
      const bobKey = sessionStorageKey(config.url, "bob");
      browser.storage!.setItem(bobKey, JSON.stringify({ token: "t-bob", expiresAt: LATER(), subject: "bob" }));
      browser.storage!.setItem(aliceKey, JSON.stringify({ token: "t-alice", expiresAt: LATER(), subject: "alice" }));
      const stub = stubFetch({});
      try {
        await createOpenBaoKeyVault(config, "alice", browser);
        assert.deepEqual([...(browser.storage as any).map.keys()], [aliceKey]);
        assert.deepEqual(stub.requests.map(r => r.init.headers["X-Vault-Token"]), ["t-bob"]);
      } finally {
        stub.restore();
      }
    });

    it("closes its tab, and revokes a sign-in as someone else", async function() {
      const browser = testBrowser(null);
      const vault = await createOpenBaoKeyVault(config, "alice", browser);
      const stub = routeFetch((request) => {
        if (request.startsWith("POST auth/oidc/oidc/auth_url")) {
          return [200, { data: { auth_url: "https://idp.example.com/authorize?state=st1" } }];
        }
        if (request.startsWith("GET auth/oidc/oidc/callback")) {
          return [200, { auth: { client_token: "t-mallory", lease_duration: 3600, metadata: { subject: "mallory" } } }];
        }
        return [200];
      });
      try {
        await assert.isRejected(vault.openOnboarding(), /as another user/);
        assert.deepEqual(browser.closedTabs, [true]);
        assert.include(stub.requests, "POST auth/token/revoke-self");
        assert.isFalse(await vault.hasKeys());
      } finally {
        stub.restore();
      }
    });
  });

  describe("forgetOpenBaoSessions", function() {
    it("forgets every sign-in kept, and revokes their tokens", async function() {
      assert.doesNotThrow(() => forgetOpenBaoSessions(null));
      const storage = memoryStorage();
      const alice = sessionStorageKey("https://openbao.example.com", "alice");
      storage.setItem(alice, JSON.stringify({ token: "t-alice", expiresAt: null, subject: "alice" }));
      storage.setItem(sessionStorageKey("https://other.example.com/", "bob"),
        JSON.stringify({ token: "t-bob", expiresAt: Date.now() + 60_000, subject: "bob" }));
      storage.setItem("unrelated", "kept");
      assert.equal(loadSession(storage, alice)?.token, "t-alice");
      const stub = stubFetch({}, {});
      try {
        forgetOpenBaoSessions(storage);
        assert.deepEqual([...storage.map.keys()], ["unrelated"]);
        assert.deepEqual(stub.requests.map(r => [r.url, r.init.headers["X-Vault-Token"], r.init.keepalive]), [
          ["https://openbao.example.com/v1/auth/token/revoke-self", "t-alice", true],
          ["https://other.example.com/v1/auth/token/revoke-self", "t-bob", true],
        ]);
      } finally {
        stub.restore();
      }
    });

    it("drops expired or malformed sign-ins when loading them", function() {
      const storage = memoryStorage();
      const key = sessionStorageKey("https://openbao.example.com", "alice");
      storage.setItem(key, JSON.stringify({ token: "t", expiresAt: Date.now() - 1, subject: "alice" }));
      assert.isNull(loadSession(storage, key));
      assert.isNull(storage.getItem(key));
      storage.setItem(key, "{not json");
      assert.isNull(loadSession(storage, key));
      storage.setItem(key, JSON.stringify({ token: "t", expiresAt: null }));   // (No subject.)
      assert.isNull(loadSession(storage, key));
    });
  });
});
