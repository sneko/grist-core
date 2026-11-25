/**
 * The "lasuite" provider, against a stand-in for the LaSuite encryption service's SDK (client.js):
 * how Grist's calls translate to the service's, which the end-to-end tests (run with the "mock"
 * provider) don't reach.
 */
import { createLaSuiteKeyVault, LaSuiteKeyVault, VaultClient } from "app/client/encryption/providers/lasuite";

import { assert } from "chai";

const bytes = (...values: number[]) => new Uint8Array(values);
const buffer = (...values: number[]) => bytes(...values).buffer;

/** A stand-in for the service's VaultClient, recording calls, with keys at given versions. */
class FakeVaultClient implements VaultClient {
  public static instances: FakeVaultClient[] = [];
  public calls: [string, ...any[]][] = [];
  public versions: Record<string, { verified: boolean, version: number }> = {
    "sub-a": { verified: true, version: 1 },
    "sub-b": { verified: true, version: 3 },
    "sub-c": { verified: false, version: 1 },
  };

  // Changes the versions after this many fetches (to simulate a member replacing their keys).
  public changeVersionsAfter = Infinity;
  public listeners = new Map<string, Set<(data: any) => void>>();
  public theme: string;

  constructor(public options: any = {}) {
    this.theme = options.theme;
    FakeVaultClient.instances.push(this);
  }

  public async init() { this.calls.push(["init"]); }
  public setAuthContext(context: { suiteUserId: string }) { this.calls.push(["setAuthContext", context]); }
  public setTheme(theme: string) { this.theme = theme; }
  public async hasKeys() { return { hasKeys: true }; }
  public openOnboarding() { this.calls.push(["openOnboarding"]); }
  public openSettings() { this.calls.push(["openSettings"]); }
  public on(event: string, listener: (data: any) => void) {
    if (!this.listeners.has(event)) { this.listeners.set(event, new Set()); }
    this.listeners.get(event)!.add(listener);
  }

  public off(event: string, listener: (data: any) => void) { this.listeners.get(event)?.delete(listener); }
  public emit(event: string) { for (const l of [...(this.listeners.get(event) ?? [])]) { l({}); } }

  public async fetchPublicKeys(subs: string[]) {
    this.calls.push(["fetchPublicKeys", subs]);
    if (--this.changeVersionsAfter < 0) {
      this.versions = Object.fromEntries(Object.entries(this.versions)
        .map(([k, v]) => [k, { ...v, version: v.version + 1 }]));
    }
    return Object.fromEntries(subs.filter(s => this.versions[s]).map(s => [s, this.versions[s]]));
  }

  public async encryptWithoutKey(data: ArrayBuffer, recipients: Record<string, { email: string, name?: string }>) {
    this.calls.push(["encryptWithoutKey", data.byteLength, recipients]);
    return { encryptedContent: new ArrayBuffer(0), encryptedKeys: this._wrapsFor(recipients) };
  }

  public async shareKeys(key: ArrayBuffer, recipients: Record<string, { email: string, name?: string }>) {
    this.calls.push(["shareKeys", [...new Uint8Array(key)], recipients]);
    return { encryptedKeys: this._wrapsFor(recipients) };
  }

  public async encryptWithKey(data: ArrayBuffer, key: ArrayBuffer) {
    this.calls.push(["encryptWithKey", [...new Uint8Array(data)], [...new Uint8Array(key)]]);
    return { encryptedData: buffer(...new Uint8Array(data).map(b => b + 1)) };
  }

  public async decryptWithKey(data: ArrayBuffer, key: ArrayBuffer, keyVersion: number, chain?: ArrayBuffer[]) {
    this.calls.push(["decryptWithKey", [...new Uint8Array(data)], [...new Uint8Array(key)], keyVersion,
      chain?.map(c => [...new Uint8Array(c)])]);
    return { data: buffer(...new Uint8Array(data).map(b => b - 1)) };
  }

  public async encryptNestedWithoutKey(data: ArrayBuffer, key: ArrayBuffer) {
    this.calls.push(["encryptNestedWithoutKey", [...new Uint8Array(data)], [...new Uint8Array(key)]]);
    return { encryptedContent: buffer(...new Uint8Array(data).map(b => b + 1)), wrappedKey: buffer(42) };
  }

  private _wrapsFor(recipients: Record<string, unknown>) {
    return Object.fromEntries(Object.keys(recipients).map((sub, i) => [sub, buffer(100 + i)]));
  }
}

describe("encryption/providers/lasuite", function() {
  const alice = { vaultUserId: "sub-a", email: "alice@example.com", name: "Alice" };
  const bob = { vaultUserId: "sub-b", email: "bob@example.com" };
  let client: FakeVaultClient;
  let vault: LaSuiteKeyVault;

  beforeEach(function() {
    client = new FakeVaultClient();
    vault = new LaSuiteKeyVault(client);
  });

  it("counts as registered only the members whose keys the service verified", async function() {
    assert.deepEqual([...await vault.getRegisteredUsers(["sub-a", "sub-b", "sub-c", "sub-unknown"])].sort(),
      ["sub-a", "sub-b"]);
    assert.deepEqual([...await vault.getRegisteredUsers([])], []);
    // (No call to the service for nobody.)
    assert.lengthOf(client.calls, 1);
  });

  it("mints a document key wrapped for each member, with the version of their key", async function() {
    const wraps = await vault.createDocumentKey([alice, bob]);
    assert.deepEqual(client.calls.find(c => c[0] === "encryptWithoutKey"), ["encryptWithoutKey", 0, {
      "sub-a": { email: "alice@example.com", name: "Alice" },
      "sub-b": { email: "bob@example.com", name: undefined },
    }]);
    assert.deepEqual(wraps.get("sub-a"), { wrappedKey: bytes(100), keyVersion: 1 });
    assert.deepEqual(wraps.get("sub-b"), { wrappedKey: bytes(101), keyVersion: 3 });
  });

  it("shares the caller's copy of a key with more members", async function() {
    const wraps = await vault.shareDocumentKey({ wrappedKey: bytes(9, 9), keyVersion: 1 }, [bob]);
    assert.deepEqual(client.calls.find(c => c[0] === "shareKeys"),
      ["shareKeys", [9, 9], { "sub-b": { email: "bob@example.com", name: undefined } }]);
    assert.deepEqual(wraps.get("sub-b"), { wrappedKey: bytes(100), keyVersion: 3 });
  });

  it("refuses wraps made while a member replaced their keys", async function() {
    // The versions read before wrapping differ from those after: the wraps may be for older keys.
    client.changeVersionsAfter = 1;
    await assert.isRejected(vault.createDocumentKey([alice, bob]), /A member's encryption keys changed meanwhile/);
    // A member without keys can't be given one either.
    client = new FakeVaultClient();
    vault = new LaSuiteKeyVault(client);
    await assert.isRejected(vault.createDocumentKey([{ vaultUserId: "sub-unknown", email: "x@example.com" }]),
      /changed meanwhile/);
  });

  it("encrypts and decrypts with the caller's copy of the key, and its version", async function() {
    const myKey = { wrappedKey: bytes(7), keyVersion: 3 };
    // (A view on a larger buffer: only its own bytes go to the service.)
    const data = new Uint8Array(buffer(0, 1, 2, 3), 1, 2);
    const ciphertext = await vault.encrypt(data, myKey);
    assert.deepEqual([...ciphertext], [2, 3]);
    assert.deepEqual([...await vault.decrypt(ciphertext, myKey)], [1, 2]);
    assert.deepEqual(client.calls.filter(c => c[0].endsWith("WithKey")), [
      ["encryptWithKey", [1, 2], [7]],
      ["decryptWithKey", [2, 3], [7], 3, undefined],
    ]);
  });

  it("encrypts attachments with keys of their own, wrapped with the document's", async function() {
    const parentKey = { wrappedKey: bytes(7), keyVersion: 2 };
    const { ciphertext, nestedKey } = await vault.encryptWithNewKey(bytes(5), parentKey);
    assert.deepEqual([...nestedKey], [42]);
    assert.deepEqual([...await vault.decryptWithNestedKey(ciphertext, parentKey, nestedKey)], [5]);
    assert.deepEqual(client.calls.at(-1), ["decryptWithKey", [6], [7], 2, [[42]]]);
  });

  it("says whether the user completed the service's setup or closed it", async function() {
    const done = vault.openOnboarding();
    assert.deepEqual(client.calls.at(-1), ["openOnboarding"]);
    client.emit("onboarding:complete");
    assert.isTrue(await done);
    const closed = vault.openOnboarding();
    client.emit("interface:closed");
    assert.isFalse(await closed);
    // (No listener left behind.)
    assert.deepEqual([...client.listeners.values()].map(s => s.size), [0, 0]);
    vault.openSettings();
    assert.deepEqual(client.calls.at(-1), ["openSettings"]);
  });

  describe("createLaSuiteKeyVault", function() {
    let prev: { window: any, document: any };

    before(function() {
      prev = { window: (global as any).window, document: (global as any).document };
      // The SDK already loaded (client.js defines it), and what of the page it touches.
      (global as any).window = { EncryptionClient: { VaultClient: FakeVaultClient } };
      const elements: any[] = [];
      (global as any).document = {
        documentElement: { lang: "fr" },
        getElementById: (id: string) => elements.find(e => e.id === id) ?? null,
        createElement: () => ({}),
        head: { appendChild: (e: any) => elements.push(e) },
      };
    });
    after(function() {
      (global as any).window = prev.window;
      (global as any).document = prev.document;
    });

    const config = {
      kind: "lasuite" as const, vaultUrl: "https://vault.example.com/", interfaceUrl: "https://ui.example.com",
    };

    it("signs the user in to the service by their OIDC subject, in Grist's language and appearance", async function() {
      let onThemeChange: (theme: string) => void = () => {};
      FakeVaultClient.instances = [];
      await createLaSuiteKeyVault(config, "sub-a", { current: "dark", onChange: (l) => { onThemeChange = l; } });
      const [sdk] = FakeVaultClient.instances;
      assert.deepEqual(sdk.options,
        { vaultUrl: config.vaultUrl, interfaceUrl: config.interfaceUrl, lang: "fr", theme: "dark" });
      assert.deepEqual(sdk.calls, [["init"], ["setAuthContext", { suiteUserId: "sub-a" }]]);
      onThemeChange("default");
      assert.equal(sdk.theme, "default");
      // Its interface's iframe keeps its own color scheme (see keepInterfaceTransparent).
      const style = (global as any).document.getElementById("grist-encryption-interface-style");
      assert.include(style.textContent, `iframe[src^="https://ui.example.com"]`);
    });

    it("refuses a user the service can't know", async function() {
      await assert.isRejected(createLaSuiteKeyVault(config, null, { current: "default", onChange: () => {} }),
        /not known to the encryption service/);
    });
  });
});
