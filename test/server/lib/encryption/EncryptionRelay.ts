/**
 * Tests the server side of encrypted documents: the doc option, the relay of encrypted changes
 * between browsers, their storage in the document's file, and the management of keys.
 */
import { marshalValue, unmarshalValue } from "app/common/encryption/EncryptedPayloads";
import { gunzip, gzip } from "app/common/encryption/EncryptionCrypto";
import {
  DOC_SCOPE, DocKeyRecord, ENCRYPTED_DOC_SERVER_ERROR, ENCRYPTED_PART_BYTES, EncryptedDocOpenResult,
  EncryptionKeysResult, EncryptionMember,
} from "app/common/encryption/EncryptionTypes";
import { UserAPI } from "app/common/UserAPI";
import { DocEncryptionKey, DocEncryptionKeyWrap } from "app/gen-server/entity/DocEncryption";
import { getEncryptionClientConfig } from "app/server/lib/encryption/encryptionConfig";
import { Deps as RelayDeps } from "app/server/lib/encryption/EncryptionRelay";
import { SQLiteDB } from "app/server/lib/SQLiteDB";
import { TestServer } from "test/gen-server/apiUtils";
import { GristClient, openClient } from "test/server/gristClient";
import * as testUtils from "test/server/testUtils";

import { assert } from "chai";
import * as fse from "fs-extra";

const ORG = "encryption";

describe("encryption/EncryptionRelay", function() {
  this.timeout(20000);
  testUtils.setTmpLogLevel("error");

  let home: TestServer;
  let owner: UserAPI;
  let wsId: number;
  let docId: string;
  let plainDocId: string;
  let clients: GristClient[] = [];
  let docKeyId: string;
  const ids: Record<string, number> = {};

  const b64 = (text: string) => Buffer.from(text).toString("base64");
  const wrap = (userId: number, keyId?: string): any =>
    ({ userId, wrappedKey: b64(`wrap-${userId}`), keyVersion: 1, ...(keyId ? { keyId } : {}) });

  async function connect(email: string) {
    const client = await openClient(home.server, email, ORG);
    clients.push(client);
    await client.readMessage();   // clientConnect
    return client;
  }

  // Messages received by each client, including those that arrived while awaiting responses.
  const received = new Map<GristClient, any[]>();

  async function call(client: GristClient, method: string, ...args: any[]) {
    const resp = await client.send(method, ...args);
    stash(client, client.messages);
    if (resp.error) { throw new Error(resp.error); }
    return resp.data;
  }

  function stash(client: GristClient, messages: any[]) {
    if (!received.has(client)) { received.set(client, []); }
    received.get(client)!.push(...messages);
  }

  /** Returns the next message of the given type, waiting for it for a short time. */
  async function nextMessage(client: GristClient, type: string, timeoutMs = 1000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      while (client.count() > 0) { stash(client, [client.shift()]); }
      const messages = received.get(client) || [];
      const index = messages.findIndex(m => m.type === type);
      if (index >= 0) { return messages.splice(index, 1)[0]; }
      if (Date.now() >= deadline) { return null; }
      await new Promise(r => setTimeout(r, 20));
    }
  }

  let suiteEnv: testUtils.EnvironmentSnapshot;

  before(async function() {
    suiteEnv = new testUtils.EnvironmentSnapshot();
    process.env.GRIST_ENCRYPTION_FEATURE_ENABLED = "true";
    process.env.GRIST_ENCRYPTION_MOCK_VAULT = "true";
    home = new TestServer(this);
    await home.start(["home", "docs"]);
    const api = await home.createHomeApi("chimpy", "docs", true);
    await api.newOrg({ name: ORG, domain: ORG });
    owner = await home.createHomeApi("chimpy", ORG, true);
    wsId = await owner.newWorkspace({ name: "encryption" }, "current");
    await owner.updateWorkspacePermissions(wsId, {
      users: { "charon@getgrist.com": "editors", "kiwi@getgrist.com": "viewers" },
    });
    docId = await owner.newDoc({ name: "secret", options: { encryption: { version: 1 } } }, wsId);
    plainDocId = await owner.newDoc({ name: "plain" }, wsId);
    for (const email of ["chimpy@getgrist.com", "charon@getgrist.com", "kiwi@getgrist.com", "outsider@getgrist.com"]) {
      ids[email] = (await home.dbManager.getUserByLogin(email)).id;
    }
  });

  afterEach(async function() {
    await Promise.all(clients.map(c => c.close()));
    clients = [];
  });

  after(async function() {
    const api = await home.createHomeApi("chimpy", "docs");
    await api.deleteOrg(ORG);
    await home.stop();
    suiteEnv.restore();
  });

  describe("configuration", function() {
    let env: testUtils.EnvironmentSnapshot;
    beforeEach(() => { env = new testUtils.EnvironmentSnapshot(); });
    afterEach(() => { env.restore(); });

    it("uses the encryption service, or a stand-in outside of production", function() {
      process.env.GRIST_ENCRYPTION_MOCK_VAULT = "false";
      process.env.GRIST_ENCRYPTION_FEATURE_ENABLED = "false";
      assert.isUndefined(getEncryptionClientConfig());
      process.env.GRIST_ENCRYPTION_FEATURE_ENABLED = "true";
      assert.throws(() => getEncryptionClientConfig(), /requires GRIST_ENCRYPTION_VAULT_URL/);
      process.env.GRIST_ENCRYPTION_VAULT_URL = "https://vault.example.com";
      process.env.GRIST_ENCRYPTION_INTERFACE_URL = "https://interface.example.com";
      assert.deepEqual(getEncryptionClientConfig(),
        { vaultUrl: "https://vault.example.com", interfaceUrl: "https://interface.example.com" });
      process.env.GRIST_ENCRYPTION_MOCK_VAULT = "true";
      process.env.NODE_ENV = "development";
      assert.deepEqual(getEncryptionClientConfig(), { mockVault: true });
      process.env.NODE_ENV = "production";
      assert.throws(() => getEncryptionClientConfig(), /no security, and can't be used in production/);
    });

    it("reads the AI service browsers may call for encrypted documents", function() {
      process.env.GRIST_ENCRYPTION_FEATURE_ENABLED = "true";
      process.env.GRIST_ENCRYPTION_MOCK_VAULT = "true";
      process.env.NODE_ENV = "development";
      const assistant = { endpoint: "https://ai.example.com/v1/chat/completions", model: "m", provider: "Example",
        sovereign: true, auth: "user-key" as const };
      process.env.GRIST_ENCRYPTION_ASSISTANT = JSON.stringify(assistant);
      assert.deepEqual(getEncryptionClientConfig()?.assistant, assistant);
      for (const [value, error] of [
        ["{", /invalid JSON/],
        [JSON.stringify({ ...assistant, endpoint: "http://ai.example.com/" }), /https URL/],
        [JSON.stringify({ ...assistant, sovereign: "yes" }), /sovereign/],
        [JSON.stringify({ ...assistant, auth: "server-key" }), /auth must be/],
      ] as const) {
        process.env.GRIST_ENCRYPTION_ASSISTANT = value;
        assert.throws(() => getEncryptionClientConfig(), error);
      }
    });

    it("refuses encrypted documents when they're not enabled", async function() {
      process.env.GRIST_ENCRYPTION_FEATURE_ENABLED = "false";
      await assert.isRejected(owner.newDoc({ name: "x", options: { encryption: { version: 1 } } }, wsId),
        /not enabled on this server/);
    });
  });

  describe("document option", function() {
    it("is set at creation, and can't be changed afterwards", async function() {
      assert.deepEqual((await owner.getDoc(docId)).options?.encryption, { version: 1 });
      await assert.isRejected(owner.updateDoc(docId, { options: { encryption: null } }),
        /can only be chosen when creating/);
      await assert.isRejected(owner.updateDoc(plainDocId, { options: { encryption: { version: 1 } } }),
        /can only be chosen when creating/);
      await owner.updateDoc(docId, { options: { description: "shh" } });
      await owner.updateDoc(docId, { options: null });
      assert.deepEqual((await owner.getDoc(docId)).options, { encryption: { version: 1 } });
      await assert.isRejected(owner.newDoc({ name: "x", options: { encryption: { version: 2 } as any } }, wsId),
        /Unsupported end-to-end encryption version/);
    });

    it("keeps the server from opening the document", async function() {
      const client = await connect("chimpy@getgrist.com");
      const resp = await client.send("openDoc", docId);
      assert.include(resp.error, ENCRYPTED_DOC_SERVER_ERROR);
      await assert.isRejected(owner.getDocAPI(docId).getRows("Table1"), /end-to-end encrypted/);
      await assert.isRejected(owner.getDocAPI(docId).fork(), /end-to-end encrypted/);
    });

    it("keeps encrypted documents restricted to their members", async function() {
      await assert.isRejected(owner.updateDocPermissions(docId, { users: { "everyone@getgrist.com": "viewers" } }),
        /must remain restricted/);
      await assert.isRejected(owner.updateDocPermissions(docId, { users: { "anon@getgrist.com": "viewers" } }),
        /must remain restricted/);
    });
  });

  describe("relay", function() {
    it("lets the owner set up the document", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const opened: EncryptedDocOpenResult = await call(alice, "openEncryptedDoc", docId);
      assert.deepInclude(opened, { snapshot: null, actions: [], head: 0, keys: [], myKeys: [] });
      assert.equal(opened.access, "owners");
      assert.equal(opened.user.email, "chimpy@getgrist.com");

      // Nothing can happen before there is a key and an initial state.
      assert.deepEqual(await call(alice, "pushEncryptedAction", docId, 0, "doc~x", b64("change")),
        { accepted: false, head: 0 });
      await assert.isRejected(call(alice, "saveEncryptedSnapshot", docId, 0, "doc~x", b64("state")),
        /current document key/);

      // Only owners create the first key, and it must include them.
      const bob = await connect("charon@getgrist.com");
      docKeyId = "doc~first";
      await assert.isRejected(call(bob, "createEncryptionKey", docId,
        { scope: DOC_SCOPE, keyId: docKeyId, baseActionNum: 0, wraps: [wrap(ids["charon@getgrist.com"])] }),
      /Only owners/);
      await assert.isRejected(call(alice, "createEncryptionKey", docId,
        { scope: DOC_SCOPE, keyId: docKeyId, baseActionNum: 0, wraps: [wrap(ids["charon@getgrist.com"])] }),
      /copy for its creator/);
      await assert.isRejected(call(alice, "createEncryptionKey", docId,
        { scope: DOC_SCOPE, keyId: "other~x", baseActionNum: 0, wraps: [wrap(ids["chimpy@getgrist.com"])] }),
      /Invalid key id/);
      assert.deepInclude(await call(alice, "createEncryptionKey", docId,
        { scope: DOC_SCOPE, keyId: docKeyId, baseActionNum: 0, wraps: [wrap(ids["chimpy@getgrist.com"])] }),
      { accepted: true, actionNum: 0 });
      await call(alice, "saveEncryptedSnapshot", docId, 0, docKeyId, b64("state0"));
      await assert.isRejected(call(alice, "saveEncryptedSnapshot", docId, 0, docKeyId, b64("again")),
        /already initialized/);

      const reopened: EncryptedDocOpenResult = await call(alice, "openEncryptedDoc", docId);
      assert.deepEqual(reopened.snapshot?.payload, b64("state0"));
      assert.deepEqual(reopened.keys,
        [{ keyId: docKeyId, scope: DOC_SCOPE, current: true, rotateOnNextEdit: false, actionNum: 0 }]);
      assert.deepEqual(reopened.bindings, []);
      assert.deepEqual(reopened.myKeys, [wrap(ids["chimpy@getgrist.com"], docKeyId)]);
    });

    it("stores encrypted content in the document's file, not in the home database", async function() {
      const path = home.server.getStorageManager().getPath(docId);
      assert.isTrue(await fse.pathExists(path));
      const db = await SQLiteDB.openDBRaw(path);
      try {
        const snapshots = await db.all("SELECT actionNum, keyId FROM _gristsys_EncryptedSnapshots");
        assert.deepEqual(snapshots, [{ actionNum: 0, keyId: docKeyId }]);
      } finally {
        await db.close();
      }
    });

    it("orders changes and forwards them to other browsers", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      const kiwi = await connect("kiwi@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      const bobOpened: EncryptedDocOpenResult = await call(bob, "openEncryptedDoc", docId);
      assert.equal(bobOpened.access, "editors");
      assert.deepEqual(bobOpened.myKeys, []);
      assert.equal((await call(kiwi, "openEncryptedDoc", docId)).access, "viewers");

      assert.deepInclude(await call(alice, "pushEncryptedAction", docId, 0, docKeyId, b64("c1")),
        { accepted: true, actionNum: 1 });
      // Bob doesn't hold the document key yet: he can't make changes others could read.
      await assert.isRejected(call(bob, "pushEncryptedAction", docId, 1, docKeyId, b64("c1-bob")),
        /holding the document key/);
      // A change made with a key that isn't the current document key is refused.
      assert.deepEqual(await call(alice, "pushEncryptedAction", docId, 1, "doc~old", b64("c2")),
        { accepted: false, head: 1 });

      for (const client of [bob, kiwi]) {
        const msg = await nextMessage(client, "encryptedDocAction");
        assert.equal(msg?.data.docId, docId);
        assert.deepInclude(msg?.data.action, { actionNum: 1, kind: "change", keyId: docKeyId, payload: b64("c1") });
      }
      assert.isNull(await nextMessage(alice, "encryptedDocAction", 300));

      assert.deepInclude(await call(alice, "pushEncryptedAction", docId, 1, docKeyId, b64("c2")),
        { accepted: true, actionNum: 2 });
      assert.deepInclude((await nextMessage(bob, "encryptedDocAction"))?.data.action, { actionNum: 2 });
      const all = await call(kiwi, "fetchEncryptedActions", docId, 0);
      assert.deepEqual(all.map((a: any) => [a.actionNum, a.payload]), [[1, b64("c1")], [2, b64("c2")]]);

      await assert.isRejected(call(kiwi, "pushEncryptedAction", docId, 2, docKeyId, b64("c3")), /No write access/);
      await assert.isRejected(call(kiwi, "saveEncryptedSnapshot", docId, 2, docKeyId, b64("s")), /No write access/);
      await assert.isRejected(call(alice, "pushEncryptedAction", docId, 2, docKeyId, "not base64!"),
        /Invalid encrypted payload/);
      await assert.isRejected(call(alice, "pushEncryptedAction", docId, -1, docKeyId, b64("x")),
        /Invalid action number/);
      // Only key holders save snapshots.
      await assert.isRejected(call(bob, "saveEncryptedSnapshot", docId, 2, docKeyId, b64("s")), /holding/);
      // Others opening the document (and seeing fewer members than its owner does) didn't take
      // anyone's keys away.
      assert.deepEqual((await call(alice, "getEncryptionKeys", docId)).myKeys.map((k: any) => k.keyId), [docKeyId]);
    });

    it("lets owners give keys to members", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      await call(bob, "openEncryptedDoc", docId);

      const members: EncryptionMember[] = await call(bob, "listEncryptionMembers", docId);
      const byEmail = Object.fromEntries(members.map(m => [m.email, m]));
      assert.deepInclude(byEmail["chimpy@getgrist.com"], { access: "owners", keyIds: [docKeyId] });
      assert.deepInclude(byEmail["charon@getgrist.com"], { access: "editors", keyIds: [] });
      assert.deepInclude(byEmail["kiwi@getgrist.com"], { access: "viewers", keyIds: [] });

      // Only owners give keys, only keys they hold, and only to members.
      await assert.isRejected(call(bob, "shareEncryptionKeys", docId, [wrap(ids["kiwi@getgrist.com"], docKeyId)]),
        /No owner access|access/i);
      await assert.isRejected(call(alice, "shareEncryptionKeys", docId, [wrap(ids["kiwi@getgrist.com"], "doc~other")]),
        /holding a key/);
      await assert.isRejected(call(alice, "shareEncryptionKeys", docId,
        [wrap(ids["outsider@getgrist.com"], docKeyId)]), /only be given to members/);

      await call(alice, "shareEncryptionKeys", docId,
        [wrap(ids["charon@getgrist.com"], docKeyId), wrap(ids["kiwi@getgrist.com"], docKeyId)]);
      assert.equal((await nextMessage(bob, "encryptedDocKeys"))?.data.docId, docId);
      const keys: EncryptionKeysResult = await call(bob, "getEncryptionKeys", docId);
      assert.deepEqual(keys.myKeys, [wrap(ids["charon@getgrist.com"], docKeyId)]);
      // Now Bob can save snapshots, and make changes, ordered with others'.
      await call(bob, "saveEncryptedSnapshot", docId, 2, docKeyId, b64("state2"));
      assert.deepEqual(await call(bob, "pushEncryptedAction", docId, 1, docKeyId, b64("c2-bob")),
        { accepted: false, head: 2 });
    });

    it("records new keys in the history, for those who held the previous one", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      await call(bob, "openEncryptedDoc", docId);
      const outsiderWraps = [wrap(ids["charon@getgrist.com"]), wrap(ids["outsider@getgrist.com"])];
      // A replacement key can only go to those who held the previous one.
      await assert.isRejected(call(bob, "createEncryptionKey", docId,
        { scope: DOC_SCOPE, keyId: "doc~second", baseActionNum: 2, wraps: outsiderWraps }), /held the one it replaces/);
      // It's ordered like a change.
      const wraps: DocKeyRecord[] = [wrap(ids["charon@getgrist.com"]), wrap(ids["chimpy@getgrist.com"])];
      assert.deepEqual(await call(bob, "createEncryptionKey", docId,
        { scope: DOC_SCOPE, keyId: "doc~second", baseActionNum: 1, wraps }), { accepted: false, head: 2 });
      assert.deepInclude(await call(bob, "createEncryptionKey", docId,
        { scope: DOC_SCOPE, keyId: "doc~second", baseActionNum: 2, wraps }), { accepted: true, actionNum: 3 });
      assert.deepInclude((await nextMessage(alice, "encryptedDocAction"))?.data.action,
        { actionNum: 3, kind: "key", keyId: "doc~second", payload: "" });
      const keys: EncryptionKeysResult = await call(alice, "getEncryptionKeys", docId);
      assert.deepEqual(keys.keys.map(k => [k.keyId, k.current]), [[docKeyId, false], ["doc~second", true]]);
      // Changes must now use the new key.
      assert.deepEqual(await call(alice, "pushEncryptedAction", docId, 3, docKeyId, b64("c4")),
        { accepted: false, head: 3 });
      assert.deepInclude(await call(alice, "pushEncryptedAction", docId, 3, "doc~second", b64("c4")),
        { accepted: true, actionNum: 4 });
      docKeyId = "doc~second";
    });

    it("takes keys away from members who lose access, flagging them for replacement", async function() {
      const alice = await connect("chimpy@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      // Kiwi held the first document key.
      await owner.updateWorkspacePermissions(wsId, { users: { "kiwi@getgrist.com": null } });
      home.dbManager.flushDocAuthCache();
      const members: EncryptionMember[] = await call(alice, "listEncryptionMembers", docId);
      assert.notInclude(members.map(m => m.email), "kiwi@getgrist.com");
      const keys: EncryptionKeysResult = await call(alice, "getEncryptionKeys", docId);
      assert.isTrue(keys.keys.find(k => k.keyId === docKeyId)!.rotateOnNextEdit);
      const allWraps = await home.dbManager.connection.manager.find(DocEncryptionKeyWrap, { where: { docId } });
      assert.notInclude(allWraps.map(w => w.userId), ids["kiwi@getgrist.com"]);
      await owner.updateWorkspacePermissions(wsId, { users: { "kiwi@getgrist.com": "viewers" } });
      home.dbManager.flushDocAuthCache();
    });

    it("lets owners take keys away and request replacements", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      await assert.isRejected(call(bob, "revokeEncryptionKeys", docId, [ids["chimpy@getgrist.com"]]), /access/i);
      await call(alice, "revokeEncryptionKeys", docId, [ids["charon@getgrist.com"]], DOC_SCOPE);
      const keys: EncryptionKeysResult = await call(bob, "getEncryptionKeys", docId);
      assert.deepEqual(keys.myKeys, []);
      await call(alice, "requestKeyRotation", docId, DOC_SCOPE);
      assert.isTrue((await call(alice, "getEncryptionKeys", docId)).keys.find((k: any) => k.current).rotateOnNextEdit);
    });

    it("stores encrypted files", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const kiwi = await connect("kiwi@getgrist.com");
      const { fileId } = await call(alice, "uploadEncryptedFile", docId, b64("ciphertext of a file"));
      assert.match(fileId, /^[0-9a-f]{32}$/);
      assert.deepEqual(await call(kiwi, "fetchEncryptedFile", docId, fileId),
        { payload: b64("ciphertext of a file"), size: 20 });
      // Parts of it.
      assert.deepEqual(await call(kiwi, "fetchEncryptedFile", docId, fileId, 14, 100),
        { payload: b64("a file"), size: 20 });
      await assert.isRejected(call(kiwi, "uploadEncryptedFile", docId, b64("x")), /No write access/);
      await assert.isRejected(call(kiwi, "fetchEncryptedFile", docId, "0".repeat(32)), /not found/);
    });

    it("prunes changes older than kept snapshots", async function() {
      const alice = await connect("chimpy@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      await assert.isRejected(call(alice, "saveEncryptedSnapshot", docId, 9, docKeyId, b64("ahead")), /doesn't match/);
      await call(alice, "saveEncryptedSnapshot", docId, 4, docKeyId, b64("state4"));
      // The latest few snapshots are kept (here at 0, 2 and 4), with the changes since the oldest.
      assert.deepEqual((await call(alice, "fetchEncryptedActions", docId, 0)).map((a: any) => a.actionNum),
        [1, 2, 3, 4]);
      // Only owners can drop the history.
      const bob = await connect("charon@getgrist.com");
      await assert.isRejected(call(bob, "saveEncryptedSnapshot", docId, 4, docKeyId, b64("x"), { compact: true }),
        /Only owners/);
      // Compacting keeps only the latest snapshot, even of the same state.
      await call(alice, "saveEncryptedSnapshot", docId, 4, docKeyId, b64("state4bis"), { compact: true });
      const opened: EncryptedDocOpenResult = await call(alice, "openEncryptedDoc", docId);
      assert.equal(opened.snapshot?.payload, b64("state4bis"));
      assert.deepEqual(opened.actions, []);
      assert.equal(opened.head, 4);
      // The history continues from there.
      assert.deepInclude(await call(alice, "pushEncryptedAction", docId, 4, docKeyId, b64("c5")),
        { accepted: true, actionNum: 5 });
    });

    it("keeps track of private columns, which only owners holding their key make public", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      await call(bob, "openEncryptedDoc", docId);
      const scope = "column:abc123";
      const wraps = [wrap(ids["chimpy@getgrist.com"])];
      // Making a column private says which one.
      await assert.isRejected(call(alice, "createEncryptionKey", docId,
        { scope, keyId: `${scope}~1`, baseActionNum: 5, wraps }), /which column/);
      await assert.isRejected(call(bob, "createEncryptionKey", docId,
        { scope, keyId: `${scope}~1`, baseActionNum: 5, wraps: [wrap(ids["charon@getgrist.com"])], colRef: 7 }),
      /Only owners/);
      assert.deepInclude(await call(alice, "createEncryptionKey", docId,
        { scope, keyId: `${scope}~1`, baseActionNum: 5, wraps, colRef: 7 }), { accepted: true, actionNum: 6 });
      assert.deepInclude((await nextMessage(bob, "encryptedDocAction"))?.data.action, { actionNum: 6, kind: "key" });
      let keys: EncryptionKeysResult = await call(bob, "getEncryptionKeys", docId);
      assert.deepEqual(keys.bindings, [{ scope, colRef: 7, boundAt: 6, releasedAt: null }]);
      assert.deepInclude(keys.keys.find(k => k.scope === scope), { keyId: `${scope}~1`, actionNum: 6 });
      await assert.isRejected(call(alice, "createEncryptionKey", docId,
        { scope: "column:other", keyId: "column:other~1", baseActionNum: 6, wraps, colRef: 7 }), /already private/);
      // Only owners holding its key can make it public again: editors can't, even holding it.
      await call(alice, "shareEncryptionKeys", docId, [wrap(ids["charon@getgrist.com"], `${scope}~1`)]);
      await assert.isRejected(call(bob, "releaseEncryptionScope", docId, scope, 6), /No owner access|access/i);
      // It's recorded in the history, ordered like a change.
      assert.deepEqual(await call(alice, "releaseEncryptionScope", docId, scope, 5), { accepted: false, head: 6 });
      assert.deepInclude(await call(alice, "releaseEncryptionScope", docId, scope, 6),
        { accepted: true, actionNum: 7 });
      assert.deepInclude((await nextMessage(bob, "encryptedDocAction"))?.data.action,
        { actionNum: 7, kind: "key", keyId: `${scope}~1` });
      keys = await call(bob, "getEncryptionKeys", docId);
      assert.deepEqual(keys.bindings, [{ scope, colRef: 7, boundAt: 6, releasedAt: 7 }]);
      await assert.isRejected(call(alice, "releaseEncryptionScope", docId, scope, 7), /not private/);

      // A whole table can be made private too: its target is minus its row id (see tableTarget()).
      const tableScope = "column:table3";
      await assert.isRejected(call(alice, "createEncryptionKey", docId,
        { scope: tableScope, keyId: `${tableScope}~1`, baseActionNum: 7, wraps, colRef: 0 }), /which column or table/);
      assert.deepInclude(await call(alice, "createEncryptionKey", docId,
        { scope: tableScope, keyId: `${tableScope}~1`, baseActionNum: 7, wraps, colRef: -3 }),
      { accepted: true, actionNum: 8 });
      keys = await call(bob, "getEncryptionKeys", docId);
      assert.deepInclude(keys.bindings, { scope: tableScope, colRef: -3, boundAt: 8, releasedAt: null });
      await assert.isRejected(call(alice, "createEncryptionKey", docId,
        { scope: "column:table3b", keyId: "column:table3b~1", baseActionNum: 8, wraps, colRef: -3 }),
      /table is already private/);
    });

    it("refuses access to non-members and to regular documents", async function() {
      const outsider = await connect("outsider@getgrist.com");
      await assert.isRejected(call(outsider, "openEncryptedDoc", docId), /No view access/);
      await assert.isRejected(call(outsider, "fetchEncryptedActions", docId, 0), /No view access/);
      const alice = await connect("chimpy@getgrist.com");
      await assert.isRejected(call(alice, "openEncryptedDoc", plainDocId), /not end-to-end encrypted/);
    });

    it("moves big snapshots and files by parts", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const kiwi = await connect("kiwi@getgrist.com");
      const opened: EncryptedDocOpenResult = await call(alice, "openEncryptedDoc", docId);
      const big = Buffer.alloc(ENCRYPTED_PART_BYTES + 1000, 7);
      big.write("start");
      big.write("end", big.length - 3);
      // Uploads go in order, by members who can write.
      const uploadId = await call(alice, "beginEncryptedUpload", docId);
      await assert.isRejected(call(kiwi, "beginEncryptedUpload", docId), /No write access/);
      await assert.isRejected(call(alice, "appendEncryptedUpload", docId, uploadId, 1, b64("x")), /Unknown or expired/);
      await call(alice, "appendEncryptedUpload", docId, uploadId, 0,
        big.subarray(0, ENCRYPTED_PART_BYTES).toString("base64"));
      await call(alice, "appendEncryptedUpload", docId, uploadId, 1,
        big.subarray(ENCRYPTED_PART_BYTES).toString("base64"));
      await call(alice, "saveEncryptedSnapshot", docId, opened.head, docKeyId, { uploadId });
      // (An upload is used once.)
      await assert.isRejected(call(alice, "uploadEncryptedFile", docId, { uploadId }), /Unknown or expired/);
      // Opening gives its size rather than its content, fetched by parts.
      const reopened: EncryptedDocOpenResult = await call(kiwi, "openEncryptedDoc", docId);
      assert.deepInclude(reopened.snapshot, { actionNum: opened.head, payload: "", size: big.length });
      const first = await call(kiwi, "fetchEncryptedSnapshot", docId, opened.head, 0, ENCRYPTED_PART_BYTES);
      const rest = await call(kiwi, "fetchEncryptedSnapshot", docId, opened.head, ENCRYPTED_PART_BYTES,
        ENCRYPTED_PART_BYTES);
      assert.isTrue(Buffer.concat([Buffer.from(first, "base64"), Buffer.from(rest, "base64")]).equals(big));
      await assert.isRejected(call(kiwi, "fetchEncryptedSnapshot", docId, opened.head, 0, ENCRYPTED_PART_BYTES + 1),
        /Invalid range/);
      // Same for files.
      const fileUpload = await call(alice, "beginEncryptedUpload", docId);
      await call(alice, "appendEncryptedUpload", docId, fileUpload, 0, big.toString("base64").slice(0, 4000));
      const { fileId } = await call(alice, "uploadEncryptedFile", docId, { uploadId: fileUpload });
      assert.deepEqual(await call(kiwi, "fetchEncryptedFile", docId, fileId, 0, 5),
        { payload: b64("start"), size: 3000 });
    });

    it("keeps documents within their maximum size", async function() {
      const alice = await connect("chimpy@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      const env = new testUtils.EnvironmentSnapshot();
      try {
        process.env.GRIST_ENCRYPTION_MAX_DOC_SIZE_MB = "1";
        await assert.isRejected(call(alice, "uploadEncryptedFile", docId, Buffer.alloc(2e6).toString("base64")),
          /maximum size/);
      } finally {
        env.restore();
      }
      await call(alice, "uploadEncryptedFile", docId, Buffer.alloc(2e6).toString("base64"));
    });

    describe("documents whose key only one member holds", function() {
      let soleDocId: string;

      before(async function() {
        // A document whose key only Bob holds (Alice gave it to him, and gave hers up).
        soleDocId = await owner.newDoc({ name: "sole", options: { encryption: { version: 1 } } }, wsId);
        const alice = await connect("chimpy@getgrist.com");
        await call(alice, "openEncryptedDoc", soleDocId);
        await call(alice, "createEncryptionKey", soleDocId,
          { scope: DOC_SCOPE, keyId: "doc~sole", baseActionNum: 0, wraps: [wrap(ids["chimpy@getgrist.com"])] });
        await call(alice, "shareEncryptionKeys", soleDocId, [wrap(ids["charon@getgrist.com"], "doc~sole")]);
        await call(alice, "revokeEncryptionKeys", soleDocId, [ids["chimpy@getgrist.com"]]);
      });

      after(async function() {
        await owner.deleteDoc(soleDocId);
      });

      it("refuses changes leaving nobody holding its key with access to it", async function() {
        const unreadable = /nobody able to read the encrypted document "sole"/;
        // Removing Bob from the workspace, or the site, or moving the document where he can't go.
        await assert.isRejected(owner.updateWorkspacePermissions(wsId, { users: { "charon@getgrist.com": null } }),
          unreadable);
        await assert.isRejected(owner.updateOrgPermissions(ORG, { users: { "charon@getgrist.com": null } }),
          unreadable);
        const otherWsId = await owner.newWorkspace({ name: "elsewhere" }, "current");
        try {
          await assert.isRejected(owner.moveDoc(soleDocId, otherWsId), unreadable);
          // Not inheriting access from the workspace either.
          await assert.isRejected(owner.updateDocPermissions(soleDocId, { maxInheritedRole: null }), unreadable);
          // Nothing changed.
          assert.equal((await owner.getDoc(soleDocId)).workspace.id, wsId);
          // Once Bob has access to the document of its own, it's all fine.
          await owner.updateDocPermissions(soleDocId, { users: { "charon@getgrist.com": "editors" } });
          await owner.moveDoc(soleDocId, otherWsId);
          await owner.moveDoc(soleDocId, wsId);
        } finally {
          await owner.deleteWorkspace(otherWsId);
        }
        // Other documents aren't concerned.
        await owner.updateWorkspacePermissions(wsId, { users: { "kiwi@getgrist.com": "editors" } });
        await owner.updateWorkspacePermissions(wsId, { users: { "kiwi@getgrist.com": "viewers" } });
      });
    });

    it("stops forwarding changes to members who lost access", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const kiwi = await connect("kiwi@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      await call(kiwi, "openEncryptedDoc", docId);
      await owner.updateWorkspacePermissions(wsId, { users: { "kiwi@getgrist.com": null } });
      home.dbManager.flushDocAuthCache();
      await call(alice, "pushEncryptedAction", docId, 5, docKeyId, b64("c6"));
      assert.isNull(await nextMessage(kiwi, "encryptedDocAction", 300));
      await assert.isRejected(call(kiwi, "fetchEncryptedActions", docId, 0), /No view access/);
      await owner.updateWorkspacePermissions(wsId, { users: { "kiwi@getgrist.com": "viewers" } });
      home.dbManager.flushDocAuthCache();
    });
  });

  describe("sensitive changes", function() {
    let sensitiveDocId: string;

    // A new encrypted document, set up by Alice, with Bob holding its key too.
    async function setUp(name: string) {
      const newDocId = await owner.newDoc({ name, options: { encryption: { version: 1 } } }, wsId);
      const alice = await connect("chimpy@getgrist.com");
      await call(alice, "openEncryptedDoc", newDocId);
      await call(alice, "createEncryptionKey", newDocId,
        { scope: DOC_SCOPE, keyId: "doc~k1", baseActionNum: 0, wraps: [wrap(ids["chimpy@getgrist.com"])] });
      await call(alice, "saveEncryptedSnapshot", newDocId, 0, "doc~k1", b64("state0"));
      await call(alice, "shareEncryptionKeys", newDocId, [wrap(ids["charon@getgrist.com"], "doc~k1")]);
      await call(alice, "pushEncryptedAction", newDocId, 0, "doc~k1", b64("c1"));
      return { alice, newDocId };
    }

    before(async function() {
      sensitiveDocId = (await setUp("sensitive")).newDocId;
    });

    it("saves snapshots along with key changes, together or not at all", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", sensitiveDocId);
      const wraps = [wrap(ids["chimpy@getgrist.com"])];
      // Only owners drop the history, even along with a key change.
      await assert.isRejected(call(bob, "createEncryptionKey", sensitiveDocId, {
        scope: DOC_SCOPE, keyId: "doc~k2", baseActionNum: 1, wraps: [wrap(ids["charon@getgrist.com"])],
        snapshot: b64("state2"), compact: true,
      }), /Only owners can drop the history/);
      // Making a column private, with the snapshot that drops what was readable before.
      const request = {
        scope: "column:salary", keyId: "column:salary~1", baseActionNum: 1, wraps, colRef: 3,
        snapshot: b64("state2-private"), compact: true,
      };
      // Refused as a whole when not on top of the latest change.
      assert.deepEqual(await call(alice, "createEncryptionKey", sensitiveDocId, { ...request, baseActionNum: 0 }),
        { accepted: false, head: 1 });
      assert.deepEqual((await call(alice, "getEncryptionKeys", sensitiveDocId)).bindings, []);
      assert.deepInclude(await call(alice, "createEncryptionKey", sensitiveDocId, request),
        { accepted: true, actionNum: 2 });
      const opened: EncryptedDocOpenResult = await call(bob, "openEncryptedDoc", sensitiveDocId);
      assert.deepInclude(opened.snapshot, { actionNum: 2, keyId: "doc~k1", payload: b64("state2-private") });
      assert.deepEqual(opened.actions, []);
      assert.deepEqual(opened.bindings, [{ scope: "column:salary", colRef: 3, boundAt: 2, releasedAt: null }]);
      // A new document key's snapshot is encrypted with it.
      assert.deepInclude(await call(bob, "createEncryptionKey", sensitiveDocId, {
        scope: DOC_SCOPE, keyId: "doc~k2", baseActionNum: 2,
        wraps: [wrap(ids["charon@getgrist.com"]), wrap(ids["chimpy@getgrist.com"])], snapshot: b64("state3"),
      }), { accepted: true, actionNum: 3 });
      assert.deepInclude((await call(alice, "openEncryptedDoc", sensitiveDocId)).snapshot,
        { actionNum: 3, keyId: "doc~k2", payload: b64("state3") });
    });

    it("undoes key changes that didn't make it into the history", async function() {
      const alice = await connect("chimpy@getgrist.com");
      // As if saving the entry failed after the home database recorded the key.
      const keys = home.dbManager.connection.manager.getRepository(DocEncryptionKey);
      await keys.update({ docId: sensitiveDocId, keyId: "doc~k2" }, { retiredAt: new Date() });
      await keys.insert({ docId: sensitiveDocId, keyId: "doc~lost", scope: DOC_SCOPE, createdBy: null,
        rotateOnNextEdit: false, retiredAt: null, createdAt: new Date(), actionNum: 4 });
      const opened: EncryptedDocOpenResult = await call(alice, "openEncryptedDoc", sensitiveDocId);
      assert.equal(opened.head, 3);
      assert.deepEqual(opened.keys.filter(k => k.current).map(k => k.keyId).sort(), ["column:salary~1", "doc~k2"]);
      assert.notInclude(opened.keys.map(k => k.keyId), "doc~lost");
    });

    it("lets owners restore earlier versions, recorded in the history", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", sensitiveDocId);
      await call(bob, "openEncryptedDoc", sensitiveDocId);
      await call(alice, "pushEncryptedAction", sensitiveDocId, 3, "doc~k2", b64("c4"));
      assert.deepInclude((await nextMessage(bob, "encryptedDocAction"))?.data.action, { actionNum: 4 });
      const snapshots = await call(bob, "listEncryptedSnapshots", sensitiveDocId);
      assert.deepEqual(snapshots.map((s: any) => [s.actionNum, s.keyId, s.userId]),
        [[3, "doc~k2", ids["charon@getgrist.com"]], [2, "doc~k1", ids["chimpy@getgrist.com"]]]);
      assert.deepInclude(await call(bob, "getEncryptedSnapshot", sensitiveDocId, 3), { payload: b64("state3") });
      // Only owners, with the current key, on top of the latest change.
      await assert.isRejected(call(bob, "restoreEncryptedSnapshot", sensitiveDocId, 4, "doc~k2", b64("old")),
        /access/i);
      await assert.isRejected(call(alice, "restoreEncryptedSnapshot", sensitiveDocId, 4, "doc~k1", b64("old")),
        /current document key/);
      assert.deepEqual(await call(alice, "restoreEncryptedSnapshot", sensitiveDocId, 3, "doc~k2", b64("old")),
        { accepted: false, head: 4 });
      assert.deepInclude(await call(alice, "restoreEncryptedSnapshot", sensitiveDocId, 4, "doc~k2", b64("old")),
        { accepted: true, actionNum: 5 });
      assert.deepInclude((await nextMessage(bob, "encryptedDocAction"))?.data.action,
        { actionNum: 5, kind: "restore", keyId: "doc~k2" });
      const opened: EncryptedDocOpenResult = await call(bob, "openEncryptedDoc", sensitiveDocId);
      assert.deepInclude(opened.snapshot, { actionNum: 5, payload: b64("old") });
      // The previous version is still there (as an earlier one).
      assert.deepEqual((await call(bob, "listEncryptedSnapshots", sensitiveDocId)).map((s: any) => s.actionNum),
        [5, 3, 2]);
    });

    it("lets owners lock documents for a while", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", sensitiveDocId);
      await call(bob, "openEncryptedDoc", sensitiveDocId);
      await assert.isRejected(call(bob, "lockEncryptedDoc", sensitiveDocId, "restoring"), /access/i);
      await call(alice, "lockEncryptedDoc", sensitiveDocId, "restoring");
      assert.deepEqual((await nextMessage(bob, "encryptedDocLock"))?.data,
        { docId: sensitiveDocId, lock: { reason: "restoring", userName: "Chimpy" } });
      assert.deepEqual(await call(bob, "getDocLock", sensitiveDocId), { reason: "restoring", userName: "Chimpy" });
      // Others can't change it meanwhile; its owner can.
      await assert.isRejected(call(bob, "pushEncryptedAction", sensitiveDocId, 5, "doc~k2", b64("c6")),
        /being changed by another member/);
      await assert.isRejected(call(alice, "lockEncryptedDoc", sensitiveDocId, "restoring"), /being changed/);
      assert.deepInclude(await call(alice, "pushEncryptedAction", sensitiveDocId, 5, "doc~k2", b64("c6")),
        { accepted: true });
      // Released when its owner is done, or gone.
      await call(alice, "unlockEncryptedDoc", sensitiveDocId);
      assert.deepEqual((await nextMessage(bob, "encryptedDocLock"))?.data, { docId: sensitiveDocId, lock: null });
      const lockExpiryMs = RelayDeps.lockExpiryMs;
      RelayDeps.lockExpiryMs = 300;
      try {
        await call(alice, "lockEncryptedDoc", sensitiveDocId, "restoring");
        assert.deepEqual((await nextMessage(bob, "encryptedDocLock"))?.data.lock,
          { reason: "restoring", userName: "Chimpy" });
        // Kept as long as its owner renews it.
        await new Promise(r => setTimeout(r, 200));
        await call(alice, "renewDocLock", sensitiveDocId);
        await new Promise(r => setTimeout(r, 200));
        assert.isNotNull(await call(bob, "getDocLock", sensitiveDocId));
        await alice.close();
        assert.deepEqual((await nextMessage(bob, "encryptedDocLock"))?.data, { docId: sensitiveDocId, lock: null });
      } finally {
        RelayDeps.lockExpiryMs = lockExpiryMs;
      }
      assert.isNull(await call(bob, "getDocLock", sensitiveDocId));
      assert.deepInclude(await call(bob, "pushEncryptedAction", sensitiveDocId, 6, "doc~k2", b64("c7")),
        { accepted: true });
    });
  });

  describe("new documents set up at once", function() {
    it("sets up keys, private columns and the first snapshot together", async function() {
      const newDocId = await owner.newDoc({ name: "copy", options: { encryption: { version: 1 } } }, wsId);
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      const init = {
        docKey: { keyId: "doc~c", wraps: [wrap(ids["chimpy@getgrist.com"]), wrap(ids["charon@getgrist.com"])] },
        columnKeys: [{ scope: "column:s", keyId: "column:s~1", colRef: 3, wraps: [wrap(ids["chimpy@getgrist.com"])] }],
        snapshot: b64("first"),
      };
      await assert.isRejected(call(bob, "initializeEncryptedDoc", newDocId, init), /access/i);
      await assert.isRejected(call(alice, "initializeEncryptedDoc", newDocId,
        { ...init, columnKeys: [{ ...init.columnKeys[0], colRef: 0 }] }), /Invalid key/);
      await assert.isRejected(call(alice, "initializeEncryptedDoc", newDocId,
        { ...init, docKey: { keyId: "doc~c",
          wraps: [wrap(ids["outsider@getgrist.com"]), wrap(ids["chimpy@getgrist.com"])] } }),
      /only be given to members/);
      // Nothing was kept of refused attempts.
      assert.deepEqual((await call(alice, "openEncryptedDoc", newDocId)).keys, []);
      await call(alice, "initializeEncryptedDoc", newDocId, init);
      const opened: EncryptedDocOpenResult = await call(bob, "openEncryptedDoc", newDocId);
      assert.deepInclude(opened.snapshot, { actionNum: 0, keyId: "doc~c", payload: b64("first") });
      assert.deepEqual(opened.bindings, [{ scope: "column:s", colRef: 3, boundAt: 0, releasedAt: null }]);
      assert.deepEqual(opened.myKeys.map(k => k.keyId), ["doc~c"]);
      await assert.isRejected(call(alice, "initializeEncryptedDoc", newDocId, init), /already initialized/);
      await owner.deleteDoc(newDocId);
    });
  });

  describe("suggestions", function() {
    it("keeps suggestions until members who can edit handle them", async function() {
      const suggestDocId = await owner.newDoc({ name: "suggest", options: { encryption: { version: 1 } } }, wsId);
      const alice = await connect("chimpy@getgrist.com");
      const kiwi = await connect("kiwi@getgrist.com");
      await call(alice, "openEncryptedDoc", suggestDocId);
      await call(alice, "createEncryptionKey", suggestDocId,
        { scope: DOC_SCOPE, keyId: "doc~s", baseActionNum: 0, wraps: [wrap(ids["chimpy@getgrist.com"])] });
      await call(alice, "saveEncryptedSnapshot", suggestDocId, 0, "doc~s", b64("state0"));
      await call(alice, "shareEncryptionKeys", suggestDocId, [wrap(ids["kiwi@getgrist.com"], "doc~s")]);
      await call(kiwi, "openEncryptedDoc", suggestDocId);
      // Viewers suggest only to documents that accept suggestions.
      await assert.isRejected(call(kiwi, "submitEncryptedSuggestion", suggestDocId, "doc~s", b64("s1")),
        /doesn't accept suggestions/);
      await owner.updateDoc(suggestDocId, { options: { proposedChanges: { acceptProposals: true } } });
      home.dbManager.flushDocAuthCache();
      await call(kiwi, "openEncryptedDoc", suggestDocId);
      await assert.isRejected(call(kiwi, "submitEncryptedSuggestion", suggestDocId, "doc~old", b64("s1")),
        /current document key/);
      const id = await call(kiwi, "submitEncryptedSuggestion", suggestDocId, "doc~s", b64("s1"));
      assert.equal((await nextMessage(alice, "encryptedDocSuggestions"))?.data.docId, suggestDocId);
      await call(alice, "submitEncryptedSuggestion", suggestDocId, "doc~s", b64("s2"));
      // Viewers see theirs; members who can edit see all.
      assert.deepEqual((await call(kiwi, "listEncryptedSuggestions", suggestDocId)).map((x: any) => x.payload),
        [b64("s1")]);
      const all = await call(alice, "listEncryptedSuggestions", suggestDocId);
      assert.deepEqual(all.map((x: any) => [x.payload, x.userId]),
        [[b64("s1"), ids["kiwi@getgrist.com"]], [b64("s2"), ids["chimpy@getgrist.com"]]]);
      // Viewers can only withdraw their own.
      await assert.isRejected(call(kiwi, "resolveEncryptedSuggestion", suggestDocId, all[1].id), /handle suggestions/);
      await call(kiwi, "resolveEncryptedSuggestion", suggestDocId, id);
      await call(alice, "resolveEncryptedSuggestion", suggestDocId, all[1].id);
      assert.deepEqual(await call(alice, "listEncryptedSuggestions", suggestDocId), []);
      await owner.deleteDoc(suggestDocId);
    });
  });

  describe("forms", function() {
    it("serves published forms to anyone, and keeps their answers until added", async function() {
      const formDocId = await owner.newDoc({ name: "forms", options: { encryption: { version: 1 } } }, wsId);
      const alice = await connect("chimpy@getgrist.com");
      const kiwi = await connect("kiwi@getgrist.com");
      await call(alice, "openEncryptedDoc", formDocId);
      await call(alice, "createEncryptionKey", formDocId,
        { scope: DOC_SCOPE, keyId: "doc~f", baseActionNum: 0, wraps: [wrap(ids["chimpy@getgrist.com"])] });
      await call(alice, "saveEncryptedSnapshot", formDocId, 0, "doc~f", b64("state0"));
      await call(kiwi, "openEncryptedDoc", formDocId);
      const formId = "a".repeat(32);
      const url = `${home.serverUrl}/o/${ORG}/api/docs/${formDocId}/encrypted-forms/${formId}`;
      // Not published yet.
      assert.equal((await fetch(url)).status, 404);
      // Only members who can edit publish forms.
      await assert.isRejected(call(kiwi, "publishEncryptedForm", formDocId, formId, b64("spec")), /access/i);
      await call(alice, "publishEncryptedForm", formDocId, formId, b64("spec"));
      // Anyone gets it (it's encrypted with the key in the form's link).
      const got = await fetch(url);
      assert.deepEqual(await got.json(), { spec: b64("spec") });
      // Anyone sends answers (encrypted for the document's members).
      const post = (payload: string) => fetch(url, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ payload }),
      });
      assert.equal((await post(b64("answer1"))).status, 200);
      assert.equal((await nextMessage(alice, "encryptedDocInbox"))?.data.docId, formDocId);
      assert.equal((await post(b64("answer2"))).status, 200);
      assert.equal((await post("not base64!")).status, 400);
      // Members who can edit see the answers waiting; others don't.
      await assert.isRejected(call(kiwi, "listEncryptedInbox", formDocId), /access/i);
      const inbox = await call(alice, "listEncryptedInbox", formDocId);
      assert.deepEqual(inbox.map((e: any) => [e.formId, e.payload]),
        [[formId, b64("answer1")], [formId, b64("answer2")]]);
      // They leave the inbox along with the change adding them, or the change is refused.
      assert.deepEqual(await call(alice, "pushEncryptedAction", formDocId, 0, "doc~f", b64("c1"),
        { consumeInbox: [inbox[0].id, 999] }), { accepted: false, head: 0 });
      assert.lengthOf(await call(alice, "listEncryptedInbox", formDocId), 2);
      assert.deepInclude(await call(alice, "pushEncryptedAction", formDocId, 0, "doc~f", b64("c1"),
        { consumeInbox: [inbox[0].id] }), { accepted: true, actionNum: 1 });
      await call(alice, "dropEncryptedInbox", formDocId, [inbox[1].id]);
      // Files attached in answers are sent first, then tied to their answer, and go with it.
      const fileResp = await fetch(`${url}/files`, { method: "POST", body: Buffer.from("encrypted file"),
        headers: { "X-Requested-With": "XMLHttpRequest" } });
      const { fileId } = await fileResp.json();
      assert.match(fileId, /^[0-9a-f]{32}$/);
      // (Not readable until its answer is sent.)
      await assert.isRejected(call(alice, "fetchEncryptedInboxFile", formDocId, fileId, 0, 100), /not found/);
      assert.equal((await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: b64("answer4"), fileIds: ["0".repeat(32)] }) })).status, 400);
      assert.equal((await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: b64("answer4"), fileIds: [fileId] }) })).status, 200);
      await assert.isRejected(call(kiwi, "fetchEncryptedInboxFile", formDocId, fileId, 0, 100), /access/i);
      assert.deepEqual(await call(alice, "fetchEncryptedInboxFile", formDocId, fileId, 0, 100),
        { payload: b64("encrypted file"), size: 14 });
      const [entry] = await call(alice, "listEncryptedInbox", formDocId);
      await call(alice, "dropEncryptedInbox", formDocId, [entry.id]);
      await assert.isRejected(call(alice, "fetchEncryptedInboxFile", formDocId, fileId, 0, 100), /not found/);
      assert.deepEqual(await call(alice, "listEncryptedInbox", formDocId), []);
      // Unpublished forms aren't served anymore.
      await call(alice, "unpublishEncryptedForm", formDocId, formId);
      assert.equal((await fetch(url)).status, 404);
      assert.equal((await post(b64("answer3"))).status, 404);
      // Regular documents have no such forms.
      assert.equal((await fetch(`${home.serverUrl}/o/${ORG}/api/docs/${plainDocId}/encrypted-forms/${formId}`)).status,
        404);
      await owner.deleteDoc(formDocId);
    });
  });

  describe("conversion", function() {
    let regularDocId: string;
    let tables: any;

    before(async function() {
      regularDocId = await owner.newDoc({ name: "to encrypt" }, wsId);
      const docApi = owner.getDocAPI(regularDocId);
      await docApi.addRows("Table1", { A: ["secret one", "secret two"] });
      await docApi.uploadAttachment(new Blob(["attached content"]), "notes.txt");
    });

    it("encrypts regular documents", async function() {
      const alice = await connect("chimpy@getgrist.com");
      let bob = await connect("charon@getgrist.com");
      assert.isUndefined((await bob.send("openDoc", regularDocId)).error);
      await assert.isRejected(call(bob, "beginDocEncryption", regularDocId), /access/i);

      const start = await call(alice, "beginDocEncryption", regularDocId);
      assert.deepEqual(start.attachments.map((a: any) => a.size), [16]);
      assert.sameMembers(start.members.map((m: any) => m.email),
        ["chimpy@getgrist.com", "charon@getgrist.com", "kiwi@getgrist.com"]);
      // Members who had it open got disconnected from it (their browser reconnects), and can't open
      // it meanwhile.
      assert.isNotNull(await nextMessage(bob, "docShutdown"));
      bob = await connect("charon@getgrist.com");
      const locked = await bob.send("openDoc", regularDocId);
      assert.match(locked.error!, /being changed by another member/);
      assert.deepEqual(locked.details?.docLock, { reason: "encrypting", userName: "Chimpy" });
      await assert.isRejected(owner.getDocAPI(regularDocId).getRows("Table1"), /being changed/);
      assert.deepEqual(await call(bob, "getDocLock", regularDocId), { reason: "encrypting", userName: "Chimpy" });
      // Only the member encrypting it gets its content.
      await assert.isRejected(call(bob, "fetchConversionData", regularDocId, 0, 10), /isn't being encrypted/);
      const data = Buffer.from(await call(alice, "fetchConversionData", regularDocId, 0, start.size), "base64");
      tables = unmarshalValue(await gunzip(data)).tables;
      assert.deepEqual(tables.Table1[3].A, ["secret one", "secret two"]);
      const file = await call(alice, "fetchConversionFile", regularDocId, start.attachments[0].rowId, 0, 100);
      assert.deepEqual(file, { payload: b64("attached content"), size: 16 });

      // Its new content goes next to it, until it's complete.
      const { fileId } = await call(alice, "uploadEncryptedFile", regularDocId, b64("encrypted attachment"));
      const path = home.server.getStorageManager().getPath(regularDocId);
      assert.isTrue(await fse.pathExists(path + ".encrypting.tmp"));
      await assert.isRejected(call(alice, "commitDocEncryption", regularDocId, "doc~new",
        [wrap(ids["outsider@getgrist.com"])], b64("snapshot")), /copy for its creator/);
      await call(alice, "commitDocEncryption", regularDocId, "doc~new",
        [wrap(ids["chimpy@getgrist.com"]), wrap(ids["charon@getgrist.com"])], b64("snapshot"));

      // It's an encrypted document now, which members open as such.
      assert.deepEqual((await owner.getDoc(regularDocId)).options?.encryption, { version: 1 });
      assert.include((await bob.send("openDoc", regularDocId)).error, ENCRYPTED_DOC_SERVER_ERROR);
      const opened: EncryptedDocOpenResult = await call(bob, "openEncryptedDoc", regularDocId);
      assert.deepInclude(opened.snapshot, { actionNum: 0, keyId: "doc~new", payload: b64("snapshot") });
      assert.deepEqual(opened.myKeys.map(k => k.keyId), ["doc~new"]);
      assert.deepEqual(await call(bob, "fetchEncryptedFile", regularDocId, fileId),
        { payload: b64("encrypted attachment"), size: 20 });
      // Nothing readable is left in its file.
      assert.isFalse(await fse.pathExists(path + ".encrypting.tmp"));
      assert.isFalse(await fse.pathExists(path + ".encrypting"));
      const db = await SQLiteDB.openDBRaw(path);
      try {
        const names = (await db.all("SELECT name FROM sqlite_master WHERE type = 'table'")).map((r: any) => r.name);
        assert.includeMembers(names, ["_gristsys_EncryptedActions", "_gristsys_EncryptedSnapshots"]);
        assert.deepEqual(names.filter((name: string) => !name.startsWith("_gristsys_Encrypted")), []);
      } finally {
        await db.close();
      }
    });

    it("makes encrypted documents regular ones again", async function() {
      const alice = await connect("chimpy@getgrist.com");
      const bob = await connect("charon@getgrist.com");
      await call(alice, "openEncryptedDoc", regularDocId);
      await call(bob, "openEncryptedDoc", regularDocId);
      // Only owners who can read everything.
      await assert.isRejected(call(bob, "beginDocDecryption", regularDocId), /access/i);
      await call(alice, "beginDocDecryption", regularDocId);
      assert.deepEqual((await nextMessage(bob, "encryptedDocLock"))?.data.lock,
        { reason: "decrypting", userName: "Chimpy" });
      await assert.isRejected(call(bob, "pushEncryptedAction", regularDocId, 0, "doc~new", b64("c1")),
        /being changed by another member/);

      const { fileIdent } = await call(alice, "uploadDecryptedFile", regularDocId, ".txt", b64("attached content"));
      assert.match(fileIdent, /^[0-9a-f]{40}\.txt$/);
      tables._grist_Attachments[3].fileIdent = [fileIdent];
      tables.Table1[3].A = ["secret one", "secret three"];
      const payload = await gzip(marshalValue({ tables }));
      await assert.isRejected(call(alice, "commitDocDecryption", regularDocId, 3, b64String(payload)),
        /changed meanwhile/);
      await call(alice, "commitDocDecryption", regularDocId, 0, b64String(payload));
      assert.deepEqual((await nextMessage(bob, "encryptedDocLock"))?.data,
        { docId: regularDocId, lock: null, decrypted: true });

      // A regular document again, without keys.
      assert.isNull((await owner.getDoc(regularDocId)).options?.encryption ?? null);
      assert.deepEqual((await owner.getDocAPI(regularDocId).getRows("Table1")).A, ["secret one", "secret three"]);
      const resp = await fetch(owner.getDocAPI(regularDocId).getAttachmentDownloadUrl(1),
        { headers: { Authorization: "Bearer api_key_for_chimpy" } });
      assert.equal(await resp.text(), "attached content");
      assert.deepEqual(await home.dbManager.connection.manager.find(DocEncryptionKeyWrap,
        { where: { docId: regularDocId } }), []);
      await assert.isRejected(call(alice, "openEncryptedDoc", regularDocId), /not end-to-end encrypted/);
    });

    it("turns access rules hiding columns into private columns", async function() {
      const rulesDocId = await owner.newDoc({ name: "with rules" }, wsId);
      const docApi = owner.getDocAPI(rulesDocId);
      await docApi.addRows("Table1", { A: ["Ana", "Ben"], B: [52100, 61300] });
      const addRules = (resource: { tableId: string, colIds: string }, rules: { aclFormula: string,
        permissionsText: string }[]) => docApi.applyUserActions([
        ["AddRecord", "_grist_ACLResources", -1, resource],
        ...rules.map((r, i) => ["AddRecord", "_grist_ACLRules", null, { resource: -1, rulePos: i + 1, ...r }]),
      ]);
      // Kiwi can't read B; nobody but owners can edit A.
      await addRules({ tableId: "Table1", colIds: "B" },
        [{ aclFormula: "user.Email == 'kiwi@getgrist.com'", permissionsText: "-R" }]);
      await addRules({ tableId: "Table1", colIds: "A" },
        [{ aclFormula: "user.Access != OWNER", permissionsText: "-U" }]);
      const alice = await connect("chimpy@getgrist.com");
      const start = await call(alice, "beginDocEncryption", rulesDocId);
      assert.lengthOf(start.columnAudiences, 1);
      const colRefB = start.columnAudiences[0].colRef;
      assert.sameMembers(start.columnAudiences[0].userIds, [ids["chimpy@getgrist.com"], ids["charon@getgrist.com"]]);
      assert.equal(start.droppedRules, 1);
      // The column key, for those who can read it, recorded with the document key.
      await call(alice, "commitDocEncryption", rulesDocId, "doc~rules", [wrap(ids["chimpy@getgrist.com"])],
        b64("snapshot"), [{ scope: "column:b", keyId: "column:b~1", colRef: colRefB,
          wraps: [wrap(ids["chimpy@getgrist.com"]), wrap(ids["charon@getgrist.com"])] }]);
      const opened: EncryptedDocOpenResult = await call(alice, "openEncryptedDoc", rulesDocId);
      assert.deepEqual(opened.bindings, [{ scope: "column:b", colRef: colRefB, boundAt: 0, releasedAt: null }]);
      assert.sameMembers(opened.keys.map(k => k.keyId), ["doc~rules", "column:b~1"]);
      await owner.deleteDoc(rulesDocId);
    });

    it("turns access rules hiding whole tables into private tables", async function() {
      const rulesDocId = await owner.newDoc({ name: "with table rules" }, wsId);
      const docApi = owner.getDocAPI(rulesDocId);
      await docApi.applyUserActions([["AddTable", "Salaries", [{ id: "Amount", type: "Numeric", isFormula: false }]]]);
      await docApi.addRows("Salaries", { Amount: [52100] });
      // Kiwi can't see the Salaries table at all.
      await docApi.applyUserActions([
        ["AddRecord", "_grist_ACLResources", -1, { tableId: "Salaries", colIds: "*" }],
        ["AddRecord", "_grist_ACLRules", null, { resource: -1, rulePos: 1,
          aclFormula: "user.Email == 'kiwi@getgrist.com'", permissionsText: "-CRUD" }],
      ]);
      const tables = await docApi.getRecords("_grist_Tables");
      const salariesRef = Number(tables.find(t => t.fields.tableId === "Salaries")!.id);
      const alice = await connect("chimpy@getgrist.com");
      const start = await call(alice, "beginDocEncryption", rulesDocId);
      // One private table (its target is minus its row id), rather than private columns.
      assert.deepEqual(start.columnAudiences.map((a: { colRef: number }) => a.colRef), [-salariesRef]);
      assert.sameMembers(start.columnAudiences[0].userIds, [ids["chimpy@getgrist.com"], ids["charon@getgrist.com"]]);
      await call(alice, "abortDocConversion", rulesDocId);
      await owner.deleteDoc(rulesDocId);
    });

    it("refuses to encrypt documents whose rules depend on their content", async function() {
      const rowsDocId = await owner.newDoc({ name: "row rules" }, wsId);
      const docApi = owner.getDocAPI(rowsDocId);
      await docApi.addRows("Table1", { A: ["mine", "theirs"] });
      await docApi.applyUserActions([
        ["AddRecord", "_grist_ACLResources", -1, { tableId: "Table1", colIds: "*" }],
        ["AddRecord", "_grist_ACLRules", null, { resource: -1, rulePos: 1,
          aclFormula: "user.Email == 'kiwi@getgrist.com' and rec.A == 'mine'", permissionsText: "-R" }],
      ]);
      const alice = await connect("chimpy@getgrist.com");
      await assert.isRejected(call(alice, "beginDocEncryption", rowsDocId), /depend on its content/);
      // Nothing changed: it opens as usual.
      assert.deepEqual((await docApi.getRows("Table1")).A, ["mine", "theirs"]);
      await owner.deleteDoc(rowsDocId);
    });

    it("drops what was prepared when interrupted", async function() {
      const lockExpiryMs = RelayDeps.lockExpiryMs;
      RelayDeps.lockExpiryMs = 1000;
      const alice = await connect("chimpy@getgrist.com");
      const path = home.server.getStorageManager().getPath(regularDocId);
      try {
        await call(alice, "beginDocEncryption", regularDocId);
        assert.isTrue(await fse.pathExists(path + ".encrypting.tmp"));
        // Its author stops (e.g. closes their browser).
        await alice.close();
      } finally {
        RelayDeps.lockExpiryMs = lockExpiryMs;
      }
      // (Dropped once released.)
      await waitFor(async () => !await fse.pathExists(path + ".encrypting.tmp"), 5000);
      // Still a regular document, which opens as usual.
      assert.deepEqual((await owner.getDocAPI(regularDocId).getRows("Table1")).A, ["secret one", "secret three"]);
    });
  });
});

function b64String(bytes: Uint8Array) {
  return Buffer.from(bytes).toString("base64");
}

async function waitFor(check: () => Promise<boolean>, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (!await check()) {
    if (Date.now() > deadline) { throw new Error("Timed out"); }
    await new Promise(r => setTimeout(r, 50));
  }
}
