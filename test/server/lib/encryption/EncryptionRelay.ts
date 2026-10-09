/**
 * Tests the server side of encrypted documents: the doc option, the relay of encrypted changes
 * between browsers, their storage in the document's file, and the management of keys.
 */
import {
  DOC_SCOPE, DocKeyRecord, ENCRYPTED_DOC_SERVER_ERROR, EncryptedDocOpenResult, EncryptionKeysResult,
  EncryptionMember,
} from "app/common/encryption/EncryptionTypes";
import { UserAPI } from "app/common/UserAPI";
import { DocEncryptionKeyWrap } from "app/gen-server/entity/DocEncryption";
import { getEncryptionClientConfig } from "app/server/lib/encryption/encryptionConfig";
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

  before(async function() {
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
      // Bob's change was computed on top of the same state: it's refused.
      assert.deepEqual(await call(bob, "pushEncryptedAction", docId, 0, docKeyId, b64("c1-bob")),
        { accepted: false, head: 1 });
      // So is a change made with a key that isn't the current document key.
      assert.deepEqual(await call(alice, "pushEncryptedAction", docId, 1, "doc~old", b64("c2")),
        { accepted: false, head: 1 });

      for (const client of [bob, kiwi]) {
        const msg = await nextMessage(client, "encryptedDocAction");
        assert.equal(msg?.data.docId, docId);
        assert.deepInclude(msg?.data.action, { actionNum: 1, kind: "change", keyId: docKeyId, payload: b64("c1") });
      }
      assert.isNull(await nextMessage(alice, "encryptedDocAction", 300));

      assert.deepInclude(await call(bob, "pushEncryptedAction", docId, 1, docKeyId, b64("c2")),
        { accepted: true, actionNum: 2 });
      assert.deepInclude((await nextMessage(alice, "encryptedDocAction"))?.data.action, { actionNum: 2 });
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
      // Now Bob can save snapshots.
      await call(bob, "saveEncryptedSnapshot", docId, 2, docKeyId, b64("state2"));
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
      assert.equal(await call(kiwi, "fetchEncryptedFile", docId, fileId), b64("ciphertext of a file"));
      await assert.isRejected(call(kiwi, "uploadEncryptedFile", docId, b64("x")), /No write access/);
      await assert.isRejected(call(kiwi, "fetchEncryptedFile", docId, "0".repeat(32)), /not found/);
    });

    it("prunes changes older than kept snapshots", async function() {
      const alice = await connect("chimpy@getgrist.com");
      await call(alice, "openEncryptedDoc", docId);
      await assert.isRejected(call(alice, "saveEncryptedSnapshot", docId, 9, docKeyId, b64("ahead")), /doesn't match/);
      await call(alice, "saveEncryptedSnapshot", docId, 4, docKeyId, b64("state4"));
      // Snapshots at 2 and 4 are kept: changes up to 2 aren't needed anymore.
      assert.deepEqual((await call(alice, "fetchEncryptedActions", docId, 0)).map((a: any) => a.actionNum), [3, 4]);
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
    });

    it("refuses access to non-members and to regular documents", async function() {
      const outsider = await connect("outsider@getgrist.com");
      await assert.isRejected(call(outsider, "openEncryptedDoc", docId), /No view access/);
      await assert.isRejected(call(outsider, "fetchEncryptedActions", docId, 0), /No view access/);
      const alice = await connect("chimpy@getgrist.com");
      await assert.isRejected(call(alice, "openEncryptedDoc", plainDocId), /not end-to-end encrypted/);
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
});
