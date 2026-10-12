/**
 * Tests the browser-side logic of encrypted documents: several "browsers", each with its own data
 * engine, editing one document through a relay that only ever sees ciphertext. Covers private
 * columns, key replacement, and attachments.
 */
import { TableDataAction } from "app/common/DocActions";
import { makeAccessRuleActions } from "app/common/encryption/AccessRulesFromPrivacy";
import { EncryptionAccessError, isLockedCell, LOCKED_CELL } from "app/common/encryption/ColumnPrivacy";
import {
  decryptFile, EncryptedFileRef, encryptFile, makeFileIdent, parseFileIdent,
} from "app/common/encryption/EncryptedAttachments";
import {
  decryptFormFile, decryptFormSpec, EncryptedFormKeys, encryptFormAnswer, encryptFormFile, encryptFormSpec,
  generateFormKeys,
} from "app/common/encryption/EncryptedForms";
import {
  decryptBundle, decryptSnapshot, DocChangeBundle, encryptBundle,
} from "app/common/encryption/EncryptedPayloads";
import { base64ToBytes, bytesToBase64, MockKeyVault } from "app/common/encryption/EncryptionCrypto";
import {
  DOC_SCOPE, EncryptedActionRecord, makeColumnScope, makeKeyId, tableTarget,
} from "app/common/encryption/EncryptionTypes";
import { buildFormSpec, FormAnswerHelpers, readFormAnswers } from "app/common/encryption/FormSpecs";
import { fromKeyRecord, Keyring, MissingKeyError } from "app/common/encryption/Keyring";
import { InvalidChange, LocalActiveDoc, LocalDocUserAction } from "app/common/encryption/LocalActiveDoc";
import { addParsedTables, parseFileLocally } from "app/common/encryption/LocalImport";
import { User } from "app/common/User";
import { createNodePyodideEngine } from "app/server/lib/encryption/NodePyodideEngine";
import { MemoryMember, MemoryRelay, RelayClient } from "test/server/lib/encryption/MemoryRelay";

import { assert } from "chai";
import * as sinon from "sinon";

describe("encryption/LocalActiveDoc", function() {
  this.timeout(120000);

  const vault = new MockKeyVault();
  const vaultIdFor = (m: { userId: number }) => `user-${m.userId}`;
  const recipient = (m: MemoryMember) => ({ vaultUserId: vaultIdFor(m), email: m.email, name: m.name });

  const alice: MemoryMember = { userId: 1, email: "alice@example.com", name: "Alice", access: "owners" };
  const bob: MemoryMember = { userId: 2, email: "bob@example.com", name: "Bob", access: "editors" };
  const carol: MemoryMember = { userId: 3, email: "carol@example.com", name: "Carol", access: "editors" };
  const dave: MemoryMember = { userId: 4, email: "dave@example.com", name: "Dave", access: "viewers" };

  interface Participant {
    member: MemoryMember;
    doc: LocalActiveDoc;
    client: RelayClient;
    received: LocalDocUserAction[];
    skipped: InvalidChange[];
    rotationFailures: Error[];
  }

  async function join(relay: MemoryRelay, member: MemoryMember, options: {
    create?: boolean, snapshotEvery?: number, canSuggest?: boolean,
  } = {}): Promise<Participant> {
    const client = relay.connect(member.userId);
    const received: LocalDocUserAction[] = [];
    const skipped: InvalidChange[] = [];
    const rotationFailures: Error[] = [];
    const keyring = new Keyring(vault, () => client.getKeys(), relay.getKeys(member.userId));
    const doc = await LocalActiveDoc.open({
      engine: await createNodePyodideEngine(),
      relay: client,
      keyring,
      engineUser: new User({ Name: member.name, Email: member.email, Access: member.access, UserID: member.userId })
        .toJSON(),
      userName: member.email,
      canEdit: member.access !== "viewers",
      canSuggest: options.canSuggest,
      onDocUserAction: action => received.push(action),
      onInvalidChange: change => skipped.push(change),
      onRotationFailed: e => rotationFailures.push(e),
      vaultIdFor,
      snapshotEvery: options.snapshotEvery,
      // (Set DEBUG_ENCRYPTION to see what each browser does.)
      log: process.env.DEBUG_ENCRYPTION ? (...args) => console.log(`[${member.name}]`, ...args) : undefined,
      newDocSettings: options.create ? { timezone: "Europe/Paris", locale: "fr-FR" } : undefined,
    }, relay.open(member.userId));
    client.doc = doc;
    return { member, doc, client, received, skipped, rotationFailures };
  }

  function leave(relay: MemoryRelay, p: Participant) {
    relay.disconnect(p.client);
    p.doc.close();
  }

  /** Sets up a new document: its first key, for its owner. */
  async function newRelay(...others: MemoryMember[]) {
    const relay = new MemoryRelay();
    for (const m of [alice, ...others]) { relay.addMember(m); }
    const wrap = (await vault.createDocumentKey([recipient(alice)])).get(vaultIdFor(alice))!;
    relay.createKey(relay.connect(alice.userId), {
      scope: DOC_SCOPE, keyId: makeKeyId(DOC_SCOPE), baseActionNum: 0,
      wraps: [{ userId: alice.userId, wrappedKey: bytesToBase64(wrap.wrappedKey), keyVersion: 1 }],
    });
    return relay;
  }

  /** Gives members all the keys of a scope (as an owner holding them would). */
  async function giveKeys(relay: MemoryRelay, scope: string, ...members: MemoryMember[]) {
    for (const key of relay.keys.filter(k => k.scope === scope)) {
      const holderWrap = relay.wraps.find(w => w.keyId === key.keyId)!;
      const wraps = await vault.shareDocumentKey(fromKeyRecord(holderWrap), members.map(recipient));
      relay.share(members.map(m => ({
        keyId: key.keyId, userId: m.userId, keyVersion: 1,
        wrappedKey: bytesToBase64(wraps.get(vaultIdFor(m))!.wrappedKey),
      })));
    }
  }

  /** A copy of each of the given keys, as someone holding them could get. */
  function anyWraps(relay: MemoryRelay, keyIds: string[]) {
    return keyIds.map(keyId => ({ ...relay.wraps.find(w => w.keyId === keyId)!, userId: 99 }));
  }

  async function tableValues(p: Participant, tableId: string): Promise<TableDataAction> {
    return (await p.doc.fetchTable(tableId)).tableData;
  }

  /** Everything the server has, decrypted with only the document keys (as any member could). */
  async function readableWithDocKey(relay: MemoryRelay): Promise<string> {
    const keyring = new Keyring(vault, async () => ({ keys: relay.keys, myKeys: [], bindings: relay.bindings }), {
      keys: relay.keys,
      bindings: relay.bindings,
      myKeys: anyWraps(relay, relay.keys.filter(k => k.scope === DOC_SCOPE).map(k => k.keyId)),
    });
    const parts: unknown[] = [];
    for (const record of relay.actions.filter(a => a.kind === "change")) {
      parts.push(await decryptBundle(keyring, record.keyId, base64ToBytes(record.payload)));
    }
    for (const snapshot of relay.snapshots) {
      parts.push(await decryptSnapshot(keyring, snapshot.keyId, base64ToBytes(snapshot.payload)));
    }
    return JSON.stringify(parts);
  }

  /**
   * Pushes a change as a member could with a modified client, skipping their browser's checks:
   * any doc actions, encrypted with the document key.
   */
  async function pushTampered(relay: MemoryRelay, p: Participant, stored: any[]) {
    const bundle: DocChangeBundle = {
      v: 1, userActions: [["Calculate"]], stored, undo: [], retValues: [null],
      info: { time: Date.now(), user: "someone-else@example.com", inst: "encrypted", otherId: 0, linkId: 0 },
    };
    const keyId = relay.currentKey(DOC_SCOPE)!.keyId;
    return relay.pushRaw(p.member.userId, keyId, bytesToBase64(await encryptBundle(p.doc.keyring, keyId, bundle)));
  }

  function allPayloads(relay: MemoryRelay) {
    return [...relay.actions, ...relay.snapshots].map(r => Buffer.from(r.payload, "base64").toString("latin1"))
      .join("\n");
  }

  describe("collaboration", function() {
    let relay: MemoryRelay;
    let a: Participant;
    let b: Participant;

    before(async function() {
      relay = await newRelay(bob, dave);
      a = await join(relay, alice, { create: true, snapshotEvery: 5 });
      await giveKeys(relay, DOC_SCOPE, bob, dave);
      b = await join(relay, bob, { snapshotEvery: 5 });
    });

    after(function() {
      leave(relay, a);
      leave(relay, b);
    });

    it("creates a new document like a regular one", async function() {
      assert.lengthOf(relay.snapshots, 1);
      assert.equal(relay.snapshots[0].actionNum, 0);
      assert.equal(relay.head, 0);
      const meta = await b.doc.fetchMetaTables();
      assert.deepEqual(meta._grist_Tables[3].tableId, ["Table1"]);
      const docInfo = meta._grist_DocInfo[3];
      assert.equal(docInfo.timezone[0], "Europe/Paris");
      assert.deepEqual(JSON.parse(docInfo.documentSettings[0] as string), { locale: "fr-FR", engine: "python3" });
    });

    it("shares changes between browsers", async function() {
      const res = await a.doc.applyUserActions([
        ["AddTable", "Participants", [
          { id: "FirstName", type: "Text", isFormula: false },
          { id: "Age", type: "Int", isFormula: false },
          { id: "Greeting", type: "Text", isFormula: true, formula: "'Bonjour ' + $FirstName" },
        ]],
        ["BulkAddRecord", "Participants", [null, null], { FirstName: ["Zoé", "Marc"], Age: [31, 45] }],
      ]);
      assert.equal(res.actionNum, 1);
      assert.match(res.actionHash!, /^[0-9a-f]{64}$/);
      assert.deepEqual(res.retValues[1], [1, 2]);
      assert.lengthOf(a.received, 1);
      assert.isTrue(a.received[0].fromSelf);
      assert.equal(a.received[0].actionGroup.user, "alice@example.com");

      await b.doc.sync();
      assert.lengthOf(b.received, 1);
      assert.isFalse(b.received[0].fromSelf);
      assert.equal(b.received[0].actionGroup.actionHash, res.actionHash);
      const table = await tableValues(b, "Participants");
      assert.deepEqual(table[3].Greeting, ["Bonjour Zoé", "Bonjour Marc"]);
      assert.deepEqual(table, await tableValues(a, "Participants"));
    });

    it("only ever sends ciphertext to the server", async function() {
      const everything = allPayloads(relay);
      for (const plaintext of ["Participants", "FirstName", "Zoé", "Marc", "Bonjour", "Table1", "alice@example.com"]) {
        assert.notInclude(everything, plaintext);
      }
    });

    it("reconciles changes made at the same time", async function() {
      relay.holdBroadcasts = true;
      const aliceRes = await a.doc.applyUserActions([["UpdateRecord", "Participants", 1, { Age: 32 }]]);
      const bobRes = await b.doc.applyUserActions([
        ["AddRecord", "Participants", null, { FirstName: "Inès", Age: 27 }],
      ]);
      await relay.releaseBroadcasts();
      await a.doc.sync();
      await b.doc.sync();
      assert.isAtLeast(relay.pushes.refused, 1);
      assert.equal(aliceRes.actionNum, 2);
      assert.equal(bobRes.actionNum, 3);
      assert.deepEqual(bobRes.retValues, [3]);
      const table = await tableValues(a, "Participants");
      assert.deepEqual(table[3].FirstName, ["Zoé", "Marc", "Inès"]);
      assert.deepEqual(table[3].Age, [32, 45, 27]);
      assert.deepEqual(await tableValues(b, "Participants"), table);
      assert.deepEqual(b.received.map(r => [r.actionGroup.actionNum, r.fromSelf]),
        [[1, false], [2, false], [3, true]]);
    });

    it("keeps formulas with random or time-dependent results identical everywhere", async function() {
      await a.doc.applyUserActions([
        ["AddColumn", "Participants", "Ticket",
          { type: "Any", isFormula: true, formula: "RANDBETWEEN(1, 1000000000)" }],
        ["AddColumn", "Participants", "Registered", {
          type: "DateTime:Europe/Paris", isFormula: false, formula: "NOW()", recalcWhen: 2,
        }],
        ["AddRecord", "Participants", null, { FirstName: "Léa", Age: 22 }],
      ]);
      await b.doc.sync();
      const aliceTable = await tableValues(a, "Participants");
      assert.isTrue(aliceTable[3].Ticket.every(v => typeof v === "number"));
      assert.equal(new Set(aliceTable[3].Ticket).size, 4);
      assert.isNumber(aliceTable[3].Registered[3]);
      assert.deepEqual(await tableValues(b, "Participants"), aliceTable);
    });

    it("undoes changes for everyone", async function() {
      const res = await b.doc.applyUserActions([["RemoveRecord", "Participants", 2]]);
      await a.doc.sync();
      assert.deepEqual((await tableValues(a, "Participants"))[2], [1, 3, 4]);
      const undone = await b.doc.applyUserActionsById([res.actionNum], [res.actionHash!], true);
      assert.isTrue(undone.isModification);
      await a.doc.sync();
      const table = await tableValues(a, "Participants");
      assert.deepEqual(table[2], [1, 2, 3, 4]);
      assert.deepEqual(await tableValues(b, "Participants"), table);
      assert.isTrue(a.received[a.received.length - 1].actionGroup.isUndo);
    });

    it("lets a newcomer load from the latest snapshot", async function() {
      await a.doc.sync();
      assert.isAbove(relay.snapshots.length, 1);
      assert.isAbove(relay.snapshots[relay.snapshots.length - 1].actionNum, 0);
      const d = await join(relay, dave);
      assert.equal(d.doc.head, relay.head);
      assert.deepEqual(await tableValues(d, "Participants"), await tableValues(a, "Participants"));
      assert.lengthOf(d.received, 0);
      await assert.isRejected(d.doc.applyUserActions([["AddRecord", "Participants", null, {}]]), /No write access/);
      await a.doc.applyUserActions([["UpdateRecord", "Participants", 1, { FirstName: "Zoe" }]]);
      await d.doc.sync();
      assert.equal((await tableValues(d, "Participants"))[3].FirstName[0], "Zoe");
      leave(relay, d);
    });

    it("keeps random values when loading a snapshot followed by changes", async function() {
      // A snapshot now, then a change after it: newcomers load the snapshot, then apply the change.
      await a.doc.saveSnapshot();
      await a.doc.applyUserActions([["AddRecord", "Participants", null, { FirstName: "Eva", Age: 30 }]]);
      assert.equal(relay.snapshots[relay.snapshots.length - 1].actionNum, relay.head - 1);
      const d = await join(relay, dave);
      assert.deepEqual(await tableValues(d, "Participants"), await tableValues(a, "Participants"));
      leave(relay, d);
      await a.doc.applyUserActions([["RemoveRecord", "Participants", 5]]);
    });

    it("does not share anything when a change changes nothing", async function() {
      const head = relay.head;
      const res = await a.doc.applyUserActions([["UpdateRecord", "Participants", 1, { FirstName: "Zoe" }]]);
      assert.isFalse(res.isModification);
      assert.equal(relay.head, head);
      await a.doc.updateCurrentTime();
      assert.equal(relay.head, head);
    });

    it("imports files, parsed in the browser", async function() {
      const engine = await createNodePyodideEngine();
      const csv = new TextEncoder().encode("Name,Joined,Score\nZoé,2024-03-01,12\nMarc,2023-11-20,9\n");
      const parsed = await parseFileLocally(engine, "Members list.csv", csv);
      const tableIds = await addParsedTables(parsed, "Members list.csv", a.doc.docData,
        actions => a.doc.applyUserActions(actions));
      assert.deepEqual(tableIds, ["Members_list"]);
      await b.doc.sync();
      const table = await tableValues(b, "Members_list");
      assert.deepEqual(table[3].Name, ["Zoé", "Marc"]);
      // (Numbers as the document's locale, French here, writes them.)
      assert.deepEqual(table[3].Score, [12, 9]);
      assert.isNumber(table[3].Joined[0]);
      const cols = await tableValues(b, "_grist_Tables_column");
      assert.equal(cols[3].type[cols[3].colId.indexOf("Score")], "Numeric");
      assert.notInclude(allPayloads(relay), "Zoé");
    });

    it("reports engine errors without breaking the document", async function() {
      const head = relay.head;
      await assert.isRejected(a.doc.applyUserActions([["AddRecord", "NoSuchTable", null, {}]]), /KeyError/);
      assert.equal(relay.head, head);
      await a.doc.applyUserActions([["AddRecord", "Participants", null, { FirstName: "Noé" }]]);
      await b.doc.sync();
      assert.deepEqual(await tableValues(b, "Participants"), await tableValues(a, "Participants"));
    });
  });

  describe("ordering", function() {
    let relay: MemoryRelay;
    let ps: Participant[];

    beforeEach(async function() {
      relay = await newRelay(bob, carol);
      const a = await join(relay, alice, { create: true, snapshotEvery: 7 });
      await giveKeys(relay, DOC_SCOPE, bob, carol);
      ps = [a, await join(relay, bob, { snapshotEvery: 7 }), await join(relay, carol, { snapshotEvery: 7 })];
      await a.doc.applyUserActions([
        ["AddTable", "Log", [
          { id: "Who", type: "Text", isFormula: false },
          { id: "N", type: "Int", isFormula: false },
          { id: "Rand", type: "Any", isFormula: true, formula: "RANDBETWEEN(1, 1000000000) if $N else 0" },
        ]],
      ]);
      for (const p of ps) { await p.doc.sync(); }
    });

    afterEach(function() {
      for (const p of ps) { leave(relay, p); }
    });

    async function assertSameEverywhere() {
      const tables = await Promise.all(ps.map(p => tableValues(p, "Log")));
      for (const table of tables.slice(1)) { assert.deepEqual(table, tables[0]); }
      return tables[0];
    }

    it("orders concurrent changes from several browsers the same way everywhere", async function() {
      relay.holdBroadcasts = true;
      // Each browser makes several changes at once, while others' changes are in flight.
      await Promise.all(ps.map(async (p) => {
        for (let i = 1; i <= 5; i++) {
          await p.doc.applyUserActions([["AddRecord", "Log", null, { Who: p.member.name, N: i }]]);
          if (i === 3) { await relay.releaseBroadcasts(); relay.holdBroadcasts = true; }
        }
      }));
      await relay.releaseBroadcasts();
      for (const p of ps) { await p.doc.sync(); }
      assert.isAbove(relay.pushes.refused, 0);
      // The history is linear, without gaps, and each change is in it once.
      const changes = relay.actions.filter(a => a.kind === "change");
      assert.deepEqual(changes.map(a => a.actionNum), changes.map((_, i) => changes[0].actionNum + i));
      const table = await assertSameEverywhere();
      assert.lengthOf(table[2], 15);
      for (const name of ["Alice", "Bob", "Carol"]) {
        // Each browser's own changes are in the order it made them.
        const mine = table[2].map((_, i) => i).filter(i => table[3].Who[i] === name).map(i => table[3].N[i]);
        assert.deepEqual(mine, [1, 2, 3, 4, 5]);
      }
      // Each browser saw every change, once, in order.
      for (const p of ps) {
        const nums = p.received.map(r => r.actionGroup.actionNum).filter(n => n > changes[0].actionNum - 1);
        assert.deepEqual(nums, changes.map(a => a.actionNum));
      }
    });

    it("fetches changes it missed, when they arrive out of order", async function() {
      const [a, b] = ps;
      relay.holdBroadcasts = true;
      await a.doc.applyUserActions([["AddRecord", "Log", null, { Who: "first", N: 1 }]]);
      await a.doc.applyUserActions([["AddRecord", "Log", null, { Who: "second", N: 2 }]]);
      // Bob gets the second change first: he fetches the one he missed, and applies both in order.
      const [first, second] = relay.actions.slice(-2);
      await b.doc.receiveAction(second);
      assert.equal(b.doc.head, second.actionNum);
      await b.doc.receiveAction(first);   // (Already applied: ignored.)
      assert.deepEqual((await tableValues(b, "Log"))[3].Who, ["first", "second"]);
      relay.holdBroadcasts = false;
      for (const p of ps) { await p.doc.sync(); }
      await assertSameEverywhere();
    });

    it("applies a change once when the server's answer to it got lost", async function() {
      const [a, b] = ps;
      const realPush = a.client.pushAction.bind(a.client);
      a.client.pushAction = async (...args) => {
        await realPush(...args);
        throw new Error("Connection lost");
      };
      try {
        await assert.isRejected(a.doc.applyUserActions([["AddRecord", "Log", null, { Who: "once", N: 1 }]]),
          /Connection lost/);
      } finally {
        a.client.pushAction = realPush;
      }
      // The change got through: Alice gets it back from the server, like everyone else.
      await b.doc.sync();
      const table = await assertSameEverywhere();
      assert.deepEqual(table[3].Who, ["once"]);
    });

    it("rejects changes that aren't shaped as changes, everywhere alike", async function() {
      const [a, b, c] = ps;
      const keyId = relay.currentKey(DOC_SCOPE)!.keyId;
      const malformed = { v: 1, userActions: [["Calculate"]], stored: [["AddRecord", "Log", 1, { Who: "x" }]] } as any;
      const record = relay.pushRaw(carol.userId, keyId,
        bytesToBase64(await encryptBundle(c.doc.keyring, keyId, malformed)));
      for (const p of [a, b, c]) {
        await p.doc.sync();
        assert.deepInclude(p.skipped[p.skipped.length - 1], { actionNum: record.actionNum, skipped: true });
        assert.match(p.skipped[p.skipped.length - 1].reason, /Malformed/);
      }
      await assertSameEverywhere();
    });

    it("keeps the current time up to date once for all", async function() {
      const [a, b] = ps;
      await a.doc.applyUserActions([["AddColumn", "Log", "Now", { type: "Any", isFormula: true, formula: "NOW()" }],
        ["AddRecord", "Log", null, { Who: "t", N: 1 }]]);
      await b.doc.sync();
      // As if an hour had passed for everyone.
      for (const p of ps) { (p.doc as any)._lastTimeUpdateMs = 0; }
      const head = relay.head;
      await a.doc.updateCurrentTime();
      assert.equal(relay.head, head + 1);
      // Others, getting the update, don't make their own.
      await b.doc.sync();
      await b.doc.updateCurrentTime();
      assert.equal(relay.head, head + 1);
      await assertSameEverywhere();
    });
  });

  describe("replacing the document key while members edit", function() {
    let relay: MemoryRelay;
    let a: Participant;
    let b: Participant;
    let c: Participant;

    beforeEach(async function() {
      relay = await newRelay(bob, carol);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, bob, carol);
      b = await join(relay, bob);
      c = await join(relay, carol);
      await a.doc.applyUserActions([
        ["AddTable", "Notes", [{ id: "Text", type: "Text", isFormula: false }]],
        ["AddRecord", "Notes", null, { Text: "start" }],
      ]);
      for (const p of [b, c]) { await p.doc.sync(); }
    });

    afterEach(function() {
      for (const p of [a, b, c]) { leave(relay, p); }
    });

    /**
     * Removes Carol from the document, as the server does when she loses access: her keys are
     * taken away (and flagged for replacement), and changes are no longer forwarded to her.
     */
    function removeCarol() {
      relay.revoke([carol.userId]);
      relay.members = relay.members.filter(m => m.userId !== carol.userId);
      relay.disconnect(c.client);
    }

    it("refuses changes made with the replaced key, and redoes them with the new one", async function() {
      const oldKeyId = relay.currentKey(DOC_SCOPE)!.keyId;
      removeCarol();
      relay.holdBroadcasts = true;
      // Alice's next edit replaces the key, while Bob, who hasn't heard of it yet, edits too.
      await a.doc.refreshKeys();
      await a.doc.applyUserActions([["AddRecord", "Notes", null, { Text: "from Alice" }]]);
      const newKeyId = relay.currentKey(DOC_SCOPE)!.keyId;
      assert.notEqual(newKeyId, oldKeyId);
      const keyNum = relay.keys.find(k => k.keyId === newKeyId)!.actionNum;
      await b.doc.applyUserActions([["AddRecord", "Notes", null, { Text: "from Bob" }]]);
      await relay.releaseBroadcasts();
      await b.doc.sync();
      await a.doc.sync();

      // Bob's first attempt, with the old key, was refused, and never reached anyone.
      const bobPushes = relay.pushLog.filter(l => l.userId === bob.userId);
      assert.deepInclude(bobPushes, { userId: bob.userId, baseActionNum: keyNum - 1, keyId: oldKeyId,
        outcome: "refused" });
      assert.isTrue(relay.actions.filter(r => r.actionNum > keyNum).every(r => r.keyId === newKeyId));
      // His change was made again on top of the key change, with the new key, once.
      const accepted = bobPushes.filter(l => l.outcome === "accepted");
      assert.lengthOf(accepted, 1);
      assert.equal(accepted[0].keyId, newKeyId);
      assert.deepEqual((await tableValues(a, "Notes"))[3].Text, ["start", "from Alice", "from Bob"]);
      assert.deepEqual(await tableValues(b, "Notes"), await tableValues(a, "Notes"));
      assert.lengthOf(b.received.filter(r => r.fromSelf), 1);
    });

    it("keeps a member who lost the key from sharing changes, without retrying", async function() {
      removeCarol();
      // Carol, unaware, edits before the key is replaced: the server refuses it, as she no longer
      // holds the key, and her browser gives up (and undoes it locally).
      await assert.isRejected(c.doc.applyUserActions([["UpdateRecord", "Notes", 1, { Text: "carol was here" }]]),
        /holding the document key/);
      assert.deepEqual(relay.pushLog.filter(l => l.userId === carol.userId).map(l => l.outcome), ["denied"]);
      assert.deepEqual((await tableValues(c, "Notes"))[3].Text, ["start"]);

      // Once the key is replaced, her attempts (with the old key) are refused, and she can't
      // follow nor make them again with the new key she doesn't have.
      await a.doc.refreshKeys();
      await a.doc.applyUserActions([["AddRecord", "Notes", null, { Text: "after" }]]);
      const head = relay.head;
      await assert.isRejected(c.doc.applyUserActions([["UpdateRecord", "Notes", 1, { Text: "again" }]]),
        MissingKeyError);
      // (Whether the server refused it or her browser couldn't even encrypt it, nothing got
      // through, and she didn't keep trying.)
      const outcomes = relay.pushLog.filter(l => l.userId === carol.userId).map(l => l.outcome);
      assert.notInclude(outcomes, "accepted");
      assert.isAtMost(outcomes.length, 2);
      assert.equal(relay.head, head);
      assert.deepEqual((await tableValues(c, "Notes"))[3].Text, ["start"]);
      assert.notInclude(JSON.stringify(await readableWithDocKey(relay)), "carol was here");
      await b.doc.sync();
      assert.deepEqual((await tableValues(b, "Notes"))[3].Text, ["start", "after"]);
    });
    it("keeps editing when keys can't be replaced, and replaces them on a later edit", async function() {
      const oldKeyId = relay.currentKey(DOC_SCOPE)!.keyId;
      removeCarol();
      await a.doc.refreshKeys();
      // The encryption service fails once: the edit still goes through, with the current key.
      const createDocumentKey = sinon.stub(vault, "createDocumentKey").rejects(new Error("vault unavailable"));
      try {
        await a.doc.applyUserActions([["AddRecord", "Notes", null, { Text: "meanwhile" }]]);
      } finally {
        createDocumentKey.restore();
      }
      assert.lengthOf(a.rotationFailures, 1);
      assert.equal(relay.currentKey(DOC_SCOPE)!.keyId, oldKeyId);
      assert.isTrue(relay.currentKey(DOC_SCOPE)!.rotateOnNextEdit);
      await b.doc.sync();
      assert.deepEqual((await tableValues(b, "Notes"))[3].Text, ["start", "meanwhile"]);

      // The next edit replaces it.
      await a.doc.applyUserActions([["AddRecord", "Notes", null, { Text: "after" }]]);
      const newKeyId = relay.currentKey(DOC_SCOPE)!.keyId;
      assert.notEqual(newKeyId, oldKeyId);
      assert.sameMembers(relay.wraps.filter(w => w.keyId === newKeyId).map(w => w.userId), [alice.userId, bob.userId]);
      await b.doc.sync();
      assert.deepEqual((await tableValues(b, "Notes"))[3].Text, ["start", "meanwhile", "after"]);
    });
  });

  describe("private columns", function() {
    let relay: MemoryRelay;
    let a: Participant;   // Owner: can read everything.
    let b: Participant;   // Can read the private column.
    let c: Participant;   // Can't.
    let scope: string;
    let salaryRef: number;
    let bobSalaryChange: EncryptedActionRecord;

    before(async function() {
      relay = await newRelay(bob, carol);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, bob, carol);
      await a.doc.applyUserActions([
        ["AddTable", "Staff", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false },
          { id: "Bonus", type: "Numeric", isFormula: false },
          { id: "Total", type: "Numeric", isFormula: true, formula: "$Salary + $Bonus" },
          { id: "Initial", type: "Text", isFormula: true, formula: "$Name[:1]" },
        ]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300], Bonus: [700, 900] }],
      ]);
      // Make Salary private, readable by Alice and Bob.
      scope = makeColumnScope();
      const cols = await tableValues(a, "_grist_Tables_column");
      salaryRef = cols[2][cols[3].colId.indexOf("Salary")];
      await a.doc.createScopeKey(scope, [alice, bob].map(m => ({ ...m, vaultUserId: vaultIdFor(m) })), salaryRef);
      // Drop what the server had before the column was private.
      await a.doc.saveSnapshot({ compact: true });
      b = await join(relay, bob);
      c = await join(relay, carol);
    });

    after(function() {
      for (const p of [a, b, c]) { leave(relay, p); }
    });

    it("makes formulas reading private columns private too", function() {
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Salary"), [scope]);
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Total"), [scope]);
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Initial"), []);
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Bonus"), []);
    });

    it("shows private values only to members holding their key", async function() {
      const expected = { Name: ["Ana", "Ben"], Salary: [52100, 61300], Bonus: [700, 900], Total: [52800, 62200] };
      for (const p of [a, b]) {
        assert.deepInclude((await tableValues(p, "Staff"))[3], expected);
      }
      assert.deepInclude((await tableValues(c, "Staff"))[3], {
        Name: ["Ana", "Ben"], Salary: [LOCKED_CELL, LOCKED_CELL], Bonus: [700, 900], Total: [LOCKED_CELL, LOCKED_CELL],
        Initial: ["A", "B"],
      });
    });

    it("never shares private values with the document key alone", async function() {
      const readable = await readableWithDocKey(relay);
      assert.include(readable, "Ana");
      for (const secret of ["52100", "61300", "52800", "62200"]) {
        assert.notInclude(readable, secret);
      }
    });

    it("lets members without the key edit what doesn't affect private values", async function() {
      await c.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Name: "Anna" }]]);
      for (const p of [a, b]) {
        await p.doc.sync();
        assert.deepInclude((await tableValues(p, "Staff"))[3], { Name: ["Anna", "Ben"], Initial: ["A", "B"] });
      }
    });

    it("refuses changes that would require reading private values", async function() {
      const head = relay.head;
      // Such changes are refused with an EncryptionAccessError.
      const err = await c.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Bonus: 1000 }]]).catch(e => e);
      assert.instanceOf(err, EncryptionAccessError);
      assert.equal(err.code, "ENCRYPTION_ACCESS_DENIED");
      await assert.isRejected(c.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Bonus: 1000 }]]),
        /used by a calculation you don't have access to/);
      await assert.isRejected(c.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Salary: 1 }]]),
        /private column/);
      await assert.isRejected(c.doc.applyUserActions([["AddRecord", "Staff", null, { Name: "Cid" }]]),
        /Rows of this table/);
      await assert.isRejected(c.doc.applyUserActions([
        ["AddColumn", "Staff", "Double", { type: "Any", isFormula: true, formula: "$Salary * 2" }],
      ]), /in formulas/);
      await assert.isRejected(c.doc.applyUserActions([["RemoveColumn", "Staff", "Salary"]]),
        /private column/);
      assert.equal(relay.head, head);
      // Nothing changed locally either.
      assert.deepInclude((await tableValues(c, "Staff"))[3], { Bonus: [700, 900], Name: ["Anna", "Ben"] });
    });

    it("updates private formulas for those who can read them", async function() {
      await b.doc.applyUserActions([["UpdateRecord", "Staff", 2, { Salary: 63000, Bonus: 1000 }]]);
      await a.doc.sync();
      await c.doc.sync();
      assert.deepInclude((await tableValues(a, "Staff"))[3], { Salary: [52100, 63000], Total: [52800, 64000] });
      assert.deepInclude((await tableValues(c, "Staff"))[3], {
        Salary: [LOCKED_CELL, LOCKED_CELL], Bonus: [700, 1000], Total: [LOCKED_CELL, LOCKED_CELL],
      });
      assert.notInclude(await readableWithDocKey(relay), "63000");
      bobSalaryChange = relay.actions[relay.actions.length - 1];
    });

    it("keeps formulas from reading private columns without naming them", async function() {
      // A formula reading Salary under a name built at runtime: not detected as private...
      await a.doc.applyUserActions([["AddColumn", "Staff", "Sneaky",
        { type: "Any", isFormula: true, formula: 'Staff.lookupOne(**{"Sal" + "ary": 1}).Name' }]]);
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Sneaky"), []);
      // ... so the engine refuses it, in every browser alike.
      for (const p of [b, c]) { await p.doc.sync(); }
      for (const p of [a, b, c]) {
        assert.deepEqual((await tableValues(p, "Staff"))[3].Sneaky as any,
          [["E", "PermissionError"], ["E", "PermissionError"]]);
        assert.match((await p.doc.getFormulaError("Staff", "Sneaky", 1))[2],
          /reads a private column without naming it/);
      }
      // Same for ways around the engine.
      await a.doc.applyUserActions([
        ["ModifyColumn", "Staff", "Sneaky", { formula: 'getattr($Staff, "Sal" + "ary")' }],
      ]);
      assert.match((await a.doc.getFormulaError("Staff", "Sneaky", 1))[2], /In encrypted documents, 'getattr'/);
      await a.doc.applyUserActions([["RemoveColumn", "Staff", "Sneaky"]]);
      for (const p of [b, c]) { await p.doc.sync(); }
    });

    it("lets members without a key save snapshots, with private values they can't read", async function() {
      // Carol can't read Salary nor Total: her snapshot passes on the sealed values she received.
      await c.doc.saveSnapshot();
      const latest = relay.snapshots[relay.snapshots.length - 1];
      assert.equal(latest.actionNum, relay.head);
      const readable = await readableWithDocKey(relay);
      for (const secret of ["52100", "63000", "52800", "64000"]) { assert.notInclude(readable, secret); }
      // Those who hold the key get the values from it.
      const b2 = await join(relay, bob);
      assert.deepInclude((await tableValues(b2, "Staff"))[3], {
        Name: ["Anna", "Ben"], Salary: [52100, 63000], Total: [52800, 64000],
      });
      leave(relay, b2);
      const c2 = await join(relay, carol);
      assert.deepInclude((await tableValues(c2, "Staff"))[3], { Salary: [LOCKED_CELL, LOCKED_CELL] });
      leave(relay, c2);
    });

    it("skips, in every browser, changes that don't respect private columns", async function() {
      // Carol, who can't read Salary, writes in it anyway (as a modified client could).
      const record = await pushTampered(relay, c, [["UpdateRecord", "Staff", 1, { Salary: 1 }]]);
      for (const p of [a, b, c]) {
        await p.doc.sync();
        assert.equal(p.doc.head, record.actionNum);
        assert.deepInclude(p.skipped[p.skipped.length - 1], { actionNum: record.actionNum, userId: carol.userId });
        assert.match(p.skipped[p.skipped.length - 1].reason, /Unsealed private values/);
      }
      assert.deepInclude((await tableValues(a, "Staff"))[3], { Salary: [52100, 63000] });
      assert.deepInclude((await tableValues(c, "Staff"))[3], { Salary: [LOCKED_CELL, LOCKED_CELL] });
      // Sealed values can't be replayed (here, Bob's earlier change, pushed again): those holding
      // the key see they don't belong there, and lock them, as they are for those who can't check.
      const replayed = relay.pushRaw(carol.userId, bobSalaryChange.keyId, bobSalaryChange.payload);
      for (const p of [a, b, c]) {
        await p.doc.sync();
        assert.equal(p.doc.head, replayed.actionNum);
        assert.deepInclude((await tableValues(p, "Staff"))[3],
          { Salary: [p === c ? LOCKED_CELL : 52100, LOCKED_CELL] });
      }
      for (const p of [a, b]) {
        assert.deepInclude(p.skipped[p.skipped.length - 1], { actionNum: replayed.actionNum, skipped: false });
        assert.match(p.skipped[p.skipped.length - 1].reason, /don't belong/);
      }
      // Members holding the key can set them again.
      await b.doc.applyUserActions([["UpdateRecord", "Staff", 2, { Salary: 63000 }]]);
      for (const p of [a, c]) { await p.doc.sync(); }
      assert.deepInclude((await tableValues(a, "Staff"))[3], { Salary: [52100, 63000], Total: [52800, 64000] });
      // Changes that can't be applied are skipped too, rather than blocking the document.
      const broken = await pushTampered(relay, c, [["AddRecord", "NoSuchTable", 1, {}]]);
      for (const p of [a, b, c]) {
        await p.doc.sync();
        assert.equal(p.skipped[p.skipped.length - 1].actionNum, broken.actionNum);
      }
      // Changes in the document's settings don't change which columns are private.
      await pushTampered(relay, c, [["UpdateRecord", "_grist_Tables_column", salaryRef, { widgetOptions: "{}" }]]);
      for (const p of [a, b, c]) {
        await p.doc.sync();
        assert.deepEqual(p.doc.privacy.scopesOf("Staff", "Salary"), [scope]);
      }
      // And the document goes on.
      await a.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Bonus: 800 }]]);
      for (const p of [b, c]) {
        await p.doc.sync();
        assert.equal((await tableValues(p, "Staff"))[3].Bonus[0], 800);
      }
      // The history shows who made changes as the server knows them.
      assert.equal(b.received[b.received.length - 1].actionGroup.user, "alice@example.com");
    });

    it("only lets owners holding a column's key make it public", async function() {
      await assert.isRejected(b.doc.releaseScope(scope), /Only owners/);
      await assert.isRejected(c.doc.releaseScope(scope), /Only owners/);
    });

    it("replaces a column's key when someone loses access to it", async function() {
      const oldKeyId = relay.currentKey(scope)!.keyId;
      relay.revoke([bob.userId], scope);
      await a.doc.refreshKeys();
      // The next edit replaces the key, for those who still hold it.
      await a.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Salary: 55000 }]]);
      const newKey = relay.currentKey(scope)!;
      assert.notEqual(newKey.keyId, oldKeyId);
      assert.isFalse(newKey.rotateOnNextEdit);
      assert.deepEqual(relay.wraps.filter(w => w.keyId === newKey.keyId).map(w => w.userId), [alice.userId]);
      // Bob doesn't get the new value anymore.
      await b.doc.sync();
      assert.deepInclude((await tableValues(b, "Staff"))[3], {
        Salary: [LOCKED_CELL, 63000], Total: [LOCKED_CELL, 64000],
      });
      assert.deepInclude((await tableValues(a, "Staff"))[3], { Salary: [55000, 63000], Total: [55800, 64000] });
      // The document was saved again with the new key (as of the key change).
      const latest = relay.snapshots[relay.snapshots.length - 1];
      assert.equal(latest.actionNum, relay.keys.find(k => k.keyId === newKey.keyId)!.actionNum);
    });

    it("replaces the document key when someone loses access to the document", async function() {
      const oldKeyId = relay.currentKey(DOC_SCOPE)!.keyId;
      relay.revoke([carol.userId]);
      relay.members = relay.members.filter(m => m.userId !== carol.userId);
      await a.doc.refreshKeys();
      await a.doc.applyUserActions([["UpdateRecord", "Staff", 2, { Name: "Benoît" }]]);
      const newKeyId = relay.currentKey(DOC_SCOPE)!.keyId;
      assert.notEqual(newKeyId, oldKeyId);
      assert.sameMembers(relay.wraps.filter(w => w.keyId === newKeyId).map(w => w.userId), [alice.userId, bob.userId]);
      // Bob follows, Carol can't.
      await b.doc.sync();
      assert.equal((await tableValues(b, "Staff"))[3].Name[1], "Benoît");
      await assert.isRejected(c.doc.sync(), MissingKeyError);
      // Everything on the server since uses the new key, and the latest snapshot too.
      const keyNum = relay.keys.find(k => k.keyId === newKeyId)!.actionNum;
      assert.isTrue(relay.actions.filter(r => r.kind === "change" && r.actionNum > keyNum)
        .every(r => r.keyId === newKeyId));
      assert.equal(relay.snapshots[relay.snapshots.length - 1].keyId, newKeyId);
    });

    it("encrypts attachments with keys of their own", async function() {
      const keyring = a.doc.keyring;
      const data = new TextEncoder().encode("%PDF confidential");
      const shared = await encryptFile(keyring, DOC_SCOPE, data);
      const fileRef = { fileId: "f1", ...shared.ref };
      assert.notInclude(Buffer.from(shared.ciphertext).toString("latin1"), "confidential");
      assert.deepEqual(await decryptFile(b.doc.keyring, fileRef, shared.ciphertext), data);
      // A file in the private column is only readable with its key.
      const secret = await encryptFile(keyring, scope, data);
      const secretRef = { fileId: "f2", ...secret.ref };
      assert.deepEqual(await decryptFile(keyring, secretRef, secret.ciphertext), data);
      await assert.isRejected(decryptFile(b.doc.keyring, secretRef, secret.ciphertext), MissingKeyError);
    });

    it("makes a private column public again, sharing its values", async function() {
      await b.doc.sync();
      // Bob lost access to Salary above.
      assert.deepInclude((await tableValues(b, "Staff"))[3], { Salary: [LOCKED_CELL, 63000] });
      await a.doc.releaseScope(scope);
      await b.doc.sync();
      assert.deepEqual(b.doc.privacy.scopesOf("Staff", "Salary"), []);
      assert.deepEqual(b.doc.privacy.scopesOf("Staff", "Total"), []);
      assert.deepInclude((await tableValues(b, "Staff"))[3], { Salary: [55000, 63000], Total: [55800, 64000] });
      assert.include(await readableWithDocKey(relay), "55000");
      // Anyone can now edit it.
      await b.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Salary: 56000 }]]);
      await a.doc.sync();
      assert.deepInclude((await tableValues(a, "Staff"))[3], { Salary: [56000, 63000], Total: [56800, 64000] });
    });
  });
  describe("private tables", function() {
    let relay: MemoryRelay;
    let a: Participant;   // Owner: can read everything.
    let b: Participant;   // Can read the private table.
    let c: Participant;   // Can't.
    let scope: string;
    let staffRef: number;

    before(async function() {
      relay = await newRelay(bob, carol);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, bob, carol);
      await a.doc.applyUserActions([
        ["AddTable", "Staff", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false },
          { id: "Total", type: "Numeric", isFormula: true, formula: "$Salary + 100" },
        ]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300] }],
        ["AddTable", "Teams", [{ id: "Team", type: "Text", isFormula: false },
          { id: "Count", type: "Any", isFormula: true, formula: "len(Staff.all)" },
          { id: "Names", type: "Any", isFormula: true, formula: "' '.join(Staff.all.Name)" }]],
        ["AddRecord", "Teams", null, { Team: "Core" }],
      ]);
      // Make the whole Staff table private, readable by Alice and Bob.
      scope = makeColumnScope();
      const tables = await tableValues(a, "_grist_Tables");
      staffRef = tables[2][tables[3].tableId.indexOf("Staff")];
      await a.doc.createScopeKey(scope, [alice, bob].map(m => ({ ...m, vaultUserId: vaultIdFor(m) })),
        tableTarget(staffRef), { compact: true });
      b = await join(relay, bob);
      c = await join(relay, carol);
    });

    after(function() {
      for (const p of [a, b, c]) { leave(relay, p); }
    });

    it("makes all the table's columns private, and formulas reading them", function() {
      for (const colId of ["Name", "Salary", "Total", "manualSort"]) {
        assert.deepEqual(a.doc.privacy.scopesOf("Staff", colId), [scope], colId);
      }
      // (Formulas elsewhere naming its columns are private too.)
      assert.deepEqual(a.doc.privacy.scopesOf("Teams", "Names"), [scope]);
      assert.deepEqual(a.doc.privacy.scopesOf("Teams", "Team"), []);
    });

    it("shows its values only to members holding its key", async function() {
      for (const p of [a, b]) {
        assert.deepInclude((await tableValues(p, "Staff"))[3], { Name: ["Ana", "Ben"], Salary: [52100, 61300] });
      }
      const locked = (await tableValues(c, "Staff"))[3];
      assert.deepEqual(locked.Name, [LOCKED_CELL, LOCKED_CELL]);
      assert.deepEqual(locked.Salary, [LOCKED_CELL, LOCKED_CELL]);
      const readable = await readableWithDocKey(relay);
      for (const secret of ["Ana", "Ben", "52100", "61300"]) {
        assert.notInclude(readable, secret);
      }
    });

    it("makes columns added later private too", async function() {
      await a.doc.applyUserActions([
        ["AddColumn", "Staff", "City", { type: "Text", isFormula: false }],
        ["UpdateRecord", "Staff", 1, { City: "Lyon" }],
      ]);
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "City"), [scope]);
      for (const p of [b, c]) { await p.doc.sync(); }
      assert.equal((await tableValues(b, "Staff"))[3].City[0], "Lyon");
      assert.equal((await tableValues(c, "Staff"))[3].City[0], LOCKED_CELL);
      assert.notInclude(await readableWithDocKey(relay), "Lyon");
    });

    it("refuses changes to it from members without its key", async function() {
      await assert.isRejected(c.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Salary: 1 }]]));
      await assert.isRejected(c.doc.applyUserActions([["AddRecord", "Staff", null, { Name: "Eve" }]]));
      await b.doc.applyUserActions([["UpdateRecord", "Staff", 2, { Salary: 62000 }]]);
      await a.doc.sync();
      assert.equal((await tableValues(a, "Staff"))[3].Salary[1], 62000);
    });

    it("needs both keys to read a private column of a private table", async function() {
      // Salary is made private too, to Alice and Carol: Carol doesn't hold the table's key.
      const colScope = makeColumnScope();
      const cols = await tableValues(a, "_grist_Tables_column");
      const salaryRef = cols[2][cols[3].colId.indexOf("Salary")];
      await a.doc.createScopeKey(colScope, [alice, carol].map(m => ({ ...m, vaultUserId: vaultIdFor(m) })), salaryRef,
        { compact: true });
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Salary"), [colScope, scope].sort());
      // (What members had already read stays in documents they have open: they open it again.)
      for (const p of [b, c]) { leave(relay, p); }
      b = await join(relay, bob);
      c = await join(relay, carol);
      assert.equal((await tableValues(a, "Staff"))[3].Salary[0], 52100);
      // Bob holds only the table's key, Carol only the column's: neither can read it.
      assert.equal((await tableValues(b, "Staff"))[3].Salary[0], LOCKED_CELL);
      assert.equal((await tableValues(b, "Staff"))[3].Name[0], "Ana");
      assert.equal((await tableValues(c, "Staff"))[3].Salary[0], LOCKED_CELL);
    });

    it("becomes a table hidden by access rules in a regular document", async function() {
      const plain = await a.doc.exportPlain(makeAccessRuleActions(a.doc.docData, a.doc.privacy, a.doc.keyring,
        relay.listMembers()));
      const resources = plain.tables._grist_ACLResources;
      const rules = plain.tables._grist_ACLRules;
      const ruleFor = (colIds: string) => {
        const resourceRef = resources[2][resources[3].colIds.indexOf(colIds)];
        assert.equal(resources[3].tableId[resources[2].indexOf(resourceRef)], "Staff");
        const index = rules[3].resource.indexOf(resourceRef);
        return { formula: rules[3].aclFormula[index], permissions: rules[3].permissionsText[index] };
      };
      // The whole table (rows included) for those who could read it, and the column private too
      // (with the formula using it) for those who held its key: both rules apply, as both keys did.
      assert.deepEqual(ruleFor("*"), { formula: `user.UserID not in [${alice.userId}, ${bob.userId}]`,
        permissions: "-CRUD" });
      assert.deepEqual(ruleFor("Salary,Total"), { formula: `user.UserID not in [${alice.userId}, ${carol.userId}]`,
        permissions: "-RU" });
    });

    it("keeps the id of a removed private table from being reused", async function() {
      await a.doc.applyUserActions([["RemoveTable", "Staff"]]);
      await a.doc.applyUserActions([["AddTable", "Other", [{ id: "X", type: "Text", isFormula: false }]]]);
      const tables = await tableValues(a, "_grist_Tables");
      assert.notEqual(tables[2][tables[3].tableId.indexOf("Other")], staffRef);
      assert.deepEqual(a.doc.privacy.scopesOf("Other", "X"), []);
      await a.doc.applyUserActions([["RemoveTable", "Other"]]);
    });
  });

  describe("what reveals private values", function() {
    let relay: MemoryRelay;
    let a: Participant;   // Owner: can read everything.
    let b: Participant;   // Can read the private columns.
    let c: Participant;   // Can't.
    let scope: string;
    let staffRef: number;
    let salaryRef: number;

    async function colRef(p: Participant, tableId: string, colId: string) {
      const tables = await tableValues(p, "_grist_Tables");
      const cols = await tableValues(p, "_grist_Tables_column");
      const tableRef = tables[2][tables[3].tableId.indexOf(tableId)];
      return cols[2].find((_, i) => cols[3].parentId[i] === tableRef && cols[3].colId[i] === colId)!;
    }

    async function syncAll() {
      for (const p of [a, b, c]) { await p.doc.sync(); }
    }

    before(async function() {
      relay = await newRelay(bob, carol);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, bob, carol);
      await a.doc.applyUserActions([
        ["AddTable", "Staff", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false },
          { id: "HighEarner", type: "Bool", isFormula: true, formula: "$Salary > 55000" },
          { id: "Grade", type: "Choice", isFormula: false, widgetOptions: JSON.stringify({ choices: ["A"] }) },
        ]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300] }],
      ]);
      staffRef = (await tableValues(a, "_grist_Tables"))[2][1];
      salaryRef = await colRef(a, "Staff", "Salary");
      scope = makeColumnScope();
      await a.doc.createScopeKey(scope, [alice, bob].map(m => ({ ...m, vaultUserId: vaultIdFor(m) })), salaryRef);
      const gradeScope = makeColumnScope();
      await a.doc.createScopeKey(gradeScope, [alice, bob].map(m => ({ ...m, vaultUserId: vaultIdFor(m) })),
        await colRef(a, "Staff", "Grade"));
      await a.doc.saveSnapshot({ compact: true });
      b = await join(relay, bob);
      c = await join(relay, carol);
    });

    after(function() {
      for (const p of [a, b, c]) { leave(relay, p); }
    });

    it("keeps private the summaries grouped by formulas using private columns", async function() {
      const highEarnerRef = await colRef(a, "Staff", "HighEarner");
      await a.doc.applyUserActions([["CreateViewSection", staffRef, 0, "record", [highEarnerRef], null]]);
      await syncAll();
      assert.deepEqual(a.doc.privacy.scopesOf("Staff_summary_HighEarner", "HighEarner"), [scope]);
      assert.deepEqual((await tableValues(b, "Staff_summary_HighEarner"))[3].HighEarner, [false, true]);
      assert.deepEqual((await tableValues(c, "Staff_summary_HighEarner"))[3].HighEarner, [LOCKED_CELL, LOCKED_CELL]);
    });

    it("seals saved filters, comments and choices of private columns", async function() {
      const sectionRef = (await tableValues(a, "_grist_Views_section"))[2][0];
      await a.doc.applyUserActions([
        ["AddRecord", "_grist_Filters", null,
          { viewSectionRef: sectionRef, colRef: salaryRef, filter: JSON.stringify({ included: [61300.5] }) }],
        ["AddRecord", "_grist_Cells", null, {
          tableRef: staffRef, colRef: salaryRef, rowId: 1, type: 1, root: true,
          content: JSON.stringify({ text: "raise to 77777" }),
        }],
        ["UpdateRecord", "_grist_Tables_column", await colRef(a, "Staff", "Grade"),
          { widgetOptions: JSON.stringify({ choices: ["A", "Fired-Secretly"] }) }],
      ]);
      await syncAll();
      const readable = await readableWithDocKey(relay);
      for (const secret of ["61300.5", "77777", "Fired-Secretly"]) { assert.notInclude(readable, secret); }
      assert.include((await tableValues(b, "_grist_Filters"))[3].filter[0], "61300.5");
      assert.include((await tableValues(b, "_grist_Cells"))[3].content[0], "77777");
      assert.equal((await tableValues(c, "_grist_Filters"))[3].filter[0], LOCKED_CELL);
      assert.equal((await tableValues(c, "_grist_Cells"))[3].content[0], LOCKED_CELL);
      const cols = await tableValues(c, "_grist_Tables_column");
      assert.equal(cols[3].widgetOptions[cols[2].indexOf(await colRef(c, "Staff", "Grade"))], LOCKED_CELL);
      // Members without the key can't change them, nor drop them (undoing it would need them).
      await assert.isRejected(c.doc.applyUserActions([["RemoveRecord", "_grist_Filters", 1]]), /private settings/);
      await assert.isRejected(c.doc.applyUserActions([["UpdateRecord", "_grist_Filters", 1, { filter: "" }]]),
        /private settings/);
      // Their snapshots pass them on, sealed.
      await c.doc.saveSnapshot();
      assert.equal(relay.snapshots[relay.snapshots.length - 1].actionNum, relay.head);
      const b2 = await join(relay, bob);
      assert.include((await tableValues(b2, "_grist_Cells"))[3].content[0], "77777");
      leave(relay, b2);
      assert.notInclude(await readableWithDocKey(relay), "77777");
    });

    it("seals the names and sizes of files attached in private columns", async function() {
      const encrypted = await encryptFile(a.doc.keyring, scope, new TextEncoder().encode("%PDF payslip"));
      const { fileId } = await a.client.uploadFile(encrypted.ciphertext);
      await a.doc.applyUserActions([["AddRecord", "_grist_Attachments", null, {
        fileName: "payslip-of-ana.pdf", fileSize: 12345, fileIdent: makeFileIdent({ fileId, ...encrypted.ref }),
      }]]);
      await syncAll();
      const readable = await readableWithDocKey(relay);
      assert.notInclude(readable, "payslip-of-ana");
      assert.notInclude(readable, "12345");
      assert.equal((await tableValues(b, "_grist_Attachments"))[3].fileName[0], "payslip-of-ana.pdf");
      assert.equal((await tableValues(c, "_grist_Attachments"))[3].fileName[0], LOCKED_CELL);
    });

    it("finds private columns used under names Python reads the same", async function() {
      await a.doc.applyUserActions([
        ["AddColumn", "Staff", "Wide", { type: "Any", isFormula: true, formula: "rec.\uFF33alary * 2" }],
      ]);
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Wide"), [scope]);
      await syncAll();
      assert.deepEqual((await tableValues(c, "Staff"))[3].Wide, [LOCKED_CELL, LOCKED_CELL]);
      assert.deepEqual((await tableValues(a, "Staff"))[3].Wide, [104200, 122600]);
      await a.doc.applyUserActions([["RemoveColumn", "Staff", "Wide"]]);
      await syncAll();
    });

    it("refuses changes to columns formulas members can't compute use", async function() {
      await a.doc.applyUserActions([
        ["AddColumn", "Staff", "Bonus", { type: "Numeric", isFormula: false }],
        ["AddColumn", "Staff", "Total", { type: "Numeric", isFormula: true, formula: "$Salary + $Bonus" }],
      ]);
      await syncAll();
      const head = relay.head;
      await assert.isRejected(c.doc.applyUserActions([["RenameColumn", "Staff", "Bonus", "Extra"]]),
        /used by a calculation/);
      await assert.isRejected(c.doc.applyUserActions([["ModifyColumn", "Staff", "Bonus", { type: "Text" }]]),
        /used by a calculation/);
      await assert.isRejected(c.doc.applyUserActions([["RemoveColumn", "Staff", "Bonus"]]), /used by a calculation/);
      assert.equal(relay.head, head);
      assert.deepInclude((await tableValues(c, "Staff"))[3], { Bonus: [0, 0] });
    });

    it("doesn't give new columns the ids of removed private columns", async function() {
      const tempScope = makeColumnScope();
      await a.doc.applyUserActions([["AddColumn", "Staff", "Temp", { type: "Text", isFormula: false }]]);
      const tempRef = await colRef(a, "Staff", "Temp");
      await a.doc.createScopeKey(tempScope, [alice].map(m => ({ ...m, vaultUserId: vaultIdFor(m) })), tempRef);
      await a.doc.applyUserActions([["RemoveColumn", "Staff", "Temp"]]);
      await a.doc.applyUserActions([["AddColumn", "Staff", "Fresh", { type: "Text", isFormula: false }]]);
      assert.isAbove(await colRef(a, "Staff", "Fresh"), tempRef);
      assert.deepEqual(a.doc.privacy.scopesOf("Staff", "Fresh"), []);
      await syncAll();
      await c.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Fresh: "anyone can write here" }]]);
    });

    it("never takes the locked placeholder for a value of regular documents", function() {
      assert.isFalse(isLockedCell("locked"));
      assert.isTrue(isLockedCell(LOCKED_CELL));
    });
  });

  describe("making a column public again", function() {
    let relay: MemoryRelay;
    let a: Participant;   // Owner holding the column's key.
    let c: Participant;   // Member who can't read it.
    let scope: string;
    let fileRef: EncryptedFileRef;

    before(async function() {
      relay = await newRelay(carol);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, carol);
      await a.doc.applyUserActions([
        ["AddTable", "Staff", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false },
          { id: "Double", type: "Numeric", isFormula: true, formula: "$Salary * 2" },
        ]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300] }],
      ]);
      const cols = await tableValues(a, "_grist_Tables_column");
      const salaryRef = cols[2][cols[3].colId.indexOf("Salary")];
      scope = makeColumnScope();
      await a.doc.createScopeKey(scope, [{ ...alice, vaultUserId: vaultIdFor(alice) }], salaryRef);
      await a.doc.saveSnapshot({ compact: true });
      const encrypted = await encryptFile(a.doc.keyring, scope, new TextEncoder().encode("%PDF payslip"));
      const { fileId } = await a.client.uploadFile(encrypted.ciphertext);
      fileRef = { fileId, ...encrypted.ref };
      await a.doc.applyUserActions([["AddRecord", "_grist_Attachments", null, {
        fileName: "payslip.pdf", fileSize: 12, fileIdent: makeFileIdent(fileRef),
      }]]);
      c = await join(relay, carol);
    });

    after(function() {
      for (const p of [a, c]) { leave(relay, p); }
    });

    it("waits for the values to be shared before saving snapshots", async function() {
      // The column is made public, but sharing its values fails (e.g. the owner went offline).
      const realPush = a.client.pushAction.bind(a.client);
      a.client.pushAction = async () => { throw new Error("offline"); };
      try {
        await a.doc.releaseScope(scope);
      } finally {
        a.client.pushAction = realPush;
      }
      await c.doc.sync();
      assert.deepEqual(c.doc.privacy.scopesOf("Staff", "Salary"), []);
      assert.deepInclude((await tableValues(c, "Staff"))[3], { Salary: [LOCKED_CELL, LOCKED_CELL] });
      // Carol's snapshot would save her locked values as the column's: she leaves it for later.
      const snapshots = relay.snapshots.length;
      await c.doc.saveSnapshot();
      assert.lengthOf(relay.snapshots, snapshots);
    });

    it("shares the values as soon as a member who can read them can", async function() {
      await a.doc.refreshKeys();
      await a.doc.sync();   // (Waits for the sharing, done in the background.)
      await c.doc.sync();
      assert.deepInclude((await tableValues(c, "Staff"))[3], { Salary: [52100, 61300], Double: [104200, 122600] });
      // Attachments of the column get keys everyone can use.
      const attachments = await tableValues(c, "_grist_Attachments");
      assert.equal(attachments[3].fileName[0], "payslip.pdf");
      const newRef = parseFileIdent(attachments[3].fileIdent[0] as string)!;
      assert.notEqual(newRef.keyId, fileRef.keyId);
      const data = await decryptFile(c.doc.keyring, newRef, await c.client.fetchFile(newRef.fileId));
      assert.equal(new TextDecoder().decode(data), "%PDF payslip");
      // Now snapshots can be saved, with the values.
      await c.doc.saveSnapshot();
      assert.equal(relay.snapshots[relay.snapshots.length - 1].actionNum, relay.head);
      const c2 = await join(relay, carol);
      assert.deepInclude((await tableValues(c2, "Staff"))[3], { Salary: [52100, 61300] });
      leave(relay, c2);
    });
  });

  describe("sensitive changes", function() {
    let relay: MemoryRelay;
    let a: Participant;   // Owner.
    let b: Participant;   // Can read the private column.
    let c: Participant;   // Can't.
    let salaryRef: number;

    before(async function() {
      relay = await newRelay(bob, carol);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, bob, carol);
      await a.doc.applyUserActions([
        ["AddTable", "Staff", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false },
        ]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300] }],
      ]);
      const cols = await tableValues(a, "_grist_Tables_column");
      salaryRef = cols[2][cols[3].colId.indexOf("Salary")];
      b = await join(relay, bob);
      c = await join(relay, carol);
    });

    after(function() {
      for (const p of [a, b, c]) { leave(relay, p); }
    });

    it("saves the document along with making a column private, dropping what was readable", async function() {
      assert.include(await readableWithDocKey(relay), "61300");
      const scope = makeColumnScope();
      await a.doc.createScopeKey(scope, [alice, bob].map(m => ({ ...m, vaultUserId: vaultIdFor(m) })), salaryRef,
        { compact: true });
      // One step: the key change and the snapshot under it, with nothing else kept.
      assert.equal(relay.keyChangeSnapshots, 1);
      assert.deepEqual(relay.snapshots.map(snap => snap.actionNum), [relay.head]);
      assert.deepEqual(relay.actions.filter(act => act.actionNum <= relay.head), []);
      assert.notInclude(await readableWithDocKey(relay), "61300");
      // Newcomers load it as such.
      const b2 = await join(relay, bob);
      const c2 = await join(relay, carol);
      assert.deepEqual((await tableValues(b2, "Staff"))[3].Salary, [52100, 61300]);
      assert.deepEqual((await tableValues(c2, "Staff"))[3].Salary, [LOCKED_CELL, LOCKED_CELL]);
      leave(relay, b2);
      leave(relay, c2);
    });

    it("saves the document along with replacing a key", async function() {
      relay.revoke([carol.userId]);
      await a.doc.refreshKeys();
      await a.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Name: "Anna" }]]);
      assert.equal(relay.keyChangeSnapshots, 2);
      const newKey = relay.currentKey(DOC_SCOPE)!;
      const latest = relay.snapshots[relay.snapshots.length - 1];
      assert.deepInclude(latest, { actionNum: newKey.actionNum, keyId: newKey.keyId });
      // Bob, given only the new key, opens it.
      const b2 = await join(relay, bob);
      assert.deepEqual((await tableValues(b2, "Staff"))[3].Name, ["Anna", "Ben"]);
      leave(relay, b2);
      await b.doc.sync();
    });

    it("lets owners restore an earlier version, which every browser reloads", async function() {
      await a.doc.saveSnapshot();
      const earlier = relay.head;
      await a.doc.applyUserActions([["BulkUpdateRecord", "Staff", [1, 2], { Name: ["Ann", "Benny"], Salary: [1, 2] }]]);
      await b.doc.sync();
      assert.deepEqual((await tableValues(b, "Staff"))[3].Name, ["Ann", "Benny"]);
      // Only owners.
      await assert.isRejected(b.doc.restoreSnapshot(earlier), /Only owners can restore/);
      await a.doc.restoreSnapshot(earlier);
      // The document is replaced: browsers that have it open must reopen it.
      await assert.isRejected(b.doc.sync(), /earlier version of this document was restored/);
      await assert.isRejected(a.doc.fetchTable("Staff"), /closed/);
      assert.deepEqual(relay.actions[relay.actions.length - 1].kind, "restore");
      a = await join(relay, alice);
      b = await join(relay, bob);
      assert.deepEqual((await tableValues(a, "Staff"))[3], { Name: ["Anna", "Ben"], Salary: [52100, 61300],
        manualSort: [1, 2] });
      assert.deepEqual((await tableValues(b, "Staff"))[3].Salary, [52100, 61300]);
      // Still private, under the current keys.
      assert.notInclude(await readableWithDocKey(relay), "61300");
      // And it goes on from there.
      await b.doc.applyUserActions([["UpdateRecord", "Staff", 2, { Name: "Benjamin" }]]);
      await a.doc.sync();
      assert.deepEqual((await tableValues(a, "Staff"))[3].Name, ["Anna", "Benjamin"]);
    });

    it("exports the whole document, with extra changes that aren't applied", async function() {
      const content = await a.doc.exportPlain([
        () => [["AddRecord", "_grist_ACLResources", null, { tableId: "Staff", colIds: "Salary" }]],
        previous => [["AddRecord", "_grist_ACLRules", null, {
          resource: previous[0], aclFormula: "user.UserID not in [1, 2]", permissionsText: "-RU", rulePos: 1,
        }]],
      ]);
      assert.equal(content.actionNum, relay.head);
      assert.deepEqual(content.tables.Staff[3].Salary, [52100, 61300]);
      const rules = content.tables._grist_ACLRules;
      const index = rules[3].aclFormula.indexOf("user.UserID not in [1, 2]");
      assert.isAbove(index, -1);
      assert.include(String(rules[3].aclFormulaParsed[index]), "NotIn");
      // Not applied to the document.
      assert.notInclude((await tableValues(a, "_grist_ACLRules"))[3].aclFormula, "user.UserID not in [1, 2]");
      // Making the document regular again: private columns get access rules for those who could
      // read them.
      const members = relay.listMembers();
      const plain = await a.doc.exportPlain(makeAccessRuleActions(a.doc.docData, a.doc.privacy, a.doc.keyring,
        members));
      const resources = plain.tables._grist_ACLResources;
      const resourceRef = resources[2][resources[3].colIds.indexOf("Salary")];
      assert.equal(resources[3].tableId[resources[2].indexOf(resourceRef)], "Staff");
      const aclRules = plain.tables._grist_ACLRules;
      const ruleIndex = aclRules[3].resource.indexOf(resourceRef);
      assert.equal(aclRules[3].aclFormula[ruleIndex], `user.UserID not in [${alice.userId}, ${bob.userId}]`);
      assert.equal(aclRules[3].permissionsText[ruleIndex], "-RU");
      assert.include(String(aclRules[3].aclFormulaParsed[ruleIndex]), "NotIn");

      // Only for members who can read everything.
      await giveKeys(relay, DOC_SCOPE, carol);
      const c2 = await join(relay, carol);
      await assert.isRejected(c2.doc.exportPlain(), /can read everything/);
      leave(relay, c2);
    });
  });

  describe("suggestions", function() {
    let relay: MemoryRelay;
    let a: Participant;   // Owner.
    let d: Participant;   // Viewer, who may suggest changes.

    before(async function() {
      relay = await newRelay(dave);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, dave);
      await a.doc.applyUserActions([
        ["AddTable", "Staff", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false },
        ]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300] }],
      ]);
      const cols = await tableValues(a, "_grist_Tables_column");
      await a.doc.createScopeKey(makeColumnScope(), [{ ...alice, vaultUserId: vaultIdFor(alice) }],
        cols[2][cols[3].colId.indexOf("Salary")], { compact: true });
      d = await join(relay, dave, { canSuggest: true });
    });

    after(function() {
      for (const p of [a, d]) { leave(relay, p); }
    });

    it("keeps changes local while suggesting, holding back others' changes", async function() {
      assert.isTrue(d.doc.isSuggesting);
      const head = relay.head;
      await d.doc.applyUserActions([["UpdateRecord", "Staff", 2, { Name: "Benjamin" }]]);
      await d.doc.applyUserActions([["AddRecord", "Staff", null, { Name: "Cleo" }]]);
      assert.equal(d.doc.pendingSuggestionCount, 2);
      assert.equal(relay.head, head);
      assert.deepEqual((await tableValues(d, "Staff"))[3].Name, ["Ana", "Benjamin", "Cleo"]);
      // Undoing the latest one.
      const latest = d.received[d.received.length - 1].actionGroup;
      await d.doc.applyUserActionsById([latest.actionNum], [latest.actionHash], true);
      assert.deepEqual((await tableValues(d, "Staff"))[3].Name, ["Ana", "Benjamin"]);
      assert.equal(d.doc.pendingSuggestionCount, 1);
      // Changes from others wait.
      await a.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Name: "Anna" }]]);
      await d.doc.sync();
      assert.deepEqual((await tableValues(d, "Staff"))[3].Name, ["Ana", "Benjamin"]);
      // Suggestions can't involve private columns.
      await assert.isRejected(d.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Salary: 1 }]]),
        /member with access|private/);
    });

    it("sends suggestions, which members who can edit apply or dismiss", async function() {
      await d.doc.submitSuggestion("Ben prefers Benjamin");
      // Undone locally, with others' changes applied now.
      assert.equal(d.doc.pendingSuggestionCount, 0);
      assert.deepEqual((await tableValues(d, "Staff"))[3].Name, ["Anna", "Ben"]);
      assert.lengthOf(relay.suggestions, 1);
      assert.notInclude(relay.suggestions[0].payload, "Benjamin");
      // Only its author sees it among viewers; members who can edit see all.
      assert.deepEqual((await d.doc.listSuggestions()).map(s => s.desc), ["Ben prefers Benjamin"]);
      const [suggestion] = await a.doc.listSuggestions();
      assert.deepEqual(suggestion.userActions, [["UpdateRecord", "Staff", 2, { Name: "Benjamin" }]]);
      assert.equal(suggestion.userId, dave.userId);
      await a.doc.applySuggestion(suggestion.id);
      assert.lengthOf(relay.suggestions, 0);
      await d.doc.sync();
      assert.deepEqual((await tableValues(d, "Staff"))[3].Name, ["Anna", "Benjamin"]);
      assert.match(a.doc.getActionSummaries().slice(-1)[0].desc!, /Suggested by dave@example.com: Ben prefers Benjamin/);

      await d.doc.applyUserActions([["AddRecord", "Staff", null, { Name: "Cleo" }]]);
      await d.doc.submitSuggestion("");
      await a.doc.dismissSuggestion((await a.doc.listSuggestions())[0].id);
      assert.lengthOf(relay.suggestions, 0);
      await a.doc.sync();
      assert.deepEqual((await tableValues(a, "Staff"))[3].Name, ["Anna", "Benjamin"]);
    });
  });

  describe("forms", function() {
    let relay: MemoryRelay;
    let a: Participant;
    let sectionId: number;
    const keys: EncryptedFormKeys = { formId: "", publicKey: "", privateKey: "", linkKey: "" };
    // Files sent with answers, as the server keeps them (encrypted by respondents).
    const inboxFiles = new Map<string, Uint8Array>();

    // What the member's browser does for reading answers (see DocConversion.makeFormAnswerHelpers()).
    function formHelpers(p: Participant): FormAnswerHelpers {
      return {
        getPrivateKey: async (formKeys) => {
          if (formKeys.privateKey) { return formKeys.privateKey; }
          const sealed = formKeys.sealedPrivateKey!;
          if (!sealed.keyIds.every(keyId => p.doc.keyring.holds(keyId))) { return null; }
          const data = await p.doc.keyring.decryptWithAll(sealed.keyIds, base64ToBytes(sealed.data));
          return new TextDecoder().decode(data);
        },
        storeFile: async (file, scope) => {
          const data = await decryptFormFile(file.key, inboxFiles.get(file.fileId)!);
          const { ciphertext, ref } = await encryptFile(p.doc.keyring, scope, data);
          const { fileId } = await p.client.uploadFile(ciphertext);
          return makeFileIdent({ fileId, ...ref });
        },
      };
    }

    before(async function() {
      relay = await newRelay(bob);
      a = await join(relay, alice, { create: true });
      await a.doc.applyUserActions([
        ["AddTable", "Contacts", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Age", type: "Numeric", isFormula: false },
          { id: "Secret", type: "Text", isFormula: false },
          { id: "Upper", type: "Text", isFormula: true, formula: "$Name.upper()" },
        ]],
      ]);
      const tables = await tableValues(a, "_grist_Tables");
      const tableRef = tables[2][tables[3].tableId.indexOf("Contacts")];
      const result = await a.doc.applyUserActions([["CreateViewSection", tableRef, 0, "form", null, null]]);
      sectionId = result.retValues[0].sectionRef;
      const cols = await tableValues(a, "_grist_Tables_column");
      await a.doc.createScopeKey(makeColumnScope(), [{ ...alice, vaultUserId: vaultIdFor(alice) }],
        cols[2].find((_, i) => cols[3].colId[i] === "Secret" && cols[3].parentId[i] === tableRef), { compact: true });
      Object.assign(keys, await generateFormKeys());
    });

    after(function() {
      leave(relay, a);
    });

    it("gives respondents the form's questions, without private columns or formulas", async function() {
      const spec = await buildFormSpec(a.doc.docData, a.doc.privacy, sectionId, keys,
        async tableId => (await a.doc.fetchTable(tableId)).tableData);
      const colIds = Object.values(spec.form.formFieldsById).map((f: any) => f.colId);
      assert.sameMembers(colIds, ["Name", "Age"]);
      assert.equal(spec.form.formTableId, "Contacts");
      // Encrypted with the link key: the server can't read it, nor change it.
      const encrypted = await encryptFormSpec(keys.linkKey, spec);
      assert.notInclude(new TextDecoder().decode(encrypted), "Contacts");
      assert.deepEqual(await decryptFormSpec(keys.linkKey, encrypted), spec);
      encrypted[20] ^= 1;
      await assert.isRejected(decryptFormSpec(keys.linkKey, encrypted));
      const otherLinkKey = (await generateFormKeys()).linkKey;
      await assert.isRejected(decryptFormSpec(otherLinkKey, await encryptFormSpec(keys.linkKey, spec)));
    });

    it("adds answers to the document, removing them from the inbox at the same time", async function() {
      await a.doc.applyUserActions([["UpdateRecord", "_grist_Views_section", sectionId, {
        shareOptions: JSON.stringify({ form: true, publish: true, encryptedForm: keys }),
      }]]);
      const answer = async (colValues: object) => bytesToBase64(await encryptFormAnswer(keys.publicKey,
        { v: 1, tableId: "Contacts", colValues: colValues as any }));
      relay.inbox.push(
        { id: 1, formId: keys.formId, payload: await answer({ Name: "Zoe", Age: 31 }), timeMs: 0 },
        // Values for columns that aren't in the form (here a private one) are left out.
        { id: 2, formId: keys.formId, payload: await answer({ Name: "Yan", Secret: "intruder" }), timeMs: 0 },
        // Not readable: dropped.
        { id: 3, formId: keys.formId, payload: bytesToBase64(new Uint8Array(100)), timeMs: 0 },
        // For a form that isn't the document's: dropped.
        { id: 4, formId: "f".repeat(32), payload: await answer({ Name: "Xi" }), timeMs: 0 },
      );
      const added = await a.doc.importFormAnswers(entries => readFormAnswers(a.doc.docData, a.doc.privacy, entries,
        formHelpers(a)));
      assert.equal(added, 2);
      assert.deepEqual(relay.inbox, []);
      const rows = (await tableValues(a, "Contacts"))[3];
      assert.deepEqual(rows.Name, ["Zoe", "Yan"]);
      assert.deepEqual(rows.Secret, ["", ""]);
      assert.deepEqual(rows.Upper, ["ZOE", "YAN"]);
      // Members who joined later see them, as any change.
      await giveKeys(relay, DOC_SCOPE, bob);
      const b = await join(relay, bob);
      assert.deepEqual((await tableValues(b, "Contacts"))[3].Name, ["Zoe", "Yan"]);
      // An answer someone else added first isn't added twice.
      relay.inbox.push({ id: 5, formId: keys.formId, payload: await answer({ Name: "Wu" }), timeMs: 0 });
      await Promise.all([
        a.doc.importFormAnswers(entries => readFormAnswers(a.doc.docData, a.doc.privacy, entries, formHelpers(a))),
        b.doc.importFormAnswers(entries => readFormAnswers(b.doc.docData, b.doc.privacy, entries, formHelpers(b))),
      ]);
      await a.doc.sync();
      assert.deepEqual((await tableValues(a, "Contacts"))[3].Name, ["Zoe", "Yan", "Wu"]);
      leave(relay, b);
    });

    it("takes answers for private columns, and files, for members who can read them", async function() {
      // Alice publishes the form with Secret in it: its private key is sealed with Secret's key.
      const secretScope = a.doc.privacy.scopesOf("Contacts", "Secret")[0];
      const keyIds = [a.doc.keyring.currentKeyId(secretScope)];
      const sealedKeys: EncryptedFormKeys = { ...await generateFormKeys(), scopes: [secretScope] };
      sealedKeys.sealedPrivateKey = { keyIds, data: bytesToBase64(await a.doc.keyring.encryptWithAll(keyIds,
        new TextEncoder().encode(sealedKeys.privateKey))) };
      delete sealedKeys.privateKey;
      await a.doc.applyUserActions([
        ["AddColumn", "Contacts", "Photo", { type: "Attachments", isFormula: false }],
      ]);
      const tables = await tableValues(a, "_grist_Tables");
      const tableRef = tables[2][tables[3].tableId.indexOf("Contacts")];
      const result = await a.doc.applyUserActions([["CreateViewSection", tableRef, 0, "form", null, null]]);
      const formSection = result.retValues[0].sectionRef;
      const cols = await tableValues(a, "_grist_Tables_column");
      const photoRef = cols[2].find((_, i) => cols[3].parentId[i] === tableRef && cols[3].colId[i] === "Photo")!;
      const fields = await tableValues(a, "_grist_Views_section_field");
      if (!fields[2].some((_, i) => fields[3].parentId[i] === formSection && fields[3].colRef[i] === photoRef)) {
        await a.doc.applyUserActions([["AddRecord", "_grist_Views_section_field", null,
          { parentId: formSection, colRef: photoRef, parentPos: 100 }]]);
      }
      await a.doc.applyUserActions([["UpdateRecord", "_grist_Views_section", formSection, {
        shareOptions: JSON.stringify({ form: true, publish: true, encryptedForm: sealedKeys }),
      }]]);
      const spec = await buildFormSpec(a.doc.docData, a.doc.privacy, formSection, sealedKeys,
        async tableId => (await a.doc.fetchTable(tableId)).tableData);
      assert.includeMembers(Object.values(spec.form.formFieldsById).map((f: any) => f.colId), ["Secret", "Photo"]);

      // A respondent sends an answer, with a file.
      const { key, payload } = await encryptFormFile(new TextEncoder().encode("%PDF resume"));
      inboxFiles.set("1".repeat(32), payload);
      relay.inbox.push({ id: 10, formId: sealedKeys.formId, timeMs: Date.now(), payload: bytesToBase64(
        await encryptFormAnswer(sealedKeys.publicKey, { v: 1, tableId: "Contacts",
          colValues: { Name: "Vic", Secret: "top secret", Photo: ["L", -1] },
          files: [{ fileId: "1".repeat(32), key, name: "resume.pdf", size: 11 }] })) });

      // Bob can't read Secret: he leaves the answer to others.
      await giveKeys(relay, DOC_SCOPE, bob);
      const b = await join(relay, bob);
      assert.equal(await b.doc.importFormAnswers(entries => readFormAnswers(b.doc.docData, b.doc.privacy, entries,
        formHelpers(b))), 0);
      assert.lengthOf(relay.inbox, 1);
      // Alice can.
      assert.equal(await a.doc.importFormAnswers(entries => readFormAnswers(a.doc.docData, a.doc.privacy, entries,
        formHelpers(a))), 1);
      assert.deepEqual(relay.inbox, []);
      const rows = (await tableValues(a, "Contacts"))[3];
      assert.equal(rows.Secret[rows.Secret.length - 1], "top secret");
      const photo = rows.Photo[rows.Photo.length - 1] as any[];
      const attachments = await tableValues(a, "_grist_Attachments");
      const index = attachments[2].indexOf(photo[1]);
      assert.equal(attachments[3].fileName[index], "resume.pdf");
      const ref = parseFileIdent(attachments[3].fileIdent[index] as string)!;
      const fileData = await decryptFile(a.doc.keyring, ref, await a.client.fetchFile(ref.fileId));
      assert.equal(new TextDecoder().decode(fileData), "%PDF resume");
      // The private value stays sealed for others.
      assert.notInclude(await readableWithDocKey(relay), "top secret");
      await b.doc.sync();
      const bRows = (await tableValues(b, "Contacts"))[3];
      assert.equal(bRows.Secret[bRows.Secret.length - 1], LOCKED_CELL);
      leave(relay, b);
    });

    it("describes the document's structure for the formula assistant, in the browser", async function() {
      const prompt = await a.doc.getFormulaPrompt("Contacts", "Upper",
        { includeAllTables: true, includeLookups: true });
      assert.include(prompt, "class Contacts:");
      assert.include(prompt, "Age: float");
      assert.include(prompt, "def Upper(rec: Contacts) -> str:");
      // No values in it.
      assert.notInclude(prompt, "Zoe");
      assert.equal(await a.doc.convertFormulaCompletion("Here:\n```python\nreturn rec.Name.lower()\n```"),
        "$Name.lower()");
    });
  });

  describe("against a server changing keys or private columns", function() {
    let relay: MemoryRelay;
    let a: Participant;   // Owner, can read Salary.
    let c: Participant;   // Can't.
    let scope: string;

    before(async function() {
      relay = await newRelay(bob, carol);
      a = await join(relay, alice, { create: true });
      await giveKeys(relay, DOC_SCOPE, bob, carol);
      await a.doc.applyUserActions([
        ["AddTable", "Staff", [{ id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false }]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300] }],
      ]);
      const cols = await tableValues(a, "_grist_Tables_column");
      scope = makeColumnScope();
      await a.doc.createScopeKey(scope, [{ ...alice, vaultUserId: vaultIdFor(alice) }],
        cols[2][cols[3].colId.indexOf("Salary")], { compact: true });
      c = await join(relay, carol);
    });

    after(function() {
      for (const p of [a, c]) { leave(relay, p); }
    });

    it("keeps columns private when the server forgets they are", async function() {
      const binding = relay.bindings.find(b => b.scope === scope)!;
      relay.bindings = relay.bindings.filter(b => b !== binding);
      try {
        // Members who open the document still know, from what members recorded.
        const c2 = await join(relay, carol);
        assert.deepEqual((await tableValues(c2, "Staff"))[3].Salary, [LOCKED_CELL, LOCKED_CELL]);
        leave(relay, c2);
        // New values stay sealed.
        await a.doc.refreshKeys();
        await a.doc.applyUserActions([["UpdateRecord", "Staff", 1, { Salary: 99999 }]]);
        assert.notInclude(await readableWithDocKey(relay), "99999");
        await c.doc.sync();
        assert.deepEqual((await tableValues(c, "Staff"))[3].Salary, [LOCKED_CELL, LOCKED_CELL]);
      } finally {
        relay.bindings.push(binding);
      }
    });

    it("refuses key changes members didn't make", async function() {
      // The server says the column was made public (without a record of it by a member).
      relay.bindings.find(b => b.scope === scope)!.releasedAt = relay.head + 1;
      relay.actions.push({ actionNum: relay.head + 1, kind: "key", keyId: relay.currentKey(scope)!.keyId,
        payload: "", userId: alice.userId, timeMs: Date.now() });
      await assert.isRejected(c.doc.sync(), /weren't made by members/);
      // Nothing got revealed.
      assert.notInclude(await readableWithDocKey(relay), "61300");
      const c2 = await join(relay, carol).catch(e => e);
      assert.match(String(c2), /weren't made by members/);
    });

    it("never uses keys the server made up", async function() {
      // A fresh document, whose key the server replaces with one it made for the members.
      const relay2 = await newRelay(bob);
      const a2 = await join(relay2, alice, { create: true });
      await a2.doc.applyUserActions([["AddRecord", "Table1", null, { A: "before" }]]);
      const fakeKeyId = makeKeyId(DOC_SCOPE);
      const wraps = await vault.createDocumentKey([recipient(alice)]);
      for (const key of relay2.keys) { key.current = false; }
      relay2.keys.push({ keyId: fakeKeyId, scope: DOC_SCOPE, current: true, rotateOnNextEdit: false,
        actionNum: relay2.head + 1 });
      relay2.wraps.push({ keyId: fakeKeyId, userId: alice.userId, keyVersion: 1,
        wrappedKey: bytesToBase64(wraps.get(vaultIdFor(alice))!.wrappedKey) });
      relay2.actions.push({ actionNum: relay2.head + 1, kind: "key", keyId: fakeKeyId, payload: "",
        userId: bob.userId, timeMs: Date.now() });
      await assert.isRejected(a2.doc.sync(), /weren't made by members/);
      // Reopening: the made-up key isn't used to write anything.
      leave(relay2, a2);
      const reopened = await join(relay2, alice).catch(e => e);
      assert.match(String(reopened), /weren't made by members/);
      assert.isFalse(relay2.actions.some(act => act.kind === "change" && act.keyId === fakeKeyId));
    });

    it("checks that copies of keys are of the keys members recorded", async function() {
      // The server gives Alice a copy of another key, under the column key's id.
      const keyId = relay.currentKey(scope)!.keyId;
      const wrap = relay.wraps.find(w => w.keyId === keyId && w.userId === alice.userId)!;
      const original = wrap.wrappedKey;
      const other = await vault.createDocumentKey([recipient(alice)]);
      wrap.wrappedKey = bytesToBase64(other.get(vaultIdFor(alice))!.wrappedKey);
      try {
        const keyring = new Keyring(vault, async () => relay.getKeys(alice.userId), relay.getKeys(alice.userId));
        keyring.setHistory(a.doc.keyring.history);
        await assert.isRejected(keyring.encrypt(keyId, new Uint8Array([1])), /is of another key/);
      } finally {
        wrap.wrappedKey = original;
      }
    });
  });
});
