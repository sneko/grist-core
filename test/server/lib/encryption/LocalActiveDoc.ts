/**
 * Tests the browser-side logic of encrypted documents: several "browsers", each with its own data
 * engine, editing one document through a relay that only ever sees ciphertext. Covers private
 * columns, key replacement, and attachments.
 */
import { TableDataAction } from "app/common/DocActions";
import { EncryptionAccessError, LOCKED_CELL } from "app/common/encryption/ColumnPrivacy";
import { decryptFile, encryptFile } from "app/common/encryption/EncryptedAttachments";
import {
  decryptBundle, decryptSnapshot, DocChangeBundle, encryptBundle,
} from "app/common/encryption/EncryptedPayloads";
import { base64ToBytes, bytesToBase64, MockKeyVault } from "app/common/encryption/EncryptionCrypto";
import {
  DOC_SCOPE, EncryptedActionRecord, makeColumnScope, makeKeyId,
} from "app/common/encryption/EncryptionTypes";
import { Keyring, MissingKeyError } from "app/common/encryption/Keyring";
import { InvalidChange, LocalActiveDoc, LocalDocUserAction } from "app/common/encryption/LocalActiveDoc";
import { addParsedTables, parseFileLocally } from "app/common/encryption/LocalImport";
import { User } from "app/common/User";
import { createNodePyodideEngine } from "app/server/lib/encryption/NodePyodideEngine";
import { MemoryMember, MemoryRelay, RelayClient } from "test/server/lib/encryption/MemoryRelay";

import { assert } from "chai";

describe("encryption/LocalActiveDoc", function() {
  this.timeout(120000);

  const vault = new MockKeyVault();
  const vaultIdFor = (m: { userId: number }) => `user-${m.userId}`;
  const mockWrap = (userId: number) => bytesToBase64(new TextEncoder().encode(`mock-wrap:user-${userId}`));

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
  }

  async function join(relay: MemoryRelay, member: MemoryMember, options: {
    create?: boolean, snapshotEvery?: number,
  } = {}): Promise<Participant> {
    const client = relay.connect(member.userId);
    const received: LocalDocUserAction[] = [];
    const skipped: InvalidChange[] = [];
    const keyring = new Keyring(vault, () => client.getKeys(), relay.getKeys(member.userId));
    const doc = await LocalActiveDoc.open({
      engine: await createNodePyodideEngine(),
      relay: client,
      keyring,
      engineUser: new User({ Name: member.name, Email: member.email, Access: member.access, UserID: member.userId })
        .toJSON(),
      userName: member.email,
      canEdit: member.access !== "viewers",
      onDocUserAction: action => received.push(action),
      onInvalidChange: change => skipped.push(change),
      vaultIdFor,
      snapshotEvery: options.snapshotEvery,
      newDocSettings: options.create ? { timezone: "Europe/Paris", locale: "fr-FR" } : undefined,
    }, relay.open(member.userId));
    client.doc = doc;
    return { member, doc, client, received, skipped };
  }

  function leave(relay: MemoryRelay, p: Participant) {
    relay.disconnect(p.client);
    p.doc.close();
  }

  /** Sets up a new document: its first key, for its owner. */
  async function newRelay(...others: MemoryMember[]) {
    const relay = new MemoryRelay();
    for (const m of [alice, ...others]) { relay.addMember(m); }
    relay.createKey(relay.connect(alice.userId), {
      scope: DOC_SCOPE, keyId: makeKeyId(DOC_SCOPE), baseActionNum: 0,
      wraps: [{ userId: alice.userId, wrappedKey: mockWrap(alice.userId), keyVersion: 1 }],
    });
    return relay;
  }

  /** Gives members all the keys of a scope (as an owner holding them would). */
  function giveKeys(relay: MemoryRelay, scope: string, ...members: MemoryMember[]) {
    for (const key of relay.keys.filter(k => k.scope === scope)) {
      relay.share(members.map(m =>
        ({ keyId: key.keyId, userId: m.userId, wrappedKey: mockWrap(m.userId), keyVersion: 1 })));
    }
  }

  async function tableValues(p: Participant, tableId: string): Promise<TableDataAction> {
    return (await p.doc.fetchTable(tableId)).tableData;
  }

  /** Everything the server has, decrypted with only the document keys (as any member could). */
  async function readableWithDocKey(relay: MemoryRelay): Promise<string> {
    const keyring = new Keyring(vault, async () => ({ keys: relay.keys, myKeys: [], bindings: relay.bindings }), {
      keys: relay.keys,
      bindings: relay.bindings,
      myKeys: relay.keys.filter(k => k.scope === DOC_SCOPE)
        .map(k => ({ keyId: k.keyId, userId: 99, wrappedKey: mockWrap(99), keyVersion: 1 })),
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
      giveKeys(relay, DOC_SCOPE, bob, dave);
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
      giveKeys(relay, DOC_SCOPE, bob, carol);
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
      // The server's copy of the document was re-encrypted with the new key.
      assert.lengthOf(relay.snapshots, 1);
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
      // Everything on the server uses the new key.
      assert.isTrue([...relay.snapshots, ...relay.actions.filter(r => r.kind === "change")]
        .every(r => r.keyId === newKeyId));
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
});
