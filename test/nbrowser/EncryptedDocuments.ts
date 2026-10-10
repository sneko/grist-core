/**
 * Encrypted documents, in the browser: creation, editing, collaboration, key sharing, private
 * columns, and the guarantee that the server only ever stores ciphertext. Uses the mock vault
 * (hardcoded key) in place of the LaSuite encryption service.
 */
import { decryptBundle, decryptSnapshot } from "app/common/encryption/EncryptedPayloads";
import { MockKeyVault } from "app/common/encryption/EncryptionCrypto";
import { DOC_SCOPE } from "app/common/encryption/EncryptionTypes";
import { Keyring } from "app/common/encryption/Keyring";
import { UserAPI } from "app/common/UserAPI";
import { SQLiteDB } from "app/server/lib/SQLiteDB";
import * as gu from "test/nbrowser/gristUtils";
import { server, setupTestSuite } from "test/nbrowser/testUtils";
import { EnvironmentSnapshot } from "test/server/testUtils";

import * as path from "path";

import { assert } from "chai";
import { driver, Key } from "mocha-webdriver";

describe("EncryptedDocuments", function() {
  this.timeout("300s");
  const cleanup = setupTestSuite();
  let envSnapshot: EnvironmentSnapshot;
  let owner: gu.Session;
  let ownerApi: UserAPI;

  // Loading the data engine into the browser takes a few seconds the first time.
  const ENGINE_LOAD_MS = 60000;

  before(async function() {
    envSnapshot = new EnvironmentSnapshot();
    process.env.GRIST_ENCRYPTION_FEATURE_ENABLED = "true";
    process.env.GRIST_ENCRYPTION_MOCK_VAULT = "true";
    await server.restart();
    owner = await gu.session().user("user1").teamSite.login();
    ownerApi = owner.createHomeApi();
  });

  after(async function() {
    envSnapshot.restore();
    await server.restart();
  });

  /** All the ciphertext the server stores for a document, in its file. */
  async function storedPayloads(docId: string) {
    const db = await SQLiteDB.openDBRaw(path.join(server.testDocDir, `${docId}.grist`));
    try {
      return {
        actions: await db.all("SELECT keyId, payload FROM _gristsys_EncryptedActions WHERE kind = 'change'"),
        snapshots: await db.all("SELECT keyId, payload FROM _gristsys_EncryptedSnapshots"),
      };
    } finally {
      await db.close();
    }
  }

  /**
   * What the server stores for a document, decrypted with the document keys only (the mock vault's
   * key is known): what any member of the document could read.
   */
  async function readableWithDocKeys(docId: string): Promise<string> {
    const keys = (await (await server.getDatabase()).connection.query(
      "SELECT key_id AS \"keyId\", scope, action_num AS \"actionNum\" FROM doc_encryption_keys WHERE doc_id = ?",
      [docId]));
    const docKeys = keys.filter((k: any) => k.scope === DOC_SCOPE);
    // Any member's copy of a key can be unwrapped by anyone knowing the mock vault's key.
    const wraps = await (await server.getDatabase()).connection.query(
      "SELECT key_id AS \"keyId\", wrapped_key AS \"wrappedKey\" FROM doc_encryption_key_wraps WHERE doc_id = ?",
      [docId]);
    const keyring = new Keyring(new MockKeyVault(), async () => { throw new Error("no fetching"); }, {
      keys: keys.map((k: any) => ({ ...k, current: true, rotateOnNextEdit: false })),
      myKeys: docKeys.map((k: any) => ({
        keyId: k.keyId, userId: 0, keyVersion: 1,
        wrappedKey: wraps.find((w: any) => w.keyId === k.keyId).wrappedKey,
      })),
      bindings: [],
    });
    const { actions, snapshots } = await storedPayloads(docId);
    const parts: unknown[] = [];
    for (const a of actions) { parts.push(await decryptBundle(keyring, a.keyId, a.payload)); }
    for (const s of snapshots) { parts.push(await decryptSnapshot(keyring, s.keyId, s.payload)); }
    return JSON.stringify(parts);
  }

  async function allStoredText(docId: string): Promise<string> {
    const { actions, snapshots } = await storedPayloads(docId);
    return [...actions, ...snapshots].map(r => Buffer.from(r.payload).toString("latin1")).join("\n");
  }

  describe("a document of one's own", function() {
    let docId: string;

    it("creates an encrypted document from the home page", async function() {
      await owner.loadDocMenu("/");
      await driver.findWait(".test-dm-add-new", 2000).click();
      await driver.findWait(".test-dm-new-encrypted-doc", 2000).click();
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      docId = (await ownerApi.getDoc((await gu.getCurrentUrlId())!)).id;
      cleanup.addAfterAll(() => ownerApi.deleteDoc(docId));
      assert.deepEqual((await ownerApi.getDoc(docId)).options?.encryption, { version: 1 });
      assert.deepEqual(await gu.getPageNames(), ["Table1"]);
      assert.isTrue(await driver.find(".test-encrypted-tag").isDisplayed());
    });

    it("edits the document, computing formulas in the browser", async function() {
      await gu.getCell({ col: "A", rowNum: 1 }).click();
      await gu.enterCell("Confidential");
      await gu.getCell({ col: "B", rowNum: 1 }).click();
      await gu.enterCell("42");
      await gu.getCell({ col: "C", rowNum: 1 }).click();
      await gu.enterFormula("$A.upper() + str(int($B * 2))");
      assert.deepEqual(await gu.getVisibleGridCells({ cols: ["A", "B", "C"], rowNums: [1] }),
        ["Confidential", "42", "CONFIDENTIAL84"]);
    });

    it("stores only ciphertext on the server, in the document's file", async function() {
      const stored = await allStoredText(docId);
      assert.isAbove(stored.length, 0);
      for (const plaintext of ["Confidential", "CONFIDENTIAL", "upper", "Table1"]) {
        assert.notInclude(stored, plaintext);
      }
      // The server can't serve the document's data itself.
      await assert.isRejected(ownerApi.getDocAPI(docId).getRows("Table1"), /end-to-end encrypted/);
    });

    it("reopens the document with its content", async function() {
      await gu.reloadDoc();
      assert.deepEqual(await gu.getVisibleGridCells({ cols: ["A", "B", "C"], rowNums: [1] }),
        ["Confidential", "42", "CONFIDENTIAL84"]);
    });

    it("supports undo and redo", async function() {
      await gu.getCell({ col: "A", rowNum: 1 }).click();
      await gu.enterCell("Secret");
      await gu.waitForServer();
      assert.equal(await gu.getCell({ col: "C", rowNum: 1 }).getText(), "SECRET84");
      await gu.undo();
      assert.equal(await gu.getCell({ col: "C", rowNum: 1 }).getText(), "CONFIDENTIAL84");
      await gu.redo();
      assert.equal(await gu.getCell({ col: "C", rowNum: 1 }).getText(), "SECRET84");
    });

    it("encrypts attachments in the browser", async function() {
      // Upload a file as the attachments widgets do, and read it back as they show it.
      const result = await driver.executeAsyncScript(`
        const done = arguments[arguments.length - 1];
        const docComm = window.gristDocPageModel.gristDoc.get().docComm;
        const file = new File(["Top secret report"], "report.txt", { type: "text/plain" });
        docComm.uploadEncryptedAttachments([file])
          .then(ids => docComm.getEncryptedAttachmentUrl(ids[0]).then(url => fetch(url)).then(r => r.text())
            .then(text => done({ ids, text })))
          .catch(e => done({ error: String(e) }));
      `) as any;
      assert.isUndefined(result.error);
      assert.equal(result.text, "Top secret report");
      // The server only has it encrypted.
      const db = await SQLiteDB.openDBRaw(path.join(server.testDocDir, `${docId}.grist`));
      try {
        const files = await db.all("SELECT payload FROM _gristsys_EncryptedFiles");
        assert.lengthOf(files, 1);
        assert.notInclude(Buffer.from(files[0].payload).toString("latin1"), "Top secret");
      } finally {
        await db.close();
      }
      assert.notInclude(await allStoredText(docId), "report.txt");
    });

    it("imports files, parsing them in the browser", async function() {
      await gu.fileDialogUpload("uploads/UploadedData1.csv", async () => {
        await gu.openDocAddNewMenu();
        await driver.findWait(".test-dp-import-encrypted", 1000).click();
      });
      await gu.waitForServer();
      await driver.findContentWait(".test-treeview-itemHeader", /UploadedData1/, 10000).click();
      await gu.waitForServer();
      assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Name", "Title"], rowNums: [1, 2] }),
        ["Lily", "director", "Kathy", "student"]);
      // The server only got it encrypted.
      assert.notInclude(await allStoredText(docId), "Lily");
      assert.include(await readableWithDocKeys(docId), "Lily");
    });

    it("never sends its data to the server through the REST API", async function() {
      const result = await driver.executeAsyncScript<string[]>(`
        const done = arguments[arguments.length - 1];
        const docApi = window.gristDocPageModel.gristDoc.get().docApi;
        const file = new File(["Leaked?"], "leak.csv", { type: "text/csv" });
        Promise.allSettled([docApi.upload([file]), docApi.addRows("Table1", { A: ["Leaked?"] })])
          .then(results => done(results.map(r => r.status === "rejected" ? String(r.reason) : "sent")));
      `);
      for (const outcome of result) { assert.match(outcome, /end-to-end encrypted/); }
    });

    it("exports widgets from the browser, including to Excel", async function() {
      const bytes = await driver.executeAsyncScript(`
        const done = arguments[arguments.length - 1];
        window.gristDocPageModel.gristDoc.get().docComm.encryption
          .exportXlsx([["Table1", ["A"], [["Confidential"], [42]]]])
          .then(data => done(Array.from(data.slice(0, 2))))
          .catch(e => done(String(e)));
      `);
      // An .xlsx file is a zip file.
      assert.deepEqual(bytes, [0x50, 0x4b]);
      await driver.find(".test-tb-share").click();
      await driver.findContentWait(".test-tb-share-option", /Export as/, 2000).click();
      assert.isTrue(await driver.findContentWait(".test-tb-share-option", /Microsoft Excel \(\.xlsx\)/, 2000)
        .isDisplayed());
      await gu.sendKeys(Key.ESCAPE, Key.ESCAPE);
      await driver.wait(async () => !(await driver.find(".grist-floating-menu").isPresent()), 2000);
    });

    it("hides what the server can't do for encrypted documents", async function() {
      // No access rules, nor automations (they would need the server to read the data).
      assert.isFalse(await driver.find(".test-tools-access-rules").isPresent());
      // Sharing: no copies nor server-side downloads, but exports from the browser.
      await driver.find(".test-tb-share").click();
      const menu = await driver.findWait(".grist-floating-menu", 2000).getText();
      for (const option of ["Duplicate document", "Work on a copy", "Download document"]) {
        assert.notInclude(menu, option);
      }
      assert.include(menu, "Export as...");
      await driver.sendKeys(Key.ESCAPE);
      // Public access can't be turned on.
      await assert.isRejected(ownerApi.updateDocPermissions(docId, { users: { "everyone@getgrist.com": "viewers" } }),
        /must remain restricted/);
    });
  });

  describe("members and private columns", function() {
    let docId: string;
    const editor = gu.translateUser("user2");
    const other = gu.translateUser("user3");
    let ownerWindow: string;
    let editorWindow: string;
    let otherWindow: string;

    /** Opens the document in a new window, as the given user (windows don't share logins). */
    async function openInNewWindow(user: gu.TestUser, options: { wait?: boolean } = {}) {
      await driver.switchTo().newWindow("tab");
      const session = await gu.session().user(user).teamSite.addLogin();
      await session.loadDoc(`/doc/${docId}`, { wait: false });
      if (options.wait !== false) { await gu.waitForDocToLoad(ENGINE_LOAD_MS); }
      return driver.getWindowHandle();
    }

    async function switchTo(window: string) {
      await driver.switchTo().window(window);
    }

    before(async function() {
      const ws = (await ownerApi.getOrgWorkspaces("current"))[0].id;
      docId = await ownerApi.newDoc({ name: "Staff", options: { encryption: { version: 1 } } }, ws);
      cleanup.addAfterAll(() => ownerApi.deleteDoc(docId));
      await ownerApi.updateDocPermissions(docId, { users: { [editor.email]: "editors", [other.email]: "editors" } });

      // The owner sets up the document.
      ownerWindow = await driver.getWindowHandle();
      await owner.loadDoc(`/doc/${docId}`, { wait: false });
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      await gu.sendActions([
        ["AddTable", "Staff", [
          { id: "Name", type: "Text", isFormula: false },
          { id: "Salary", type: "Numeric", isFormula: false },
          { id: "Bonus", type: "Numeric", isFormula: false },
          { id: "Total", type: "Numeric", isFormula: true, formula: "$Salary + $Bonus" },
        ]],
        ["BulkAddRecord", "Staff", [null, null], { Name: ["Ana", "Ben"], Salary: [52100, 61300], Bonus: [700, 900] }],
      ]);
    });

    after(async function() {
      for (const window of [otherWindow, editorWindow]) {
        if (window) {
          await switchTo(window);
          await driver.close();
        }
      }
      await switchTo(ownerWindow);
    });

    it("gives the key to members, from the document's settings", async function() {
      // A member who wasn't given the key yet waits for it.
      editorWindow = await openInNewWindow("user2", { wait: false });
      await driver.findContentWait(".test-modal-dialog", /Waiting for access/, ENGINE_LOAD_MS);

      // The owner gives it to members waiting for it.
      await switchTo(ownerWindow);
      await driver.find(".test-tools-settings").click();
      await driver.findWait(".test-encryption-settings", 5000);
      await gu.waitToPass(async () => {
        assert.include(await driver.find(".test-encryption-settings").getText(), editor.email);
      });
      await driver.find(".test-encryption-grant").click();
      await driver.findContentWait(".test-notifier-toast-wrapper", /Gave access to [1-9]\d* member/, 10000);

      // The member's document opens.
      await switchTo(editorWindow);
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      await gu.openPage("Staff");
      assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Name", "Salary", "Total"], rowNums: [1, 2] }),
        ["Ana", "52100", "52800", "Ben", "61300", "62200"]);
    });

    it("lets the owner make a column private to some members", async function() {
      await switchTo(ownerWindow);
      await gu.openPage("Staff");
      await gu.waitForServer();
      await gu.openColumnPanel("Salary");
      // (Close notifications, which may cover the button.)
      for (const close of await driver.findAll(".test-notifier-toast-close")) { await close.click(); }
      await driver.findWait(".test-column-make-private", 2000).click();
      await driver.findContentWait(".test-modal-dialog label", new RegExp(`^${editor.name} `), 5000).click();
      await driver.find(".test-modal-confirm").click();
      await gu.waitForServer();
      await driver.findWait(".test-column-private", 5000);
      assert.isTrue(await gu.getColumnHeader({ col: "Salary" }).find(".test-column-private-marker").isPresent());
      assert.isTrue(await gu.getColumnHeader({ col: "Total" }).find(".test-column-private-marker").isPresent());
      assert.isFalse(await gu.getColumnHeader({ col: "Bonus" }).find(".test-column-private-marker").isPresent());
    });

    it("shows private values only to members who can read them", async function() {
      // The editor was chosen: they still see everything.
      await switchTo(editorWindow);
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Name", "Salary", "Total"], rowNums: [1] }),
          ["Ana", "52100", "52800"]);
      }, 10000);

      // The other member wasn't: they see locks.
      otherWindow = await openInNewWindow("user3");
      await gu.openPage("Staff");
      assert.deepEqual(
        await gu.getVisibleGridCells({ cols: ["Name", "Salary", "Bonus", "Total"], rowNums: [1, 2] }),
        ["Ana", "🔒", "700", "🔒", "Ben", "🔒", "900", "🔒"]);
    });

    it("never gives private values to the server, even under the document key", async function() {
      const readable = await readableWithDocKeys(docId);
      assert.include(readable, "Ana");
      for (const secret of ["52100", "61300", "52800", "62200"]) {
        assert.notInclude(readable, secret);
      }
    });

    it("refuses edits needing a calculation the member can't do", async function() {
      // Bonus is used by Total, which uses Salary: this member can't recompute it.
      await gu.wipeToasts();
      await gu.getCell({ col: "Bonus", rowNum: 1 }).click();
      await gu.enterCell("1000");
      await gu.waitToPass(async () => {
        assert.match((await gu.getToasts()).join("\n"),
          /used by a calculation you don't have access to.*has to be changed by a member/s);
      }, 5000);
      assert.equal(await gu.getCell({ col: "Bonus", rowNum: 1 }).getText(), "700");

      // Private values can't be edited at all.
      await gu.wipeToasts();
      await gu.getCell({ col: "Salary", rowNum: 1 }).click();
      await driver.sendKeys(Key.ENTER);
      await gu.waitToPass(async () => {
        assert.match((await gu.getToasts()).join("\n"), /don't have access to this private column/);
      }, 5000);
      assert.isFalse(await driver.find(".cell_editor").isPresent());
    });

    it("lets the member edit what doesn't involve private values", async function() {
      await gu.wipeToasts();
      await gu.getCell({ col: "Name", rowNum: 1 }).click();
      await gu.enterCell("Anna");
      await gu.waitForServer();
      await switchTo(ownerWindow);
      await gu.waitToPass(async () => {
        assert.equal(await gu.getCell({ col: "Name", rowNum: 1 }).getText(), "Anna");
      }, 10000);
    });

    it("keeps private values private as they change", async function() {
      await switchTo(editorWindow);
      await gu.getCell({ col: "Salary", rowNum: 2 }).click();
      await gu.enterCell("70000");
      await gu.waitForServer();
      await switchTo(ownerWindow);
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Salary", "Total"], rowNums: [2] }), ["70000", "70900"]);
      }, 10000);
      await switchTo(otherWindow);
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Name", "Salary", "Total"], rowNums: [1, 2] }),
          ["Anna", "🔒", "🔒", "Ben", "🔒", "🔒"]);
      }, 10000);
      assert.notInclude(await readableWithDocKeys(docId), "70000");
    });

    it("only lets owners holding its key make the column public again", async function() {
      // The editor holds the key, but isn't an owner: no such control for them.
      await switchTo(editorWindow);
      await gu.openColumnPanel("Salary");
      await driver.findWait(".test-column-private", 5000);
      assert.isFalse(await driver.find(".test-column-make-public").isPresent());
      // The owner can. The other member then sees the values, without reloading.
      await switchTo(ownerWindow);
      await gu.openColumnPanel("Salary");
      for (const close of await driver.findAll(".test-notifier-toast-close")) { await close.click(); }
      await driver.findWait(".test-column-make-public", 5000).click();
      await gu.waitForServer();
      await driver.findWait(".test-column-make-private", 5000);
      assert.isFalse(await gu.getColumnHeader({ col: "Total" }).find(".test-column-private-marker").isPresent());
      await switchTo(otherWindow);
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Name", "Salary", "Total"], rowNums: [1, 2] }),
          ["Anna", "52100", "52800", "Ben", "70000", "70900"]);
      }, 10000);
      assert.include(await readableWithDocKeys(docId), "70000");
    });
  });
});
