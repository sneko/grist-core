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
    // (Without what's still encrypted, as random base64 text may contain what tests look for.)
    return JSON.stringify(parts).replace(/"(data|check|wrappedKey)":"[^"]*"/g, "");
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
      // No automations (they would need the server to read the data). Access rules only explain
      // how access works (see "explains access on the Access Rules page").
      assert.isFalse(await driver.find(".test-tools-automations").isPresent());
      assert.isFalse(await driver.find(".test-tools-access-rules-trigger").isPresent());
      // Sharing: no server-side copies nor downloads, but copies and exports made by the browser.
      await driver.find(".test-tb-share").click();
      const menu = await driver.findWait(".grist-floating-menu", 2000).getText();
      for (const option of ["Work on a copy", "Download document"]) {
        assert.notInclude(menu, option);
      }
      assert.include(menu, "Duplicate document");
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
      // (The editor is added later, to see them wait for the key.)
      await ownerApi.updateDocPermissions(docId, { users: { [other.email]: "editors" } });

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

    it("lets owners accept members waiting for the key, from the sharing dialog", async function() {
      // A member added while the owner has the document open waits for the key.
      await ownerApi.updateDocPermissions(docId, { users: { [editor.email]: "editors" } });
      editorWindow = await openInNewWindow("user2", { wait: false });
      await driver.findContentWait(".test-modal-dialog", /Waiting for access/, ENGINE_LOAD_MS);
      // Meanwhile, the page says the document is being opened.
      assert.match(await driver.find(".test-encrypted-doc-loader").getText(), /Opening the encrypted document/);

      // The owner accepts them in the sharing dialog (they enabled encryption), along with
      // members added before.
      await switchTo(ownerWindow);
      await driver.find(".test-tb-share").click();
      await driver.findContentWait(".test-tb-share-option", /Manage users/, 2000).click();
      await acceptAllInSharingDialog();

      // The member's document opens.
      await switchTo(editorWindow);
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      assert.isFalse(await driver.find(".test-encrypted-doc-loader").isPresent());
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
      // Who can read it, the owner first noted as such.
      await gu.waitToPass(async () => {
        const audience = await driver.findAll(".test-column-audience-member", e => e.getText());
        assert.include(audience, "Chimpy (you)");
      }, 5000);
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
      // Bonus is used by Total, which uses Salary: this member can't recompute it. They're told
      // so as they start typing, and its cells show it, as locked ones do.
      assert.equal(await gu.getCell({ col: "Bonus", rowNum: 1 }).getCssValue("cursor"), "not-allowed");
      assert.notEqual(await gu.getCell({ col: "Name", rowNum: 1 }).getCssValue("cursor"), "not-allowed");
      await gu.wipeToasts();
      await gu.getCell({ col: "Bonus", rowNum: 1 }).click();
      await driver.sendKeys("1");
      await gu.waitToPass(async () => {
        assert.match((await gu.getToasts()).join("\n"),
          /used by a calculation you don't have access to.*has to be changed by a member/s);
      }, 5000);
      assert.isFalse(await driver.find(".cell_editor").isPresent());
      assert.equal(await gu.getCell({ col: "Bonus", rowNum: 1 }).getText(), "700");
      // Changes made without the editor (e.g. pasting, clearing) are refused all the same.
      await gu.wipeToasts();
      await driver.sendKeys(Key.DELETE);
      await gu.waitToPass(async () => {
        assert.match((await gu.getToasts()).join("\n"), /used by a calculation you don't have access to/);
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

    it("lets the owner make a whole table private", async function() {
      await switchTo(ownerWindow);
      await gu.sendActions([
        ["AddTable", "Payroll", [{ id: "Who", type: "Text", isFormula: false },
          { id: "Amount", type: "Numeric", isFormula: false }]],
        ["BulkAddRecord", "Payroll", [null, null], { Who: ["Ana", "Ben"], Amount: [3100, 4200] }],
      ]);
      // The other member sees it while it isn't private yet.
      await switchTo(otherWindow);
      await gu.openPage("Payroll");
      await gu.waitToPass(async () => {
        assert.equal(await gu.getCell({ col: "Who", rowNum: 1 }).getText(), "Ana");
      }, 10000);
      await switchTo(ownerWindow);
      await gu.openPage("Payroll");
      await gu.openWidgetPanel("data");
      for (const close of await driver.findAll(".test-notifier-toast-close")) { await close.click(); }
      await driver.findWait(".test-table-make-private", 5000).click();
      // Readable by the owner and the editor.
      await driver.findContentWait(".test-modal-dialog label", new RegExp(`^${editor.name} `), 5000).click();
      await driver.find(".test-modal-confirm").click();
      await driver.findWait(".test-table-private", 10000);
      assert.includeMembers(await driver.findAll(".test-table-audience-member", e => e.getText()), ["Chimpy (you)"]);
      // A column added later is private too, and its settings say why.
      await gu.sendActions([["AddVisibleColumn", "Payroll", "Note", { type: "Text", isFormula: false }],
        ["UpdateRecord", "Payroll", 1, { Note: "raise" }]]);
      await gu.openColumnPanel("Note");
      await driver.findWait(".test-column-private-table", 5000);
      // The table shows a lock in its title, rather than one on each column, and so does its page
      // (in the list of pages, and next to its name at the top).
      assert.isTrue(await driver.find(".test-table-private-marker").isDisplayed());
      assert.lengthOf(await driver.findAll(".test-column-private-marker"), 0);
      const pagesWithLock = await driver.findAll(".test-treeview-itemHeader", async e =>
        (await e.find(".test-page-private-marker").isPresent()) ? e.find(".test-docpage-label").getText() : null);
      assert.deepEqual(pagesWithLock.filter(Boolean), ["Payroll"]);
      assert.lengthOf(await driver.findAll(".test-page-private-marker"), 2);

      // A column of it can be restricted further, to some of the table's members (here, the owner
      // alone): only that column gets a lock.
      await gu.wipeToasts();
      await driver.find(".test-column-make-private").click();
      await driver.findWait(".test-modal-dialog", 2000);
      await gu.waitToPass(async () => {
        assert.deepEqual(await driver.findAll(".test-modal-dialog label", e => e.getText()),
          [`${editor.name} (${editor.email})`]);
      }, 5000);
      await driver.find(".test-modal-confirm").click();
      await driver.findWait(".test-column-private-in-table", 10000);
      await gu.waitToPass(async () => {
        assert.deepEqual(await driver.findAll(".test-column-private-marker",
          e => e.findClosest(".column_name").getText()), ["Note"]);
      }, 5000);

      await switchTo(editorWindow);
      await gu.openPage("Payroll");
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Who", "Amount", "Note"], rowNums: [1] }),
          ["Ana", "3100", "🔒"]);
      }, 10000);
      // The other member sees it locked right away (values they had received before included),
      // and still after opening it again.
      await switchTo(otherWindow);
      await gu.openPage("Payroll");
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Who", "Amount", "Note"], rowNums: [1, 2] }),
          ["🔒", "🔒", "🔒", "🔒", "🔒", ""]);
      }, 10000);
      // Their columns have no lock of their own: all of the table is locked for them alike.
      assert.lengthOf(await driver.findAll(".test-column-private-marker"), 0);
      assert.notMatch((await gu.getToasts()).join("\n"), /given access/);
      await driver.navigate().refresh();
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      await gu.openPage("Payroll");
      // (Making Note private saved its values encrypted, including empty ones.)
      assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Who", "Amount", "Note"], rowNums: [1, 2] }),
        ["🔒", "🔒", "🔒", "🔒", "🔒", "🔒"]);
      const readable = await readableWithDocKeys(docId);
      for (const secret of ["3100", "4200", "raise"]) {
        assert.notInclude(readable, secret);
      }
    });

    it("explains access on the Access Rules page", async function() {
      // Members see private tables and columns, with who can read them.
      await switchTo(otherWindow);
      await driver.find(".test-tools-access-rules").click();
      await driver.findWait(".test-acl-encrypted", 5000);
      assert.match(await driver.find(".test-acl-encrypted").getText(), /server can't read its data/);
      await driver.findContentWait(".test-acl-encrypted-target", /^Payroll$/, 5000);
      assert.lengthOf(await driver.findAll(".test-acl-encrypted-no-access"), 2);
      assert.isFalse(await driver.find(".test-acl-encrypted-settings").isPresent());

      // Owners also see the members who can read, and get to the settings.
      await switchTo(ownerWindow);
      await driver.find(".test-tools-access-rules").click();
      await driver.findContentWait(".test-acl-encrypted-target", /^Payroll$/, 5000);
      await gu.waitToPass(async () => {
        // (Those of the table, and those of its restricted column.)
        assert.deepEqual((await driver.findAll(".test-acl-encrypted-member", e => e.getText())).sort(),
          ["Chimpy (you)", "Chimpy (you)", editor.name].sort());
      }, 5000);
      assert.isTrue(await driver.find(".test-acl-encrypted-settings").isPresent());
      await driver.find(".test-acl-encrypted-open").click();
      await driver.findWait(".test-table-private", 5000);
      await driver.find(".test-raw-data-close-button").click();
      await gu.waitToPass(async () => assert.isFalse(await driver.find(".test-raw-data-close-button").isPresent()));

      // A private column is listed too, and leads to the column's settings.
      await gu.openPage("Staff");
      await gu.openColumnPanel("Salary");
      for (const close of await driver.findAll(".test-notifier-toast-close")) { await close.click(); }
      await driver.findWait(".test-column-make-private", 5000).click();
      await driver.find(".test-modal-confirm").click();
      await driver.findWait(".test-column-private", 10000);
      await driver.find(".test-tools-access-rules").click();
      await driver.findContentWait(".test-acl-encrypted-target", /^Staff › Salary$/, 5000);
      assert.deepEqual(await driver.findAll(".test-acl-encrypted-target", e => e.getText()),
        ["Payroll", "Payroll › Note", "Staff › Salary"]);
      await driver.findAll(".test-acl-encrypted-open").then(opens => opens[2].click());
      await driver.findWait(".test-column-private", 5000);
      assert.equal(await driver.find(".test-field-label").value(), "Salary");
      await driver.find(".test-raw-data-close-button").click();
    });

    it("removes members from a table's restricted columns along with the table", async function() {
      await switchTo(ownerWindow);
      await gu.openPage("Payroll");
      // The editor gets the restricted Note column too.
      await gu.openColumnPanel("Note");
      await gu.wipeToasts();
      await driver.findWait(".test-column-change-audience", 5000).click();
      await driver.findContentWait(".test-modal-dialog label", new RegExp(`^${editor.name} `), 5000).click();
      await driver.find(".test-modal-confirm").click();
      await gu.waitToPass(async () => {
        assert.sameMembers(await driver.findAll(".test-column-audience-member", e => e.getText()),
          ["Chimpy (you)", editor.name]);
      }, 10000);
      // They're told, and see it once they reload (values they had locked come with the document).
      await switchTo(editorWindow);
      await gu.waitToPass(async () => {
        assert.match((await gu.getToasts()).join("\n"), /given access to more of this document/);
      }, 10000);
      assert.isTrue(await driver.findContent(".test-notifier-toast-custom-action", /Reload to see it/).isDisplayed());
      // (Reloading as the editor: windows share their login with the last one opened.)
      const session = await gu.session().user("user2").teamSite.addLogin();
      await session.loadDoc(`/doc/${docId}`, { wait: false });
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      await gu.openPage("Payroll");
      await gu.waitToPass(async () => {
        assert.equal(await gu.getCell({ col: "Note", rowNum: 1 }).getText(), "raise");
      }, 10000);

      // Removed from the table, they lose its restricted column too, and see it all locked.
      await switchTo(ownerWindow);
      await gu.openWidgetPanel("data");
      await gu.wipeToasts();
      await driver.findWait(".test-table-change-audience", 5000).click();
      await driver.findContentWait(".test-modal-dialog label", new RegExp(`^${editor.name} `), 5000).click();
      await driver.find(".test-modal-confirm").click();
      await gu.waitToPass(async () => {
        assert.deepEqual(await driver.findAll(".test-table-audience-member", e => e.getText()), ["Chimpy (you)"]);
      }, 10000);
      await gu.openColumnPanel("Note");
      await gu.waitToPass(async () => {
        assert.deepEqual(await driver.findAll(".test-column-audience-member", e => e.getText()), ["Chimpy (you)"]);
      }, 10000);
      await switchTo(editorWindow);
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ cols: ["Who", "Amount", "Note"], rowNums: [1] }),
          ["🔒", "🔒", "🔒"]);
      }, 10000);
    });

    it("shows answers to forms waiting for a member who can read their private columns", async function() {
      // The owner publishes a form filling Salary (private to them), then closes the document.
      await switchTo(ownerWindow);
      await gu.openPage("Staff");
      await gu.addNewSection("Form", "Staff");
      await driver.findWait(".test-forms-publish", 5000).click();
      if (await driver.find(".test-modal-confirm").isPresent()) { await driver.find(".test-modal-confirm").click(); }
      await gu.waitForServer();
      const shareButton = await driver.findWait(".test-forms-share", 5000);
      await gu.scrollIntoView(shareButton);
      await shareButton.click();
      const formUrl = await driver.findWait(".test-forms-link", 5000).getAttribute("value");
      await gu.sendKeys(Key.ESCAPE);
      await driver.get("about:blank");

      await gu.onNewTab(async () => {
        await driver.get(formUrl);
        await driver.findWait('input[name="Name"]', 10000).click();
        await gu.sendKeys("Cleo");
        await driver.find('input[name="Salary"]').click();
        await gu.sendKeys("48000");
        await driver.find('button[type="submit"]').click();
        await driver.findWait(".test-form-success-page", 10000);
      });

      // The editor can't read Salary: their browser leaves the answer, and says why.
      await switchTo(editorWindow);
      await gu.openPage("Staff");
      // On the form, and on the table it fills.
      await gu.waitToPass(async () => {
        assert.deepEqual(await driver.findAll(".test-waiting-answers", e => e.getText()), [
          "1 form answer is waiting. Only editors or owners with access to the column Staff › Salary can add it.",
          "1 form answer is waiting. Only editors or owners with access to the column Staff › Salary can add it.",
        ]);
      }, 10000);

      // Once the owner opens the document, their browser adds it.
      await switchTo(ownerWindow);
      const session = await gu.session().user("user1").teamSite.addLogin();
      await session.loadDoc(`/doc/${docId}`, { wait: false });
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      await switchTo(editorWindow);
      await gu.waitToPass(async () => {
        assert.isFalse(await driver.find(".test-waiting-answers").isPresent());
        assert.include(await gu.getVisibleGridCells({ section: "STAFF", cols: ["Name"], rowNums: [1, 2, 3] }),
          "Cleo");
      }, 20000);
    });
  });

  describe("whole documents", function() {
    let docId: string;
    let copyId: string;

    /** Waits for the page to reload and show the document (encrypted or not) with the given values in column A. */
    async function waitForValues(values: string[]) {
      await gu.waitToPass(async () => {
        await gu.openPage("Table1");
        assert.deepEqual(await gu.getVisibleGridCells({
          section: "TABLE1", cols: ["A"], rowNums: values.map((_, i) => i + 1),
        }), values);
      }, ENGINE_LOAD_MS);
    }

    before(async function() {
      // (Earlier tests signed in other members: sign in again, for real.)
      owner = await gu.session().user("user1").teamSite.login({});
      const ws = (await ownerApi.getOrgWorkspaces("current"))[0].id;
      docId = await ownerApi.newDoc({ name: "To encrypt" }, ws);
      cleanup.addAfterAll(() => ownerApi.deleteDoc(docId));
      await ownerApi.getDocAPI(docId).addRows("Table1", { A: ["alpha", "beta"], B: ["secret1", "secret2"] });
      // An access rule hides B from a member.
      const member = gu.translateUser("user3");
      await ownerApi.updateDocPermissions(docId, { users: { [member.email]: "viewers" } });
      await ownerApi.getDocAPI(docId).applyUserActions([
        ["AddRecord", "_grist_ACLResources", -1, { tableId: "Table1", colIds: "B" }],
        ["AddRecord", "_grist_ACLRules", null, { resource: -1, rulePos: 1,
          aclFormula: `user.Email == '${member.email}'`, permissionsText: "-R" }],
      ]);
    });

    it("encrypts a regular document, from its settings", async function() {
      await owner.loadDoc(`/doc/${docId}`);
      await driver.find(".test-tools-settings").click();
      await driver.findWait(".test-encryption-encrypt", 5000).click();
      await driver.findWait(".test-modal-confirm", 2000).click();
      // Once done, it says what became of the access rule.
      await driver.findContentWait(".test-modal-dialog", /1 column\(s\) hidden by access rules are now private/, 30000);
      assert.deepEqual((await ownerApi.getDoc(docId)).options?.encryption, { version: 1 });
      await driver.find(".test-encryption-summary-ok").click();
      await gu.waitToPass(async () => {
        assert.isTrue(await driver.find(".test-encrypted-tag").isDisplayed());
      }, ENGINE_LOAD_MS);
      await waitForValues(["alpha", "beta"]);
      assert.notInclude(await allStoredText(docId), "alpha");
      await assert.isRejected(ownerApi.getDocAPI(docId).getRows("Table1"), /end-to-end encrypted/);
      // The column hidden by the rule is private, sealed even under the document key.
      assert.isTrue(await gu.getColumnHeader({ col: "B" }).find(".test-column-private-marker").isPresent());
      assert.deepEqual(await gu.getVisibleGridCells({ section: "TABLE1", cols: ["B"], rowNums: [1, 2] }),
        ["secret1", "secret2"]);
      assert.notInclude(await readableWithDocKeys(docId), "secret1");
    });

    it("duplicates an encrypted document, in the browser", async function() {
      await driver.find(".test-tb-share").click();
      await driver.findWait(".test-encrypted-copy", 2000).click();
      const name = await driver.findWait(".test-encrypted-copy-name", 2000);
      await name.doClear();
      await name.sendKeys("Encrypted copy");
      await driver.find(".test-modal-confirm").click();
      await gu.waitToPass(async () => {
        const id = (await ownerApi.getDoc((await gu.getCurrentUrlId())!)).id;
        assert.notEqual(id, docId);
        copyId = id;
      }, 30000);
      cleanup.addAfterAll(() => ownerApi.deleteDoc(copyId));
      await waitForValues(["alpha", "beta"]);
      // Private columns stay private.
      assert.isTrue(await gu.getColumnHeader({ col: "B" }).find(".test-column-private-marker").isPresent());
      assert.deepEqual(await gu.getVisibleGridCells({ section: "TABLE1", cols: ["B"], rowNums: [1, 2] }),
        ["secret1", "secret2"]);
      assert.notInclude(await readableWithDocKeys(copyId), "secret1");
      const copy = await ownerApi.getDoc(copyId);
      assert.equal(copy.name, "Encrypted copy");
      assert.deepEqual(copy.options?.encryption, { version: 1 });
      assert.notInclude(await allStoredText(copyId), "alpha");
    });

    it("restores earlier versions", async function() {
      await owner.loadDoc(`/doc/${docId}`, { wait: false });
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      await gu.openPage("Table1");
      await gu.getCell({ col: "A", rowNum: 1 }).click();
      await gu.enterCell("gamma");
      await gu.waitForServer();
      // Removing a member who could read it replaces keys on the next edit, which saves a version
      // under the new keys.
      await ownerApi.updateDocPermissions(docId, { users: { [gu.translateUser("user3").email]: null } });
      await listMembers();
      await gu.getCell({ col: "A", rowNum: 1 }).click();
      await gu.enterCell("delta");
      await gu.waitForServer();

      await driver.find(".test-tools-log").click();
      await driver.findContentWait(".test-doc-history-tabs .test-select-button", /Snapshots/, 2000).click();
      await gu.waitToPass(async () => {
        assert.lengthOf(await driver.findAll(".test-encrypted-snapshot"), 2);
      }, 5000);
      // The oldest one is the encrypted document as first saved.
      const snapshots = await driver.findAll(".test-encrypted-snapshot");
      await snapshots[1].find(".test-encrypted-snapshot-restore").click();
      await driver.findWait(".test-modal-confirm", 2000).click();
      await waitForValues(["alpha", "beta"]);
    });

    it("takes answers to forms, encrypted for the document's members", async function() {
      await gu.addNewSection("Form", "Table1");
      await driver.findWait(".test-forms-publish", 5000).click();
      if (await driver.find(".test-modal-confirm").isPresent()) {
        await driver.find(".test-modal-confirm").click();
      }
      await gu.waitForServer();
      const shareButton = await driver.findWait(".test-forms-share", 5000);
      await gu.scrollIntoView(shareButton);
      await shareButton.click();
      const formUrl = await driver.findWait(".test-forms-link", 5000).getAttribute("value");
      assert.match(formUrl, /\/forms\/encrypted\.[A-Za-z0-9]+\.[0-9a-f]{32}\/\d+#[\w-]+$/);
      await gu.sendKeys(Key.ESCAPE);
      // Without the key in its link (or with another one), the form can't be read.
      for (const brokenUrl of [formUrl.split("#")[0], formUrl.replace(/#.*/, "#" + "A".repeat(43))]) {
        await gu.onNewTab(async () => {
          await driver.get(brokenUrl);
          await driver.findWait(".test-form-error-page-text", 10000);
          assert.isFalse(await driver.find('input[name="A"]').isPresent());
        });
      }
      await gu.onNewTab(async () => {
        await driver.get(formUrl);
        await driver.findWait('input[name="A"]', 10000).click();
        await gu.sendKeys("from the form");
        await driver.find('button[type="submit"]').click();
        await driver.findWait(".test-form-success-page", 10000);
      });
      // The owner's browser, which has the document open, adds the answer.
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ section: "TABLE1", cols: ["A"], rowNums: [1, 2, 3] }),
          ["alpha", "beta", "from the form"]);
      }, 20000);
      assert.notInclude(await allStoredText(docId), "from the form");

      // A question can be made private from the form: respondents still answer it, and the form
      // follows (it's published again), but only members who can read it get the answers.
      // (Document history was left open in the right panel.)
      if (await driver.find(".test-right-tool-close").isPresent()) {
        await driver.find(".test-right-tool-close").click();
      }
      await driver.findContent(".active_section .test-forms-label", /^C\*?$/).click();
      await gu.openColumnPanel();
      await gu.wipeToasts();
      await driver.findWait(".test-panel-question-privacy .test-column-make-private", 5000).click();
      await driver.findWait(".test-modal-confirm", 2000).click();
      await driver.findWait(".test-question-private", 10000);
      await gu.onNewTab(async () => {
        await gu.waitToPass(async () => {
          await driver.get(formUrl);
          await driver.findWait('input[name="C"]', 5000);
        }, 20000);
        await driver.find('input[name="A"]').click();
        await gu.sendKeys("second");
        await driver.find('input[name="C"]').click();
        await gu.sendKeys("private answer");
        await driver.find('button[type="submit"]').click();
        await driver.findWait(".test-form-success-page", 10000);
      });
      await gu.waitToPass(async () => {
        assert.deepEqual(await gu.getVisibleGridCells({ section: "TABLE1", cols: ["A", "C"], rowNums: [4] }),
          ["second", "private answer"]);
      }, 20000);
      assert.notInclude(await readableWithDocKeys(docId), "private answer");
      // (Back to how it was, for what follows.)
      await driver.findContent(".active_section .test-forms-label", /^C\*?$/).click();
      await driver.findWait(".test-panel-question-privacy .test-column-make-public", 5000).click();
      await gu.waitForServer();
    });

    it("makes an encrypted document regular again", async function() {
      await driver.find(".test-tools-settings").click();
      for (const close of await driver.findAll(".test-notifier-toast-close")) { await close.click(); }
      await driver.findWait(".test-encryption-decrypt", 5000).click();
      await driver.findWait(".test-modal-confirm", 2000).click();
      await gu.waitToPass(async () => {
        assert.isNull((await ownerApi.getDoc(docId)).options?.encryption ?? null);
      }, 30000);
      assert.deepEqual((await ownerApi.getDocAPI(docId).getRows("Table1")).A,
        ["alpha", "beta", "from the form", "second"]);
      // It reopens as a regular document.
      await gu.waitToPass(async () => {
        assert.isTrue(await driver.find(".test-encryption-encrypt").isDisplayed());
      }, 20000);
      assert.isFalse(await driver.find(".test-encrypted-tag").isPresent());
    });
  });

  describe("suggestions", function() {
    let docId: string;
    const viewer = gu.translateUser("user3");
    let ownerWindow: string;
    let viewerWindow: string;

    before(async function() {
      const ws = (await ownerApi.getOrgWorkspaces("current"))[0].id;
      owner = await gu.session().user("user1").teamSite.login({});
      docId = await ownerApi.newDoc({ name: "Suggest", options: { encryption: { version: 1 } } }, ws);
      cleanup.addAfterAll(() => ownerApi.deleteDoc(docId));
      await ownerApi.updateDocPermissions(docId, { users: { [viewer.email]: "viewers" } });
      await ownerApi.updateDoc(docId, { options: { proposedChanges: { acceptProposals: true } } });
      ownerWindow = await driver.getWindowHandle();
      await owner.loadDoc(`/doc/${docId}`, { wait: false });
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
      await gu.sendActions([["BulkAddRecord", "Table1", [null], { A: ["draft"] }]]);
      // Opening it, the owner is told the viewer waits to be accepted, and accepts them.
      await driver.findContentWait(".test-notifier-toast-wrapper", /waiting for you to accept them/, 10000);
      await driver.findContent(".test-notifier-toast-custom-action", /Review/i).click();
      await acceptAllInSharingDialog();
      await driver.switchTo().newWindow("tab");
      viewerWindow = await driver.getWindowHandle();
      const session = await gu.session().user("user3").teamSite.addLogin();
      await session.loadDoc(`/doc/${docId}`, { wait: false });
      await gu.waitForDocToLoad(ENGINE_LOAD_MS);
    });

    after(async function() {
      if (viewerWindow) {
        await driver.switchTo().window(viewerWindow);
        await driver.close();
      }
      await driver.switchTo().window(ownerWindow);
    });

    it("lets viewers suggest changes, which owners apply", async function() {
      // The viewer edits: it's a suggestion, made in their browser only.
      await gu.getCell({ col: "A", rowNum: 1 }).click();
      await gu.enterCell("final");
      await gu.waitForServer();
      assert.equal(await gu.getCell({ col: "A", rowNum: 1 }).getText(), "final");
      await driver.switchTo().window(ownerWindow);
      await gu.openPage("Table1");
      assert.equal(await gu.getCell({ col: "A", rowNum: 1 }).getText(), "draft");

      await driver.switchTo().window(viewerWindow);
      await driver.findContent(".test-tb-share-action", /Send suggestion/).click();
      await driver.findWait(".test-suggestion-desc", 2000).sendKeys("Ready");
      await driver.find(".test-modal-confirm").click();
      await gu.waitToPass(async () => {
        assert.equal(await gu.getCell({ col: "A", rowNum: 1 }).getText(), "draft");
      });

      await driver.switchTo().window(ownerWindow);
      await driver.find(".test-tools-encrypted-suggestions").click();
      await driver.findContentWait(".test-suggestion", /Ready/, 5000);
      await driver.find(".test-suggestion-apply").click();
      await gu.waitForServer();
      await gu.waitToPass(async () => {
        assert.isFalse(await driver.find(".test-suggestion").isPresent());
      });
      await gu.sendKeys(Key.ESCAPE);
      assert.equal(await gu.getCell({ col: "A", rowNum: 1 }).getText(), "final");
      await driver.switchTo().window(viewerWindow);
      await gu.waitToPass(async () => {
        assert.equal(await gu.getCell({ col: "A", rowNum: 1 }).getText(), "final");
      }, 10000);
      await driver.switchTo().window(ownerWindow);
    });
  });

  describe("account", function() {
    it("shows whether encryption is enabled on the account", async function() {
      await gu.session().user("user1").teamSite.login();
      await gu.openProfileSettingsPage();
      assert.equal(await driver.findWait(".test-account-page-encryption-status", 5000).getText(), "Enabled");
    });
  });
});

// In the sharing dialog: accepts all members waiting for the key (at least one), then closes it.
async function acceptAllInSharingDialog() {
  await driver.findWait(".test-um-member-accept-encryption", 5000);
  while (await driver.find(".test-um-member-accept-encryption").isPresent()) {
    const count = (await driver.findAll(".test-um-member-accept-encryption")).length;
    await driver.find(".test-um-member-accept-encryption").click();
    await gu.waitToPass(async () => {
      assert.lengthOf(await driver.findAll(".test-um-member-accept-encryption"), count - 1);
    }, 10000);
  }
  await driver.find(".test-um-cancel").click();
}

// Lists members, which takes keys away from those who lost access (as the sharing dialog does).
async function listMembers() {
  const result = await driver.executeAsyncScript(`
    const done = arguments[arguments.length - 1];
    window.gristDocPageModel.gristDoc.get().docComm.encryption.listMembers()
      .then(() => done({})).catch(e => done({ error: String(e) }));
  `) as any;
  assert.isUndefined(result.error);
}
