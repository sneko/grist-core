/**
 * Converts documents to and from end-to-end encryption, at the request of an owner who can read
 * all of their content. The browser does the encryption (or decryption), as the server can't, but
 * the server stores the result, and makes the switch:
 *
 * Encrypting a regular document (beginDocEncryption, commitDocEncryption):
 *  1. The document gets locked (see docLocks.ts): its members are disconnected from it, and can't
 *     open it again until it's done (they're told it's in progress, and it reopens once done).
 *  2. The server returns its content (all tables, as the browser's data engine loads them), and
 *     its attachments. The browser encrypts them with a new document key, and uploads them into a
 *     file next to the document's ("<doc>.encrypting.tmp"), as for any encrypted document.
 *  3. Once all is uploaded, the server saves the snapshot of the new document in that file, then
 *     records the document key, and that the document is encrypted, in the home database, then
 *     replaces the document's file with the new one. If interrupted before the home database is
 *     updated, the new file is dropped; after, it's moved in place on the next opening (see
 *     finishPendingConversion()).
 *  4. Earlier versions of the document kept by the storage (e.g. S3 versions) are deleted: they
 *     hold its content in clear.
 *
 * Decrypting an encrypted document (beginDocDecryption, uploadDecryptedFile, commitDocDecryption)
 * goes the same way the other way round: the document is locked (browsers that have it open show
 * it), the browser sends its decrypted content (with access rules replacing private columns, so
 * that members don't get to see values they couldn't read) and attachments, which the server
 * writes as a regular document in "<doc>.decrypting.tmp"; then the home database is updated (no
 * longer encrypted, keys dropped), the file replaced, and earlier (encrypted) versions deleted.
 */
import { ApiError } from "app/common/ApiError";
import { TableDataAction } from "app/common/DocActions";
import { marshalValue, unmarshalValue } from "app/common/encryption/EncryptedPayloads";
import { gunzip, gzip } from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, DocKeyRecord, EncryptionMember, isEncryptedDoc, isValidTarget, PayloadSource, tableTarget,
} from "app/common/encryption/EncryptionTypes";
import { schema } from "app/common/schema";
import { Document } from "app/gen-server/entity/Document";
import { Share } from "app/gen-server/entity/Share";
import { HomeDBManager } from "app/gen-server/lib/homedb/HomeDBManager";
import { GristObjCode } from "app/plugin/GristData";
import { ActiveDoc } from "app/server/lib/ActiveDoc";
import { Client } from "app/server/lib/Client";
import { Comm } from "app/server/lib/Comm";
import { DocAuthorizer, DocAuthorizerImpl } from "app/server/lib/DocAuthorizer";
import { DocManager } from "app/server/lib/DocManager";
import { makeExceptionalDocSession, OptDocSession } from "app/server/lib/DocSession";
import { DocStorage } from "app/server/lib/DocStorage";
import { DocLock, getDocLock } from "app/server/lib/encryption/docLocks";
import {
  DECRYPTING_SUFFIX, EncryptedDocFile, ENCRYPTING_SUFFIX, finishPendingConversion, INCOMPLETE_SUFFIX,
  MAX_INLINE_BYTES,
} from "app/server/lib/encryption/EncryptedDocStorage";
import { EncryptionRelay } from "app/server/lib/encryption/EncryptionRelay";
import { EncryptionStore } from "app/server/lib/encryption/EncryptionStore";
import { IDocStorageManager } from "app/server/lib/IDocStorageManager";
import { GRIST_DOC_SQL } from "app/server/lib/initialDocSql";
import log from "app/server/lib/log";

import * as crypto from "crypto";

import * as fse from "fs-extra";

/**
 * A column or table that access rules hide from some members, which becomes private to those who
 * can read it (see beginEncryption()). colRef is a binding target (see tableTarget()).
 */
export interface ColumnAudience {
  colRef: number;
  userIds: number[];
}

/** A column key created along with the document key, when encrypting a document. */
export interface NewColumnKey {
  scope: string;
  keyId: string;
  colRef: number;
  wraps: DocKeyRecord[];
}

/** What beginDocEncryption returns. */
export interface DocEncryptionStart {
  // The document's content (marshalled, compressed {tables}), fetched by parts with
  // fetchConversionData().
  size: number;
  attachments: { rowId: number, size: number }[];
  // Members of the document (who can be given its key).
  members: Omit<EncryptionMember, "keyIds">[];
  // Columns and tables that access rules hide from some members: they become private to the others.
  columnAudiences: ColumnAudience[];
  // How many access rules were about something else than reading (e.g. limiting edits), which
  // encrypted documents can't enforce.
  droppedRules: number;
}

// User tables are written by batches of this many rows when decrypting.
const ROWS_PER_BATCH = 5000;

interface EncryptingState {
  lock: DocLock;
  activeDoc: ActiveDoc;
  data: Uint8Array;
  staging: EncryptedDocFile;
  stagingPath: string;
}

interface DecryptingState {
  lock: DocLock;
  staging: DocStorage;
  stagingPath: string;
}

export class EncryptionConversion {
  private _keys: EncryptionStore;
  private _encrypting = new Map<string, EncryptingState>();
  private _decrypting = new Map<string, DecryptingState>();

  constructor(private _dbManager: HomeDBManager, private _storageManager: IDocStorageManager,
    private _docManager: DocManager, private _relay: EncryptionRelay) {
    this._keys = new EncryptionStore(_dbManager);
    _relay.conversions = this;
  }

  public registerCommMethods(comm: Comm) {
    comm.registerMethods({
      beginDocEncryption: (client: Client, docId: string) => this.beginEncryption(client, docId),
      fetchConversionData: (client: Client, docId: string, offset: number, length: number) =>
        this.fetchData(client, docId, offset, length),
      fetchConversionFile: (client: Client, docId: string, rowId: number, offset: number, length: number) =>
        this.fetchFile(client, docId, rowId, offset, length),
      commitDocEncryption: (client: Client, docId: string, keyId: string, wraps: DocKeyRecord[],
        snapshot: PayloadSource, columnKeys?: NewColumnKey[]) =>
        this.commitEncryption(client, docId, keyId, wraps, snapshot, columnKeys),
      beginDocDecryption: (client: Client, docId: string) => this.beginDecryption(client, docId),
      uploadDecryptedFile: (client: Client, docId: string, ext: string, payload: PayloadSource) =>
        this.uploadDecryptedFile(client, docId, ext, payload),
      commitDocDecryption: (client: Client, docId: string, baseActionNum: number, tables: PayloadSource) =>
        this.commitDecryption(client, docId, baseActionNum, tables),
      abortDocConversion: (client: Client, docId: string) => this.abort(client, docId),
    });
  }

  /** The file to store uploads in, for a document being encrypted by this client (if it is). */
  public getStagingFile(client: Client, docId: string): EncryptedDocFile | undefined {
    const state = this._encrypting.get(docId);
    if (state?.lock.client !== client) { return undefined; }
    state.lock.renew?.();
    return state.staging;
  }

  public async beginEncryption(client: Client, docId: string): Promise<DocEncryptionStart> {
    const auth = new DocAuthorizerImpl({
      dbManager: this._dbManager, urlId: docId, openMode: "default", authSession: client.authSession,
    });
    await auth.assertAccess("owners");
    const doc = auth.getCachedAuth().cachedDoc;
    if (auth.getCachedAuth().docId !== docId || !doc) { throw new ApiError("Invalid document", 400); }
    if (isEncryptedDoc(doc)) { throw new ApiError("Document is already encrypted", 400); }
    if (doc.trunkId) { throw new ApiError("Copies made to suggest changes can't be encrypted", 400); }
    if (!client.authSession.userId) { throw new ApiError("Encryption keys require being logged in", 401); }
    const forks = await this._dbManager.connection.manager.count(Document, { where: { trunkId: docId } });
    if (forks > 0) {
      throw new ApiError("This document has copies made to suggest changes: remove them first", 400);
    }

    const session = makeExceptionalDocSession("system");
    const lock = this._relay.lock(client, docId, "encrypting", { onRelease: () => this._dropEncrypting(docId) });
    lock.session = session;
    try {
      // Disconnect members who have it open (they can't open it again while it's locked).
      const open = this._docManager.getActiveDoc(docId);
      if (open) { await (await open).shutdown(); }
      const activeDoc = await this._docManager.fetchDoc(session, docId);
      await activeDoc.waitForInitialization();
      const members = await this._relay.getMembers(client, docId);
      const { columnAudiences, droppedRules } = await this._convertAccessRules(activeDoc, client, auth, members);
      const tables = await this._fetchAllTables(activeDoc);
      const data = await gzip(marshalValue({ tables }));

      const stagingPath = this._storageManager.getPath(docId) + ENCRYPTING_SUFFIX + INCOMPLETE_SUFFIX;
      await fse.remove(stagingPath);
      const staging = await EncryptedDocFile.open(stagingPath);
      this._encrypting.set(docId, { lock, activeDoc, data, staging, stagingPath });
      this._assertStillLocked(docId, lock);

      const attachments = activeDoc.docData!.getMetaTable("_grist_Attachments").getRecords();
      return {
        size: data.length,
        attachments: attachments.map(a => ({ rowId: a.id, size: a.fileSize })),
        members,
        columnAudiences,
        droppedRules,
      };
    } catch (e) {
      this._relay.unlock(docId, lock);
      throw e;
    }
  }

  /** Returns part of the content of a document being encrypted (see beginEncryption()). */
  public async fetchData(client: Client, docId: string, offset: number, length: number): Promise<Base64> {
    const state = this._getEncrypting(client, docId);
    checkRange(offset, length);
    return Buffer.from(state.data.subarray(offset, offset + length)).toString("base64");
  }

  /** Returns part of an attachment of a document being encrypted, with its size. */
  public async fetchFile(client: Client, docId: string, rowId: number, offset: number,
    length: number): Promise<{ payload: Base64, size: number }> {
    const state = this._getEncrypting(client, docId);
    checkRange(offset, length);
    const record = state.activeDoc.docData!.getMetaTable("_grist_Attachments").getRecord(rowId);
    if (!record) { throw new ApiError("Attachment not found", 404); }
    const data = await state.activeDoc.getAttachmentData(state.lock.session!, record);
    return { payload: data.subarray(offset, offset + length).toString("base64"), size: data.length };
  }

  /**
   * Completes the encryption of a document: its snapshot (as uploaded, encrypted with the new
   * document key keyId), and the copies of the key for its members.
   */
  public async commitEncryption(client: Client, docId: string, keyId: string, wraps: DocKeyRecord[],
    snapshot: PayloadSource, columnKeys: NewColumnKey[] = []): Promise<void> {
    const state = this._getEncrypting(client, docId);
    const userId = client.authSession.userId!;
    if (typeof keyId !== "string" || !keyId.startsWith(`${DOC_SCOPE}~`) || keyId.length > 200) {
      throw new ApiError("Invalid key id", 400);
    }
    wraps = (Array.isArray(wraps) ? wraps : []).map(w => ({ ...w, keyId }));
    this._relay.checkWraps(wraps);
    if (!wraps.some(w => w.userId === userId)) {
      throw new ApiError("The document key must include a copy for its creator", 400);
    }
    const memberIds = new Set((await this._relay.getMembers(client, docId)).map(m => m.userId));
    if (!wraps.every(w => memberIds.has(w.userId))) {
      throw new ApiError("Keys can only be given to members of the document", 400);
    }
    // Keys of columns made private (see _convertAccessRules()).
    if (!Array.isArray(columnKeys)) { throw new ApiError("Invalid column keys", 400); }
    const colRefs = new Set<number>();
    for (const key of columnKeys) {
      if (typeof key?.scope !== "string" || !/^column:[a-z0-9]{1,64}$/.test(key.scope) ||
        typeof key.keyId !== "string" || !key.keyId.startsWith(`${key.scope}~`) || key.keyId.length > 200 ||
        !isValidTarget(key.colRef) || colRefs.has(key.colRef)) {
        throw new ApiError("Invalid column key", 400);
      }
      colRefs.add(key.colRef);
      key.wraps = (Array.isArray(key.wraps) ? key.wraps : []).map(w => ({ ...w, keyId: key.keyId }));
      this._relay.checkWraps(key.wraps);
      if (!key.wraps.some(w => w.userId === userId) || !key.wraps.every(w => memberIds.has(w.userId))) {
        throw new ApiError("Column keys are for members, including their creator", 400);
      }
    }

    // 1. The new content, complete, next to the document.
    await state.staging.saveSnapshot(0, keyId, snapshot, userId);
    await state.staging.db.close();
    const donePath = state.stagingPath.slice(0, -INCOMPLETE_SUFFIX.length);
    await fse.move(state.stagingPath, donePath, { overwrite: true });
    // The document can't change anymore (nobody else can open it).
    await state.activeDoc.shutdown();

    // 2. The document is encrypted from now on.
    await this._dbManager.connection.transaction(async (manager) => {
      const doc = await manager.findOneOrFail(Document, { where: { id: docId } });
      if (isEncryptedDoc(doc)) { throw new ApiError("Document is already encrypted", 400); }
      doc.options = { ...doc.options, encryption: { version: 1 } };
      await manager.save(doc);
      await this._keys.addKey(manager, docId, DOC_SCOPE, keyId, wraps, userId, 0);
      for (const key of columnKeys) {
        await this._keys.addKey(manager, docId, key.scope, key.keyId, key.wraps, userId, 0);
        await this._keys.bindScope(manager, docId, key.scope, key.colRef, 0, userId);
      }
      // Shares (e.g. published forms) need the server to read the document.
      await manager.delete(Share, { docId });
    });
    this._encrypting.delete(docId);
    await this._afterSwitch(docId, { encrypted: true });
    this._relay.unlock(docId, state.lock);
  }

  /**
   * Starts decrypting a document, by an owner holding all its keys: locks it, and prepares a
   * regular document to write its content in.
   */
  public async beginDecryption(client: Client, docId: string): Promise<void> {
    await this._relay.authorizeConversion(client, docId);
    const lock = this._relay.lock(client, docId, "decrypting", { onRelease: () => this._dropDecrypting(docId) });
    try {
      const stagingPath = this._storageManager.getPath(docId) + DECRYPTING_SUFFIX + INCOMPLETE_SUFFIX;
      await fse.remove(stagingPath);
      const staging = new DocStorage(pathOnly(stagingPath), docId);
      await staging.createFile();
      await staging.exec(GRIST_DOC_SQL);
      this._decrypting.set(docId, { lock, staging, stagingPath });
      this._assertStillLocked(docId, lock);
    } catch (e) {
      this._relay.unlock(docId, lock);
      throw e;
    }
  }

  /**
   * Stores a decrypted attachment of a document being decrypted. Returns its identifier in the
   * regular document (from its checksum, as for regular attachments).
   */
  public async uploadDecryptedFile(client: Client, docId: string, ext: string,
    payload: PayloadSource): Promise<{ fileIdent: string }> {
    const state = this._getDecrypting(client, docId);
    if (typeof ext !== "string" || !/^(\.[A-Za-z0-9_-]{1,20})?$/.test(ext)) { throw new ApiError("Invalid extension", 400); }
    const data = await this._relay.takePayload(client, docId, payload);
    const fileIdent = crypto.createHash("sha1").update(data).digest("hex") + ext;
    await state.staging.attachOrUpdateFile(fileIdent, data, undefined);
    return { fileIdent };
  }

  /**
   * Completes the decryption of a document, given its content (marshalled, compressed {tables},
   * as of the change baseActionNum, which must be the latest one).
   */
  public async commitDecryption(client: Client, docId: string, baseActionNum: number,
    source: PayloadSource): Promise<void> {
    const state = this._getDecrypting(client, docId);
    await this._relay.authorizeConversion(client, docId);
    if (await this._relay.getHead(docId) !== baseActionNum) {
      throw new ApiError("The document changed meanwhile", 409);
    }
    const payload = unmarshalValue(await gunzip(await this._relay.takePayload(client, docId, source)));
    const tables: { [tableId: string]: TableDataAction } = payload?.tables;
    if (!tables || typeof tables !== "object" || !tables._grist_Tables || !tables._grist_Tables_column) {
      throw new ApiError("Invalid document content", 400);
    }

    // 1. The new content, complete, next to the document.
    await writeTables(state.staging, tables);
    await state.staging.run("UPDATE _gristsys_FileInfo SET docId = ?", docId);
    await state.staging.shutdown();
    const donePath = state.stagingPath.slice(0, -INCOMPLETE_SUFFIX.length);
    await fse.move(state.stagingPath, donePath, { overwrite: true });

    // 2. The document isn't encrypted anymore.
    await this._dbManager.connection.transaction(async (manager) => {
      const doc = await manager.findOneOrFail(Document, { where: { id: docId } });
      doc.options = { ...doc.options, encryption: null };
      await manager.save(doc);
      await this._keys.dropAll(manager, docId);
    });
    this._decrypting.delete(docId);
    await this._relay.closeStorage(docId);
    await this._afterSwitch(docId, { encrypted: false });
    this._relay.unlock(docId, state.lock, { decrypted: true });
  }

  public async abort(client: Client, docId: string): Promise<void> {
    const lock = getDocLock(docId);
    if (lock?.client === client && (lock.reason === "encrypting" || lock.reason === "decrypting")) {
      this._relay.unlock(docId, lock);
    }
  }

  private async _fetchAllTables(activeDoc: ActiveDoc) {
    const session = getDocLock(activeDoc.docName)!.session!;
    const tables: { [tableId: string]: TableDataAction } = { ...await activeDoc.fetchMetaTables(session) };
    const docData = activeDoc.docData!;
    for (const table of docData.getMetaTable("_grist_Tables").getRecords()) {
      const { tableData } = await activeDoc.fetchTable(session, table.tableId, true);
      tables[table.tableId] = tableData;
    }
    // What encrypted documents don't support: shares (e.g. published forms), external storage of
    // attachments (they become part of the document).
    tables._grist_Shares = ["TableData", "_grist_Shares", [], mapValues(tables._grist_Shares?.[3], () => [])];
    // Access rules: the server can't enforce them anymore (those hiding columns become private
    // columns, see _convertAccessRules()). Only the document's default rules are kept.
    const rules = tables._grist_ACLRules;
    if (rules) {
      const keep = rules[2].map((_, i) => i).filter(i => !rules[3].aclFormula?.[i] && !rules[3].userAttributes?.[i]);
      tables._grist_ACLRules = ["TableData", "_grist_ACLRules", keep.map(i => rules[2][i]),
        Object.fromEntries(Object.entries(rules[3]).map(([colId, values]) => [colId, keep.map(i => values[i])]))];
      const resources = tables._grist_ACLResources;
      const used = new Set(tables._grist_ACLRules[3].resource || []);
      const keepRes = resources[2].map((_, i) => i).filter(i => used.has(resources[2][i]));
      tables._grist_ACLResources = ["TableData", "_grist_ACLResources", keepRes.map(i => resources[2][i]),
        Object.fromEntries(Object.entries(resources[3]).map(([colId, values]) =>
          [colId, keepRes.map(i => values[i])]))];
    }
    const pages = tables._grist_Pages;
    if (pages?.[3].shareRef) { pages[3].shareRef = pages[3].shareRef.map(() => 0); }
    const info = tables._grist_DocInfo;
    const settingsIndex = info[3].documentSettings ? 0 : -1;
    if (settingsIndex === 0) {
      try {
        const settings = JSON.parse(String(info[3].documentSettings[0] || "{}"));
        delete settings.attachmentStoreId;
        info[3].documentSettings = [JSON.stringify(settings)];
      } catch (e) {
        // Leave settings as they are.
      }
    }
    return tables;
  }

  /**
   * Works out what access rules mean for each member: tables and columns they hide from some
   * members become private to the others (with keys of their own, see commitEncryption()). Rules depending on
   * the content (e.g. hiding some rows, or some cells) can't be converted: the document can't be
   * encrypted then. Nor can it by an owner who can't read all of it.
   */
  private async _convertAccessRules(activeDoc: ActiveDoc, client: Client, auth: DocAuthorizer,
    members: { userId: number, email: string }[]) {
    const docData = activeDoc.docData!;
    const rules = docData.getMetaTable("_grist_ACLRules").getRecords().filter(r => r.aclFormula || r.userAttributes);
    if (rules.length === 0) { return { columnAudiences: [], droppedRules: 0 }; }
    const asUser = (userId?: number) => {
      const linkParameters = userId ? { aclAsUserId: String(userId) } : undefined;
      const session = new OptDocSession({ client, ...(linkParameters ? { linkParameters } : {}) });
      session.authorizer = auth;
      return session;
    };
    if (!await activeDoc.canReadEverything(asUser())) {
      throw new ApiError("Only owners who can read all of a document can encrypt it", 403);
    }
    const system = getDocLock(activeDoc.docName)!.session!;
    // What each member can't read, by binding target (see tableTarget()): tables hidden as a
    // whole become private tables, other hidden columns private columns.
    const hidden = new Map<number, Set<number>>();   // target -> userIds who can't read it
    const hide = (target: number, userId: number) => {
      if (!hidden.has(target)) { hidden.set(target, new Set()); }
      hidden.get(target)!.add(userId);
    };
    const columns = docData.getMetaTable("_grist_Tables_column");
    for (const table of docData.getMetaTable("_grist_Tables").getRecords()) {
      // Summary tables follow their source table.
      if (table.summarySourceTable) { continue; }
      const full = (await activeDoc.fetchTable(system, table.tableId, true)).tableData;
      for (const member of members) {
        let seen: TableDataAction | null;
        try {
          seen = (await activeDoc.fetchTable(asUser(member.userId), table.tableId, true)).tableData;
        } catch (e) {
          if ((e)?.code !== "ACL_DENY") { throw e; }
          seen = null;    // The whole table is hidden from them.
        }
        const unconvertible = () => new ApiError(`Access rules of table ${table.tableId} depend on its content ` +
          `(e.g. hiding rows or cells from ${member.email}): they can't be kept in an encrypted document. ` +
          "Remove them first (columns can be made private instead, once encrypted)", 400);
        if (!seen) {
          hide(tableTarget(table.id), member.userId);
          continue;
        }
        if (seen[2].length !== full[2].length) { throw unconvertible(); }
        for (const col of columns.filterRecords({ parentId: table.id })) {
          if (col.colId === "id") { continue; }
          const values = seen[3][col.colId];
          if (values) {
            if (values.some(v => Array.isArray(v) && v[0] === GristObjCode.Censored)) { throw unconvertible(); }
            continue;
          }
          hide(col.id, member.userId);
        }
      }
    }
    const columnAudiences = [...hidden.entries()].map(([colRef, userIds]) => ({
      colRef, userIds: members.map(m => m.userId).filter(id => !userIds.has(id)),
    }));
    // Rules not about reading (e.g. limiting edits) can't be kept.
    const droppedRules = rules.filter(r => !String(r.permissionsText).includes("R")).length;
    return { columnAudiences, droppedRules };
  }

  /**
   * Once the home database says the document switched, puts its new file in place, and deletes
   * earlier versions of it kept by the storage.
   */
  private async _afterSwitch(docId: string, options: { encrypted: boolean }) {
    this._dbManager.flushDocAuthCache();
    await this._storageManager.prepareLocalDoc(docId);
    await finishPendingConversion(this._storageManager.getPath(docId), options);
    this._storageManager.markAsChanged(docId, "edit");
    await this._storageManager.closeDocument(docId);
    try {
      const { snapshots } = await this._storageManager.getSnapshots(docId, true);
      const older = snapshots.slice(1).map(s => s.snapshotId);
      if (older.length > 0) {
        log.info(`EncryptionConversion: deleting ${older.length} earlier version(s) of ${docId}`);
        await this._storageManager.removeSnapshots(docId, older);
      }
    } catch (e) {
      // The switch is done: just let it be known that earlier versions are still around.
      log.error(`EncryptionConversion: could not delete earlier versions of ${docId}`, e);
    }
  }

  // The lock may have been released meanwhile (e.g. its holder disconnected): then what was
  // prepared gets dropped.
  private _assertStillLocked(docId: string, lock: DocLock) {
    if (getDocLock(docId) !== lock) {
      lock.onRelease?.().catch(e => log.warn("EncryptionConversion: cleanup failed", e));
      throw new ApiError("The conversion was interrupted", 409);
    }
    lock.renew?.();
  }

  private _getEncrypting(client: Client, docId: string): EncryptingState {
    const state = this._encrypting.get(docId);
    if (state?.lock.client !== client || getDocLock(docId) !== state.lock) {
      throw new ApiError("This document isn't being encrypted", 409);
    }
    state.lock.renew?.();
    return state;
  }

  private _getDecrypting(client: Client, docId: string): DecryptingState {
    const state = this._decrypting.get(docId);
    if (state?.lock.client !== client || getDocLock(docId) !== state.lock) {
      throw new ApiError("This document isn't being decrypted", 409);
    }
    state.lock.renew?.();
    return state;
  }

  private async _dropEncrypting(docId: string) {
    const state = this._encrypting.get(docId);
    if (!state) { return; }
    this._encrypting.delete(docId);
    await state.staging.db.close().catch(() => {});
    await fse.remove(state.stagingPath);
  }

  private async _dropDecrypting(docId: string) {
    const state = this._decrypting.get(docId);
    if (!state) { return; }
    this._decrypting.delete(docId);
    await state.staging.shutdown().catch(() => {});
    await fse.remove(state.stagingPath);
  }
}

/**
 * Writes the tables of a document (all of them, as the data engine returns them) into a new
 * regular document, whose metadata tables exist already.
 */
async function writeTables(storage: DocStorage, tables: { [tableId: string]: TableDataAction }) {
  const metaTableIds = Object.keys(schema).filter(tableId => tables[tableId]);
  // Columns first: the storage learns the document's schema from them.
  metaTableIds.sort((a, b) => order(a) - order(b));
  for (const tableId of metaTableIds) {
    const [, , rowIds, columns] = tables[tableId];
    const known = new Set(Object.keys((schema as any)[tableId]));
    const values = Object.fromEntries(Object.entries(columns).filter(([colId]) => known.has(colId)));
    await storage.applyStoredActions([["ReplaceTableData", tableId, rowIds, values]]);
  }
  const columns = tables._grist_Tables_column;
  const colIndex = (colId: string) => columns[3][colId] as any[];
  for (const [i, tableRef] of tables._grist_Tables[2].entries()) {
    const tableId = String(tables._grist_Tables[3].tableId[i]);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tableId) || tableId.startsWith("_grist")) {
      throw new ApiError("Invalid document content", 400);
    }
    const tableColumns = columns[2].map((_, j) => j).filter(j => colIndex("parentId")[j] === tableRef)
      .map(j => ({ id: String(colIndex("colId")[j]), type: String(colIndex("type")[j]) }));
    await storage.applyStoredActions([["AddTable", tableId,
      tableColumns.map(c => ({ ...c, isFormula: false, formula: "" }))]]);
    const data = tables[tableId];
    if (!data) { continue; }
    const [, , rowIds, values] = data;
    const colIds = tableColumns.map(c => c.id).filter(colId => values[colId]);
    for (let start = 0; start < rowIds.length; start += ROWS_PER_BATCH) {
      const end = start + ROWS_PER_BATCH;
      await storage.applyStoredActions([["BulkAddRecord", tableId, rowIds.slice(start, end),
        Object.fromEntries(colIds.map(colId => [colId, values[colId].slice(start, end)]))]]);
    }
  }
}

function order(tableId: string) {
  return tableId === "_grist_Tables_column" ? 0 : tableId === "_grist_Tables" ? 1 : 2;
}

function mapValues<T>(obj: Record<string, unknown> | undefined, fn: () => T): Record<string, T> {
  return Object.fromEntries(Object.keys(obj || {}).map(key => [key, fn()]));
}

// A storage manager for a document at the given path (for files of documents being converted).
function pathOnly(path: string): IDocStorageManager {
  return { getPath: () => path, markAsChanged: () => {} } as unknown as IDocStorageManager;
}

function checkRange(offset: unknown, length: unknown) {
  if (!Number.isInteger(offset) || (offset as number) < 0 || !Number.isInteger(length) || (length as number) <= 0 ||
    (length as number) > MAX_INLINE_BYTES) {
    throw new ApiError("Invalid range", 400);
  }
}
