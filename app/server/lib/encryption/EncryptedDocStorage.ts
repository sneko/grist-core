/**
 * Stores the content of encrypted documents, as ciphertext, in their usual document file (the
 * .grist file managed by the storage manager, which syncs it to external storage like any
 * document). Such a file isn't a regular Grist document: it holds
 *  - the document's history, as a linear series of encrypted changes (and key changes);
 *  - encrypted snapshots of the whole document, so that opening it doesn't require replaying
 *    its whole history;
 *  - encrypted files (attachments);
 *  - uploads in progress, for snapshots and files too big for a single message.
 *
 * The server can't read any of it. The one rule it enforces is ordering: a change is accepted
 * only if it was computed on top of the latest one. A document is only served by the doc worker
 * it's assigned to, and all writes to one document go through a mutex, so that's safe.
 */
import { ApiError } from "app/common/ApiError";
import {
  Base64, ENCRYPTED_PART_BYTES, EncryptedActionRecord,
  EncryptedInboxEntry, EncryptedSnapshotInfo, EncryptedSnapshotRecord, EncryptedSuggestion, PayloadSource,
} from "app/common/encryption/EncryptionTypes";
import { IDocStorageManager } from "app/server/lib/IDocStorageManager";
import log from "app/server/lib/log";
import { OpenMode, SQLiteDB } from "app/server/lib/SQLiteDB";

import * as crypto from "crypto";

import { Mutex } from "async-mutex";
import * as fse from "fs-extra";

// How many snapshots to keep. Changes up to the oldest one kept are deleted: older states remain
// available in the storage manager's own snapshots of the file (when it keeps any).
const SNAPSHOTS_KEPT = 5;

// Limit on how many changes a single fetch returns; callers fetch again for more.
const MAX_ACTIONS_PER_FETCH = 500;

// Snapshots and files are returned whole if no bigger than this, and by parts otherwise.
export const MAX_INLINE_BYTES = ENCRYPTED_PART_BYTES;

// Uploads not completed after this long are dropped.
const UPLOAD_EXPIRY_MS = 60 * 60 * 1000;

// Files are closed (and synced to external storage) after this long without use.
const IDLE_CLOSE_MS = 60 * 1000;

const CREATE_TABLES = `
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedActions (
    actionNum INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    keyId TEXT NOT NULL,
    payload BLOB,
    userId INTEGER,
    timeMs INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedSnapshots (
    actionNum INTEGER PRIMARY KEY,
    keyId TEXT NOT NULL,
    payload BLOB NOT NULL,
    userId INTEGER,
    timeMs INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedFiles (
    fileId TEXT PRIMARY KEY,
    payload BLOB NOT NULL,
    userId INTEGER,
    timeMs INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedSuggestions (
    id INTEGER PRIMARY KEY,
    keyId TEXT NOT NULL,
    payload BLOB NOT NULL,
    userId INTEGER,
    timeMs INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedForms (
    formId TEXT PRIMARY KEY,
    spec BLOB NOT NULL,
    timeMs INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedInbox (
    id INTEGER PRIMARY KEY,
    formId TEXT NOT NULL,
    payload BLOB NOT NULL,
    timeMs INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedInboxFiles (
    fileId TEXT PRIMARY KEY,
    formId TEXT NOT NULL,
    payload BLOB NOT NULL,
    entryId INTEGER,
    timeMs INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _gristsys_EncryptedUploads (
    uploadId TEXT NOT NULL,
    seq INTEGER NOT NULL,
    data BLOB NOT NULL,
    userId INTEGER,
    timeMs INTEGER NOT NULL,
    PRIMARY KEY (uploadId, seq)
  );
`;

// Documents being converted to or from encryption are prepared in a file next to theirs, with
// one of these suffixes, while being written (".tmp"), then once complete. See
// finishPendingConversion().
export const ENCRYPTING_SUFFIX = ".encrypting";
export const DECRYPTING_SUFFIX = ".decrypting";
export const INCOMPLETE_SUFFIX = ".tmp";

export type AppendResult =
  { accepted: true, action: EncryptedActionRecord } |
  { accepted: false, head: number };

export type { PayloadSource };

/**
 * One open document file. Use only through EncryptedDocStorage.withDoc() (or for a document being
 * converted, see EncryptionConversion.ts).
 */
export class EncryptedDocFile {
  /** Opens (or creates) a file holding an encrypted document. */
  public static async open(path: string): Promise<EncryptedDocFile> {
    // Files of encrypted documents only hold the tables below, which get created if missing
    // (e.g. in the file of a document being encrypted), whatever the file's storage version.
    const db = await SQLiteDB.openDBRaw(path, OpenMode.OPEN_CREATE);
    try {
      await db.exec(CREATE_TABLES);
    } catch (e) {
      await db.close();
      throw e;
    }
    return new EncryptedDocFile(db);
  }

  constructor(public readonly db: SQLiteDB) {}

  /**
   * Runs callback in a transaction of the file (nested calls are part of the same transaction):
   * if it fails, nothing it did is kept.
   */
  public async transaction<T>(callback: () => Promise<T>): Promise<T> {
    return this.db.execTransaction(callback);
  }

  /** The number of the latest change (changes covered by snapshots may have been pruned). */
  public async getHead(): Promise<number> {
    const row = await this.db.get(
      "SELECT MAX(COALESCE((SELECT MAX(actionNum) FROM _gristsys_EncryptedActions), 0)," +
      " COALESCE((SELECT MAX(actionNum) FROM _gristsys_EncryptedSnapshots), 0)) AS head");
    return row?.head || 0;
  }

  /** How many bytes the file takes. */
  public async getSize(): Promise<number> {
    const pages = await this.db.get("PRAGMA page_count");
    const pageSize = await this.db.get("PRAGMA page_size");
    return (pages?.page_count || 0) * (pageSize?.page_size || 0);
  }

  /**
   * The latest snapshot. Its payload is included only if it's small enough: otherwise it's empty,
   * and `size` tells how much to fetch with readSnapshot().
   */
  public async getLatestSnapshot(): Promise<EncryptedSnapshotRecord | null> {
    const row = await this.db.get(
      "SELECT actionNum, keyId, length(payload) AS size, timeMs FROM _gristsys_EncryptedSnapshots " +
      "ORDER BY actionNum DESC LIMIT 1");
    if (!row) { return null; }
    const payload = row.size <= MAX_INLINE_BYTES ? await this.readSnapshot(row.actionNum, 0, row.size) : "";
    return { actionNum: row.actionNum, keyId: row.keyId, payload, size: row.size, timeMs: row.timeMs };
  }

  /** The snapshots kept, newest first. */
  public async listSnapshots(): Promise<EncryptedSnapshotInfo[]> {
    return this.db.all(
      "SELECT actionNum, keyId, length(payload) AS size, userId, timeMs FROM _gristsys_EncryptedSnapshots " +
      "ORDER BY actionNum DESC") as Promise<EncryptedSnapshotInfo[]>;
  }

  /** A snapshot, with its payload included only if it's small enough (as getLatestSnapshot()). */
  public async getSnapshot(actionNum: number): Promise<EncryptedSnapshotRecord | null> {
    const row = await this.db.get(
      "SELECT actionNum, keyId, length(payload) AS size, timeMs FROM _gristsys_EncryptedSnapshots " +
      "WHERE actionNum = ?", actionNum);
    if (!row) { return null; }
    const payload = row.size <= MAX_INLINE_BYTES ? await this.readSnapshot(row.actionNum, 0, row.size) : "";
    return { actionNum: row.actionNum, keyId: row.keyId, payload, size: row.size, timeMs: row.timeMs };
  }

  /** Returns part of a snapshot's payload. */
  public async readSnapshot(actionNum: number, offset: number, length: number): Promise<Base64> {
    const row = await this.db.get(
      "SELECT substr(payload, ?, ?) AS part FROM _gristsys_EncryptedSnapshots WHERE actionNum = ?",
      offset + 1, length, actionNum);
    if (!row) { throw new ApiError("Snapshot not found: the document may have changed, please reload it", 404); }
    return toBase64(row.part);
  }

  public async hasSnapshot(): Promise<boolean> {
    return Boolean(await this.db.get("SELECT 1 FROM _gristsys_EncryptedSnapshots LIMIT 1"));
  }

  /** Returns changes after the given one, in order (at most MAX_ACTIONS_PER_FETCH of them). */
  public async getActions(afterActionNum: number): Promise<EncryptedActionRecord[]> {
    const rows = await this.db.all(
      "SELECT actionNum, kind, keyId, payload, userId, timeMs FROM _gristsys_EncryptedActions " +
      "WHERE actionNum > ? ORDER BY actionNum LIMIT ?", afterActionNum, MAX_ACTIONS_PER_FETCH);
    return rows.map(toActionRecord);
  }

  /**
   * Appends a change (or a key change), if baseActionNum is still the latest one. Otherwise,
   * refuses it and returns the current head, so that the author can catch up and retry.
   */
  public async appendAction(baseActionNum: number, record: {
    kind: EncryptedActionRecord["kind"], keyId: string, payload: Base64, userId: number | null,
  }): Promise<AppendResult> {
    const head = await this.getHead();
    if (head !== baseActionNum) { return { accepted: false, head }; }
    if (!await this.hasSnapshot()) { throw new Error("Encrypted document has not been initialized"); }
    const action: EncryptedActionRecord = { actionNum: head + 1, ...record, timeMs: Date.now() };
    await this.db.run(
      "INSERT INTO _gristsys_EncryptedActions (actionNum, kind, keyId, payload, userId, timeMs) " +
      "VALUES (?, ?, ?, ?, ?, ?)",
      action.actionNum, action.kind, action.keyId, fromBase64(action.payload), action.userId, action.timeMs);
    return { accepted: true, action };
  }

  /**
   * Saves a snapshot of the document as of actionNum, and prunes what it makes unnecessary. The
   * snapshot for actionNum 0 is the initial state of the document: it can only be saved once.
   * Returns false if the snapshot was of no use (e.g. a newer one exists).
   */
  public async saveSnapshot(actionNum: number, keyId: string, source: PayloadSource,
    userId: number | null, options: { compact?: boolean } = {}): Promise<boolean> {
    return this.transaction(async () => {
      const head = await this.getHead();
      if (actionNum > head || actionNum < 0) {
        throw new Error(`Snapshot for change ${actionNum} doesn't match the document (at ${head})`);
      }
      const rows = (await this.db.all(
        "SELECT actionNum, keyId FROM _gristsys_EncryptedSnapshots ORDER BY actionNum DESC")) as
        { actionNum: number, keyId: string }[];
      const existing = rows.map(r => r.actionNum);
      if (actionNum === 0 && existing.length > 0) {
        throw new Error("Encrypted document is already initialized");
      }
      // The same state saved again is of no use, unless compacting, or re-encrypting it with a
      // new key (members given only the new key need it).
      if (existing.length > 0 && (actionNum < existing[0] ||
        (actionNum === existing[0] && !options.compact && rows[0].keyId === keyId))) {
        // The same state or a newer one is saved already.
        await this.dropUpload(source);
        return false;
      }
      const payload = await this.takePayload(source);
      // A snapshot of the same state gets replaced.
      await this.db.run("DELETE FROM _gristsys_EncryptedSnapshots WHERE actionNum = ?", actionNum);
      await this.db.run(
        "INSERT INTO _gristsys_EncryptedSnapshots (actionNum, keyId, payload, userId, timeMs) VALUES (?, ?, ?, ?, ?)",
        actionNum, keyId, payload, userId, Date.now());
      // When compacting, only this snapshot is kept (so that content made private isn't
      // available anymore in readable form).
      const kept = options.compact ? [actionNum] :
        [actionNum, ...existing.filter(n => n !== actionNum)].slice(0, SNAPSHOTS_KEPT);
      const oldestKept = kept[kept.length - 1];
      await this.db.run("DELETE FROM _gristsys_EncryptedSnapshots WHERE actionNum < ?", oldestKept);
      await this.db.run("DELETE FROM _gristsys_EncryptedActions WHERE actionNum <= ?", oldestKept);
      return true;
    });
  }

  public async saveFile(source: PayloadSource, userId: number | null): Promise<string> {
    const fileId = crypto.randomBytes(16).toString("hex");
    return this.db.execTransaction(async () => {
      await this.db.run("INSERT INTO _gristsys_EncryptedFiles (fileId, payload, userId, timeMs) VALUES (?, ?, ?, ?)",
        fileId, await this.takePayload(source), userId, Date.now());
      return fileId;
    });
  }

  /** A file's size, or null if there's no such file. */
  public async getFileSize(fileId: string): Promise<number | null> {
    const row = await this.db.get("SELECT length(payload) AS size FROM _gristsys_EncryptedFiles WHERE fileId = ?",
      fileId);
    return row ? row.size : null;
  }

  /** Returns part of a file. */
  public async readFile(fileId: string, offset: number, length: number): Promise<Base64 | null> {
    const row = await this.db.get(
      "SELECT substr(payload, ?, ?) AS part FROM _gristsys_EncryptedFiles WHERE fileId = ?",
      offset + 1, length, fileId);
    return row ? toBase64(row.part) : null;
  }

  /** Publishes (or updates) a form, given its spec (encrypted with its link key). */
  public async setForm(formId: string, spec: Base64): Promise<void> {
    await this.db.run("INSERT OR REPLACE INTO _gristsys_EncryptedForms (formId, spec, timeMs) VALUES (?, ?, ?)",
      formId, fromBase64(spec), Date.now());
  }

  public async removeForm(formId: string): Promise<void> {
    await this.db.run("DELETE FROM _gristsys_EncryptedForms WHERE formId = ?", formId);
  }

  /** A published form's spec (encrypted), or null if it isn't published. */
  public async getForm(formId: string): Promise<Base64 | null> {
    const row = await this.db.get("SELECT spec FROM _gristsys_EncryptedForms WHERE formId = ?", formId);
    return row ? toBase64(row.spec) : null;
  }

  /** Keeps an answer to a form (encrypted for the form), until added to the document. */
  public async addToInbox(formId: string, payload: Base64): Promise<void> {
    await this.db.run("INSERT INTO _gristsys_EncryptedInbox (formId, payload, timeMs) VALUES (?, ?, ?)",
      formId, fromBase64(payload), Date.now());
  }

  /**
   * Keeps a file attached in an answer to a form (encrypted by the respondent), until its answer is
   * added to the document. Files of answers never sent are dropped after a while.
   */
  public async addInboxFile(formId: string, payload: Buffer): Promise<string> {
    await this.db.run("DELETE FROM _gristsys_EncryptedInboxFiles WHERE entryId IS NULL AND timeMs < ?",
      Date.now() - UPLOAD_EXPIRY_MS);
    const fileId = crypto.randomBytes(16).toString("hex");
    await this.db.run(
      "INSERT INTO _gristsys_EncryptedInboxFiles (fileId, formId, payload, entryId, timeMs) VALUES (?, ?, ?, NULL, ?)",
      fileId, formId, payload, Date.now());
    return fileId;
  }

  /** Keeps an answer, with the files sent for it (which must be for the same form, and not used yet). */
  public async addToInboxWithFiles(formId: string, payload: Base64, fileIds: string[]): Promise<void> {
    await this.transaction(async () => {
      await this.addToInbox(formId, payload);
      const entryId = (await this.db.get("SELECT last_insert_rowid() AS id"))!.id;
      for (const fileId of fileIds) {
        const row = await this.db.get(
          "SELECT 1 FROM _gristsys_EncryptedInboxFiles WHERE fileId = ? AND formId = ? AND entryId IS NULL",
          fileId, formId);
        if (!row) { throw new ApiError("Unknown file", 400); }
        await this.db.run("UPDATE _gristsys_EncryptedInboxFiles SET entryId = ? WHERE fileId = ?", entryId, fileId);
      }
    });
  }

  /** Returns part of a file attached in an answer still in the inbox, with its size. */
  public async readInboxFile(fileId: string, offset: number,
    length: number): Promise<{ payload: Base64, size: number } |
    null> {
    const row = await this.db.get(
      "SELECT substr(payload, ?, ?) AS part, length(payload) AS size FROM _gristsys_EncryptedInboxFiles " +
      "WHERE fileId = ? AND entryId IS NOT NULL", offset + 1, length, fileId);
    return row ? { payload: toBase64(row.part), size: row.size } : null;
  }

  /** How many bytes files waiting in the inbox take. */
  public async getInboxFilesSize(): Promise<number> {
    return (await this.db.get("SELECT SUM(length(payload)) AS size FROM _gristsys_EncryptedInboxFiles"))?.size || 0;
  }

  /** Answers waiting to be added to the document, oldest first (at most `limit`). */
  public async getInbox(limit: number): Promise<EncryptedInboxEntry[]> {
    const rows = await this.db.all(
      "SELECT id, formId, payload, timeMs FROM _gristsys_EncryptedInbox ORDER BY id LIMIT ?", limit);
    return rows.map(r => ({ id: r.id, formId: r.formId, payload: toBase64(r.payload), timeMs: r.timeMs }));
  }

  public async countInbox(): Promise<number> {
    return (await this.db.get("SELECT COUNT(*) AS n FROM _gristsys_EncryptedInbox"))?.n || 0;
  }

  /** Removes answers from the inbox. Returns how many were there. */
  public async removeFromInbox(ids: number[]): Promise<number> {
    let removed = 0;
    for (const id of ids) {
      const before = await this.db.get("SELECT 1 FROM _gristsys_EncryptedInbox WHERE id = ?", id);
      if (before) {
        await this.db.run("DELETE FROM _gristsys_EncryptedInbox WHERE id = ?", id);
        await this.db.run("DELETE FROM _gristsys_EncryptedInboxFiles WHERE entryId = ?", id);
        removed++;
      }
    }
    return removed;
  }

  /** Adds a suggestion of changes (see EncryptedSuggestion). Returns its id. */
  public async addSuggestion(keyId: string, payload: Base64, userId: number | null): Promise<number> {
    return this.transaction(async () => {
      await this.db.run(
        "INSERT INTO _gristsys_EncryptedSuggestions (keyId, payload, userId, timeMs) VALUES (?, ?, ?, ?)",
        keyId, fromBase64(payload), userId, Date.now());
      return (await this.db.get("SELECT last_insert_rowid() AS id"))!.id;
    });
  }

  /** Suggestions not handled yet, oldest first (only those by userId, if given). */
  public async getSuggestions(options: { userId?: number } = {}): Promise<EncryptedSuggestion[]> {
    const rows = await this.db.all(
      "SELECT id, keyId, payload, userId, timeMs FROM _gristsys_EncryptedSuggestions " +
      (options.userId !== undefined ? "WHERE userId = ? " : "") + "ORDER BY id",
      ...(options.userId !== undefined ? [options.userId] : []));
    return rows.map(toSuggestion);
  }

  public async getSuggestion(id: number): Promise<EncryptedSuggestion | null> {
    const row = await this.db.get(
      "SELECT id, keyId, payload, userId, timeMs FROM _gristsys_EncryptedSuggestions WHERE id = ?", id);
    return row ? toSuggestion(row) : null;
  }

  public async countSuggestions(): Promise<number> {
    return (await this.db.get("SELECT COUNT(*) AS n FROM _gristsys_EncryptedSuggestions"))?.n || 0;
  }

  public async removeSuggestion(id: number): Promise<void> {
    await this.db.run("DELETE FROM _gristsys_EncryptedSuggestions WHERE id = ?", id);
  }

  /** Starts an upload, for a payload too big for a single message. Returns its id. */
  public async beginUpload(): Promise<string> {
    await this.db.run("DELETE FROM _gristsys_EncryptedUploads WHERE timeMs < ?", Date.now() - UPLOAD_EXPIRY_MS);
    return crypto.randomBytes(16).toString("hex");
  }

  /** Adds the part number `seq` (starting at 0) of an upload. Returns the upload's size so far. */
  public async appendUpload(uploadId: string, seq: number, chunk: Base64, userId: number | null): Promise<number> {
    if (seq > 0 && !await this.db.get(
      "SELECT 1 FROM _gristsys_EncryptedUploads WHERE uploadId = ? AND seq = ?", uploadId, seq - 1)) {
      throw new ApiError("Unknown or expired upload", 404);
    }
    await this.db.run(
      "INSERT OR REPLACE INTO _gristsys_EncryptedUploads (uploadId, seq, data, userId, timeMs) VALUES (?, ?, ?, ?, ?)",
      uploadId, seq, fromBase64(chunk), userId, Date.now());
    return this.getUploadSize(uploadId);
  }

  public async getUploadSize(uploadId: string): Promise<number> {
    const row = await this.db.get(
      "SELECT SUM(length(data)) AS size FROM _gristsys_EncryptedUploads WHERE uploadId = ?", uploadId);
    return row?.size || 0;
  }

  /** Returns the bytes of a payload, consuming the upload it's in, if any. */
  public async takePayload(source: PayloadSource): Promise<Buffer> {
    if (typeof source === "string") { return fromBase64(source); }
    const rows = await this.db.all(
      "SELECT data FROM _gristsys_EncryptedUploads WHERE uploadId = ? ORDER BY seq", source.uploadId);
    if (rows.length === 0) { throw new ApiError("Unknown or expired upload", 404); }
    await this.dropUpload(source);
    return Buffer.concat(rows.map(r => Buffer.from(r.data)));
  }

  /** Drops what was uploaded for a payload, if anything. */
  public async dropUpload(source: PayloadSource) {
    if (typeof source === "string") { return; }
    await this.db.run("DELETE FROM _gristsys_EncryptedUploads WHERE uploadId = ?", source.uploadId);
  }
}

export class EncryptedDocStorage {
  private _files = new Map<string, { file: Promise<EncryptedDocFile>, mutex: Mutex, timer?: NodeJS.Timeout }>();

  constructor(private _storageManager: IDocStorageManager) {}

  /**
   * Runs callback with the document's file, opening it if needed (fetching it from external
   * storage if it's not available locally), with exclusive access to it. If `write` is set, the
   * file is marked as changed, to get synced to external storage.
   */
  public async withDoc<T>(docId: string, options: { write: boolean },
    callback: (file: EncryptedDocFile) => Promise<T>): Promise<T> {
    let entry = this._files.get(docId);
    if (!entry) {
      entry = { file: this._openFile(docId), mutex: new Mutex() };
      this._files.set(docId, entry);
      entry.file.catch(() => this._files.delete(docId));
    }
    const current = entry;
    if (current.timer) { clearTimeout(current.timer); }
    try {
      return await current.mutex.runExclusive(async () => {
        const file = await current.file;
        const result = await callback(file);
        if (options.write) { this._storageManager.markAsChanged(docId, "edit"); }
        return result;
      });
    } finally {
      if (this._files.get(docId) === current) {
        current.timer = setTimeout(() => this._closeFile(docId).catch(e =>
          log.warn(`EncryptedDocStorage: failed to close ${docId}`, e)), IDLE_CLOSE_MS);
      }
    }
  }

  /** Closes all files (e.g. on shutdown). */
  public async close() {
    await Promise.all([...this._files.keys()].map(docId => this._closeFile(docId)));
  }

  /** Closes a document's file now (e.g. before it gets replaced), once done with its current use. */
  public async closeDoc(docId: string) {
    await this._closeFile(docId);
  }

  private async _openFile(docId: string): Promise<EncryptedDocFile> {
    await this._storageManager.prepareLocalDoc(docId);
    const path = this._storageManager.getPath(docId);
    // It may have just been encrypted, without its new content in place yet.
    if (await finishPendingConversion(path, { encrypted: true })) {
      this._storageManager.markAsChanged(docId, "edit");
    }
    return EncryptedDocFile.open(path);
  }

  private async _closeFile(docId: string) {
    const entry = this._files.get(docId);
    if (!entry) { return; }
    if (entry.timer) { clearTimeout(entry.timer); }
    await entry.mutex.runExclusive(async () => {
      if (this._files.get(docId) !== entry) { return; }
      this._files.delete(docId);
      const file = await entry.file.catch(() => null);
      if (!file) { return; }
      await file.db.close();
      await this._storageManager.closeDocument(docId);
    });
  }
}

/**
 * Documents get converted to (or from) encryption by preparing their new content in a file next
 * to theirs (with ENCRYPTING_SUFFIX or DECRYPTING_SUFFIX), completed before the home database
 * says the document is (or isn't) encrypted, and then moved in place. If something interrupted
 * that, this finishes it (or drops what was prepared, if the home database wasn't updated), given
 * whether the document is encrypted now. Returns whether the document's file got replaced.
 */
export async function finishPendingConversion(path: string, options: { encrypted: boolean }): Promise<boolean> {
  const done = path + (options.encrypted ? ENCRYPTING_SUFFIX : DECRYPTING_SUFFIX);
  const abandoned = path + (options.encrypted ? DECRYPTING_SUFFIX : ENCRYPTING_SUFFIX);
  for (const leftover of [abandoned, abandoned + INCOMPLETE_SUFFIX, done + INCOMPLETE_SUFFIX]) {
    await fse.remove(leftover);
  }
  if (!await fse.pathExists(done)) { return false; }
  log.warn(`EncryptedDocStorage: finishing the conversion of ${path} (${options.encrypted ? "en" : "de"}crypted)`);
  await fse.move(done, path, { overwrite: true });
  return true;
}

function toActionRecord(row: any): EncryptedActionRecord {
  return {
    actionNum: row.actionNum,
    kind: row.kind,
    keyId: row.keyId,
    payload: row.payload ? toBase64(row.payload) : "",
    userId: row.userId,
    timeMs: row.timeMs,
  };
}

function toSuggestion(row: any): EncryptedSuggestion {
  return { id: row.id, keyId: row.keyId, payload: toBase64(row.payload), userId: row.userId, timeMs: row.timeMs };
}

function toBase64(bytes: Uint8Array | null): Base64 {
  return bytes ? Buffer.from(bytes).toString("base64") : "";
}

function fromBase64(payload: Base64): Buffer {
  return Buffer.from(payload, "base64");
}
