/**
 * Stores the content of encrypted documents, as ciphertext, in their usual document file (the
 * .grist file managed by the storage manager, which syncs it to external storage like any
 * document). Such a file isn't a regular Grist document: it holds
 *  - the document's history, as a linear series of encrypted changes (and key changes);
 *  - encrypted snapshots of the whole document, so that opening it doesn't require replaying
 *    its whole history;
 *  - encrypted files (attachments).
 *
 * The server can't read any of it. The one rule it enforces is ordering: a change is accepted
 * only if it was computed on top of the latest one. A document is only served by the doc worker
 * it's assigned to, and all writes to one document go through a mutex, so that's safe.
 */
import { Base64, EncryptedActionRecord, EncryptedSnapshotRecord } from "app/common/encryption/EncryptionTypes";
import { IDocStorageManager } from "app/server/lib/IDocStorageManager";
import log from "app/server/lib/log";
import { OpenMode, SchemaInfo, SQLiteDB } from "app/server/lib/SQLiteDB";

import * as crypto from "crypto";

import { Mutex } from "async-mutex";

// How many snapshots to keep. Changes up to the oldest one kept are deleted.
const SNAPSHOTS_KEPT = 2;

// Limit on how many changes a single fetch returns; callers fetch again for more.
const MAX_ACTIONS_PER_FETCH = 500;

// Files are closed (and synced to external storage) after this long without use.
const IDLE_CLOSE_MS = 60 * 1000;

const SCHEMA: SchemaInfo = {
  async create(db) {
    await db.exec(`
      CREATE TABLE _gristsys_EncryptedActions (
        actionNum INTEGER PRIMARY KEY,
        kind TEXT NOT NULL,
        keyId TEXT NOT NULL,
        payload BLOB,
        userId INTEGER,
        timeMs INTEGER NOT NULL
      );
      CREATE TABLE _gristsys_EncryptedSnapshots (
        actionNum INTEGER PRIMARY KEY,
        keyId TEXT NOT NULL,
        payload BLOB NOT NULL,
        userId INTEGER,
        timeMs INTEGER NOT NULL
      );
      CREATE TABLE _gristsys_EncryptedFiles (
        fileId TEXT PRIMARY KEY,
        payload BLOB NOT NULL,
        userId INTEGER,
        timeMs INTEGER NOT NULL
      );
    `);
  },
  migrations: [
    async (db) => {
      await db.exec(`
        CREATE TABLE _gristsys_EncryptedActions (
          actionNum INTEGER PRIMARY KEY,
          kind TEXT NOT NULL,
          keyId TEXT NOT NULL,
          payload BLOB,
          userId INTEGER,
          timeMs INTEGER NOT NULL
        );
        CREATE TABLE _gristsys_EncryptedSnapshots (
          actionNum INTEGER PRIMARY KEY,
          keyId TEXT NOT NULL,
          payload BLOB NOT NULL,
          userId INTEGER,
          timeMs INTEGER NOT NULL
        );
        CREATE TABLE _gristsys_EncryptedFiles (
          fileId TEXT PRIMARY KEY,
          payload BLOB NOT NULL,
          userId INTEGER,
          timeMs INTEGER NOT NULL
        );
      `);
    },
  ],
};

export type AppendResult =
  { accepted: true, action: EncryptedActionRecord } |
  { accepted: false, head: number };

/** One open document file. Use only through EncryptedDocStorage.withDoc(). */
export class EncryptedDocFile {
  constructor(public readonly db: SQLiteDB) {}

  /** The number of the latest change (changes covered by snapshots may have been pruned). */
  public async getHead(): Promise<number> {
    const row = await this.db.get(
      "SELECT MAX(COALESCE((SELECT MAX(actionNum) FROM _gristsys_EncryptedActions), 0)," +
      " COALESCE((SELECT MAX(actionNum) FROM _gristsys_EncryptedSnapshots), 0)) AS head");
    return row?.head || 0;
  }

  public async getLatestSnapshot(): Promise<EncryptedSnapshotRecord | null> {
    const row = await this.db.get(
      "SELECT actionNum, keyId, payload, timeMs FROM _gristsys_EncryptedSnapshots ORDER BY actionNum DESC LIMIT 1");
    return row ? { actionNum: row.actionNum, keyId: row.keyId, payload: toBase64(row.payload), timeMs: row.timeMs } :
      null;
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
  public async saveSnapshot(actionNum: number, keyId: string, payload: Base64,
    userId: number | null, options: { compact?: boolean } = {}): Promise<boolean> {
    return this.db.execTransaction(async () => {
      const head = await this.getHead();
      if (actionNum > head || actionNum < 0) {
        throw new Error(`Snapshot for change ${actionNum} doesn't match the document (at ${head})`);
      }
      const existing: number[] = (await this.db.all(
        "SELECT actionNum FROM _gristsys_EncryptedSnapshots ORDER BY actionNum DESC")).map(r => r.actionNum);
      if (actionNum === 0 && existing.length > 0) {
        throw new Error("Encrypted document is already initialized");
      }
      if (existing.length > 0 && (actionNum < existing[0] || (actionNum === existing[0] && !options.compact))) {
        // The same state or a newer one is saved already.
        return false;
      }
      // Compacting replaces even a snapshot of the same state (e.g. re-encrypted with a new key).
      await this.db.run("DELETE FROM _gristsys_EncryptedSnapshots WHERE actionNum = ?", actionNum);
      await this.db.run(
        "INSERT INTO _gristsys_EncryptedSnapshots (actionNum, keyId, payload, userId, timeMs) VALUES (?, ?, ?, ?, ?)",
        actionNum, keyId, fromBase64(payload), userId, Date.now());
      // When compacting, only this snapshot is kept (e.g. so that content encrypted with a key
      // someone shouldn't have anymore, or made private, isn't available anymore).
      const kept = options.compact ? [actionNum] :
        [actionNum, ...existing.filter(n => n !== actionNum)].slice(0, SNAPSHOTS_KEPT);
      const oldestKept = kept[kept.length - 1];
      await this.db.run("DELETE FROM _gristsys_EncryptedSnapshots WHERE actionNum < ?", oldestKept);
      await this.db.run("DELETE FROM _gristsys_EncryptedActions WHERE actionNum <= ?", oldestKept);
      return true;
    });
  }

  public async saveFile(payload: Base64, userId: number | null): Promise<string> {
    const fileId = crypto.randomBytes(16).toString("hex");
    await this.db.run("INSERT INTO _gristsys_EncryptedFiles (fileId, payload, userId, timeMs) VALUES (?, ?, ?, ?)",
      fileId, fromBase64(payload), userId, Date.now());
    return fileId;
  }

  public async getFile(fileId: string): Promise<Base64 | null> {
    const row = await this.db.get("SELECT payload FROM _gristsys_EncryptedFiles WHERE fileId = ?", fileId);
    return row ? toBase64(row.payload) : null;
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

  private async _openFile(docId: string): Promise<EncryptedDocFile> {
    await this._storageManager.prepareLocalDoc(docId);
    const db = await SQLiteDB.openDB(this._storageManager.getPath(docId), SCHEMA, OpenMode.OPEN_CREATE);
    return new EncryptedDocFile(db);
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

function toBase64(bytes: Uint8Array): Base64 {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(payload: Base64): Buffer {
  return Buffer.from(payload, "base64");
}
