/**
 * LocalActiveDoc plays, in the browser, the role ActiveDoc plays on the server for regular
 * documents, for encrypted documents: it owns the data engine, applies user actions, and produces
 * the doc actions the rest of the client consumes. What it doesn't do is persist anything:
 * changes are encrypted and pushed to the server (the "relay"), which orders them and forwards
 * them to the other browsers that have the document open.
 *
 * Synchronization is optimistic and linear:
 *  - Each change gets applied to the local engine, encrypted, and pushed as following the latest
 *    change known locally (`head`). The server accepts it only if that's still the latest one.
 *  - If the server refuses it, someone else's change got in first: the local change is undone,
 *    the missing changes are fetched and applied, and the user's actions are applied again on top.
 *  - Changes from others are applied with the formula values their author's engine computed, so
 *    that every browser ends up with exactly the same data (even for formulas like NOW()).
 *  - A browser that missed changes (e.g. while disconnected) notices the gap in their numbers
 *    and fetches them. If the server no longer has them (they get pruned once covered by newer
 *    snapshots), the document needs reopening, which loads the latest snapshot.
 *
 * Keys (see EncryptionTypes.ts): changes and snapshots are encrypted with the current document
 * key, and values of private columns, within them, with the keys of their scopes (see
 * ColumnPrivacy.ts). When a key is flagged for replacement (someone who held it lost access),
 * the next edit first creates its replacement; the key change is recorded in the history, so all
 * browsers switch keys at the same point. Columns becoming private or public are recorded the same
 * way.
 *
 * The server can't check changes (it can't read them), and any member holding the document key
 * can make one. So each browser checks the changes it receives: those it can't decrypt or apply,
 * or that don't respect private columns, are skipped. Every browser comes to the same conclusion
 * (it depends only on the history and on what the server says about keys and private columns),
 * so they all skip the same changes, and keep the same document. (Checks only members holding a
 * column's key can make lock the values concerned instead, see ColumnPrivacy.ts.)
 *
 * The rest of the client sees nothing of this: it gets the same doc actions and action groups it
 * would get from the server for a regular document. This class has no browser dependencies, so
 * that it can be tested under Node; the engine, relay and vault are supplied by the caller.
 */
import { LocalActionBundle } from "app/common/ActionBundle";
import { ActionGroup, MinimalActionGroup } from "app/common/ActionGroup";
import { summarizeAction } from "app/common/ActionSummarizer";
import { createEmptyActionSummary } from "app/common/ActionSummary";
import { ApplyUAOptions, ApplyUAResult, TableFetchResult } from "app/common/ActiveDocAPI";
import { DocAction, getTableId, isSchemaAction, TableDataAction, UserAction } from "app/common/DocActions";
import { DocData } from "app/common/DocData";
import {
  BlobTable, ChangePrivacy, checkSealing, ColumnPrivacy, EncryptionAccessError, sealActions, sealTables,
  unsealActions, unsealTables,
} from "app/common/encryption/ColumnPrivacy";
import {
  decryptBundle, decryptSnapshot, DocChangeBundle, DocSnapshotPayload, encryptBundle, encryptSnapshot,
} from "app/common/encryption/EncryptedPayloads";
import { base64ToBytes, bytesToBase64, KeyRecipient, sha256Hex } from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, EncryptedActionRecord, EncryptedDocOpenResult, EncryptedPushResult, EncryptionKeysResult,
  EncryptionMember, makeKeyId, NewKeyRequest,
} from "app/common/encryption/EncryptionTypes";
import { Keyring, MissingKeyError } from "app/common/encryption/Keyring";
import { IDataEngine } from "app/common/encryption/PyodideEngine";
import { CannotCarryError, SealedCells } from "app/common/encryption/SealedCells";

import { Mutex } from "async-mutex";
import flatten from "lodash/flatten";
import isEqual from "lodash/isEqual";

/** The server side of an encrypted document, as LocalActiveDoc needs it. */
export interface IEncryptionRelay {
  fetchActions(afterActionNum: number): Promise<EncryptedActionRecord[]>;
  pushAction(baseActionNum: number, keyId: string, payload: Base64): Promise<EncryptedPushResult>;
  saveSnapshot(actionNum: number, keyId: string, payload: Base64, options?: { compact?: boolean }): Promise<void>;
  getKeys(): Promise<EncryptionKeysResult>;
  listMembers(): Promise<EncryptionMember[]>;
  createKey(request: NewKeyRequest): Promise<EncryptedPushResult>;
  releaseScope(scope: string, baseActionNum: number): Promise<EncryptedPushResult>;
}

/** What GristDoc expects to receive for each change (see CommDocUserAction). */
export interface LocalDocUserAction {
  docActions: DocAction[];
  actionGroup: ActionGroup;
  fromSelf: boolean;
  rowCount: number;
}

export interface LocalActiveDocOptions {
  engine: IDataEngine;
  relay: IEncryptionRelay;
  keyring: Keyring;
  // The user, as passed to the data engine (for trigger formulas using `user`); see User.toJSON().
  engineUser: object;
  // How the user appears in the history of the document.
  userName: string;
  canEdit: boolean;
  onDocUserAction: (action: LocalDocUserAction) => void;
  // How the encryption service identifies a member (needed to give them keys), if it can.
  vaultIdFor: (member: { userId: number, vaultUserId: string | null }) => string | null;
  // Save a new snapshot when there are at least this many changes since the latest one.
  snapshotEvery?: number;
  // How many recent changes to keep in memory (for undo and the history panel).
  maxHistory?: number;
  // Used when this browser creates the document.
  newDocSettings?: { timezone: string, locale: string };
  // Called for changes from others that don't respect private columns, or can't be applied (see
  // the comment at the top): skipped, or with some private values locked.
  onInvalidChange?: (change: InvalidChange) => void;
  log?: (...args: any[]) => void;
}

export interface InvalidChange {
  actionNum: number;
  userId: number | null;
  reason: string;
  skipped: boolean;     // Whether the change was skipped altogether.
}

/** Thrown when the document can't be followed anymore, and must be reopened. */
export class NeedsReloadError extends Error {}

interface HistoryEntry {
  actionNum: number;
  actionHash: string;
  bundle: DocChangeBundle;    // With unsealed values.
  fromSelf: boolean;
}

// Engine output for apply_user_actions (see main.py), i.e. a SandboxActionBundle.
interface EngineResult {
  stored: [number, DocAction][];
  undo: [number, DocAction][];
  retValues: any[];
  rowCount: { total: number };
}

const MAX_PUSH_ATTEMPTS = 20;
const TOO_FAST_ERROR = "Could not save change: the document is changing too fast, please retry";

export class LocalActiveDoc {
  /**
   * Loads a document from what the server returned on opening it: the latest snapshot and the
   * changes since. If there is neither, and options.newDocSettings is set, creates the document
   * (its initial state then gets saved as the first snapshot).
   */
  public static async open(options: LocalActiveDocOptions,
    openResult: EncryptedDocOpenResult): Promise<LocalActiveDoc> {
    const doc = new LocalActiveDoc(options);
    await doc._load(openResult);
    return doc;
  }

  public docData: DocData;

  private _engine: IDataEngine;
  private _relay: IEncryptionRelay;
  private _keyring: Keyring;
  private _mutex = new Mutex();
  private _head = 0;
  private _snapshotNum = 0;
  private _history = new Map<number, HistoryEntry>();
  private _rowCount = 0;
  private _bundling = false;
  private _lastOwnActionNum = 0;
  private _log: (...args: any[]) => void;
  private _closed = false;
  // While loading, nobody is listening for changes yet: they are reflected in what gets fetched.
  private _loading = true;
  private _privacy = new ColumnPrivacy([]);
  private _frozen: [string, string][] = [];
  private _scopeEntries: [string, string, string[]][] = [];
  private _sealedCells = new SealedCells();
  private _memberLabels = new Map<number, string>();

  private constructor(private _options: LocalActiveDocOptions) {
    this._engine = _options.engine;
    this._relay = _options.relay;
    this._keyring = _options.keyring;
    this._log = _options.log || (() => {});
  }

  /** The number of the latest change applied locally. */
  public get head() { return this._head; }

  public get canEdit() { return this._options.canEdit; }

  public get keyring() { return this._keyring; }

  /** Which columns are private (and which formulas depend on them). */
  public get privacy() { return this._privacy; }

  /** The metadata tables, as returned to the client when opening a document. */
  public async fetchMetaTables(): Promise<{ [tableId: string]: TableDataAction }> {
    return this._exclusive(() => this._engine.call("fetch_meta_tables"));
  }

  /** Recent changes, for the client's undo stack (none are undoable after reopening). */
  public getRecentMinimalActions(): MinimalActionGroup[] {
    return [...this._history.values()].map(h => ({
      actionNum: h.actionNum,
      actionHash: h.actionHash,
      fromSelf: false,
      linkId: h.bundle.info.linkId,
      otherId: h.bundle.info.otherId,
      rowIdHint: 0,
      isUndo: getPrimaryAction(h.bundle) === "ApplyUndoActions",
    }));
  }

  public async fetchTable(tableId: string): Promise<TableFetchResult> {
    return this._exclusive(async () => ({ tableData: await this._engine.call("fetch_table", tableId) }));
  }

  public async applyUserActions(actions: UserAction[], options?: ApplyUAOptions): Promise<ApplyUAResult> {
    this._assertCanEdit();
    return this._exclusive(() => this._applyAndPush(actions, options || {}));
  }

  /** Redo (or undo, if `undo` is set) changes identified by number and hash. */
  public async applyUserActionsById(actionNums: number[], actionHashes: string[], undo: boolean,
    options?: ApplyUAOptions): Promise<ApplyUAResult> {
    this._assertCanEdit();
    return this._exclusive(async () => {
      const entries = actionNums.map((actionNum, i) => {
        const entry = this._history.get(actionNum);
        if (!entry) { throw new Error(`Could not find actionNum ${actionNum}`); }
        if (entry.actionHash !== actionHashes[i]) {
          throw new Error(`Hash mismatch for actionNum ${actionNum}: ` +
            `expected ${actionHashes[i]} but got ${entry.actionHash}`);
        }
        return entry;
      });
      const actions: UserAction[] = undo ?
        [["ApplyUndoActions", flatten(entries.map(e => e.bundle.undo))]] :
        flatten(entries.map(e => e.bundle.userActions));
      return this._applyAndPush(actions, options || {});
    });
  }

  /** Called with each change the server broadcasts (changes from other browsers). */
  public async receiveAction(record: EncryptedActionRecord): Promise<void> {
    return this._exclusive(() => this._catchUp([record]));
  }

  /** Fetches and applies any changes the server has that we don't. */
  public async sync(): Promise<void> {
    return this._exclusive(() => this._catchUp([]));
  }

  public startBundleUserActions() { this._bundling = true; this._lastOwnActionNum = 0; }
  public stopBundleUserActions() { this._bundling = false; this._lastOwnActionNum = 0; }

  public async findColFromValues(values: any[], n: number, optTableId?: string): Promise<number[]> {
    return this._exclusive(() => this._engine.call("find_col_from_values", values, n, optTableId));
  }

  public async getFormulaError(tableId: string, colId: string, rowId: number): Promise<any> {
    return this._exclusive(() => this._engine.call("get_formula_error", tableId, colId, rowId));
  }

  public async autocomplete(txt: string, tableId: string, columnId: string, rowId: number | null): Promise<any> {
    return this._exclusive(() =>
      this._engine.call("autocomplete", txt, tableId, columnId, rowId, this._options.engineUser));
  }

  /** Returns the Python code generated for the document's formulas (for the "Code view" page). */
  public async fetchPythonCode(): Promise<string> {
    return this._exclusive(() => this._engine.call("fetch_table_schema"));
  }

  /** Recent changes, with summaries, for the document's history. */
  public getActionSummaries(): ActionGroup[] {
    return [...this._history.values()].map(h =>
      makeActionGroup(h.bundle, h.bundle.stored, h.bundle.undo, h.bundle.retValues,
        { actionNum: h.actionNum, actionHash: h.actionHash, fromSelf: false }));
  }

  /**
   * Saves a snapshot of the document now (normally done automatically every few changes). With
   * `compact`, the server drops older snapshots and changes, e.g. so that content made private
   * is no longer available in readable form.
   */
  public async saveSnapshot(options: { compact?: boolean } = {}): Promise<void> {
    this._assertCanEdit();
    return this._exclusive(() => this._saveSnapshot(options));
  }

  /**
   * Keeps formulas that depend on the current time up to date. Like the server does every hour
   * for regular documents; the result is shared like any other change.
   */
  public async updateCurrentTime(): Promise<void> {
    if (!this.canEdit) { return; }
    return this._exclusive(async () => {
      await this._applyAndPush([["UpdateCurrentTime"]], {}, { internal: true, skipIfEmpty: true });
    });
  }

  /**
   * Creates the key of a new scope (e.g. for new private columns), for the given members. The
   * key change is recorded in the history, ordered like any change.
   */
  public async createScopeKey(scope: string, recipients: (KeyRecipient & { userId: number })[],
    colRef?: number): Promise<string> {
    this._assertCanEdit();
    return this._exclusive(() => this._createKey(scope, recipients, colRef));
  }

  /**
   * Makes a private column public again (its scope no longer protects it). Members who couldn't
   * read it get its values (and those of formulas that were private because of it) in a change
   * that follows.
   */
  public async releaseScope(scope: string): Promise<void> {
    this._assertCanEdit();
    return this._exclusive(async () => {
      for (let attempt = 1; ; attempt++) {
        const result = await this._relay.releaseScope(scope, this._head);
        if (result.accepted) {
          const before = this._privacy;
          this._head = result.actionNum;
          await this._keyring.refresh();
          await this._updatePrivacy();
          await this._shareRevealedValues(before, this._privacy);
          return;
        }
        await this._catchUp([]);
        if (attempt >= MAX_PUSH_ATTEMPTS) { throw new Error(TOO_FAST_ERROR); }
      }
    });
  }

  /** Gets the latest state of keys (e.g. when the server says they changed). */
  public async refreshKeys(): Promise<void> {
    return this._exclusive(async () => {
      await this._keyring.refresh();
      await this._updatePrivacy();
    });
  }

  /** Replaces keys flagged for replacement now, rather than on the next edit. */
  public async rotateKeys(): Promise<void> {
    if (!this.canEdit) { return; }
    return this._exclusive(() => this._rotateKeysIfNeeded());
  }

  public close() { this._closed = true; }

  private async _load(openResult: EncryptedDocOpenResult) {
    if (openResult.snapshot) {
      const snapshot = await decryptSnapshot(this._keyring, openResult.snapshot.keyId,
        base64ToBytes(openResult.snapshot.payload));
      this._head = this._snapshotNum = snapshot.actionNum;
      await this._loadSnapshot(snapshot);
    } else if (openResult.actions.length > 0 || openResult.head > 0) {
      throw new Error("Encrypted document has changes but no snapshot to apply them to");
    } else if (this._options.newDocSettings) {
      await this._createNewDoc(this._options.newDocSettings);
      await this._updatePrivacy();
      await this._saveSnapshot();
    } else {
      throw new Error("Encrypted document is not initialized yet");
    }
    await this._engine.call("initialize", null);
    // As the server does when it opens a document, evaluate all formulas (so the engine learns
    // what they depend on), but keeping the values everyone shares: re-evaluating NOW() or
    // RANDBETWEEN() in each browser would give each different values. This must come before
    // applying any change, which would evaluate them.
    await this._engine.call("calculate_exactly", this._options.engineUser);
    this.docData = new DocData(tableId => this.fetchTable(tableId), await this._engine.call("fetch_meta_tables"));
    // Changes since the snapshot; there may be more on the server than were returned.
    await this._catchUp(openResult.actions);

    if (this.canEdit && this._head - this._snapshotNum >= this._snapshotEvery()) {
      await this._saveSnapshot();
    }
    this._loading = false;
  }

  private async _createNewDoc(settings: { timezone: string, locale: string }) {
    await this._engine.call("load_empty");
    await this._engine.call("apply_user_actions", [["InitNewDoc"]]);
    // Like a regular new document (see GRIST_DOC_WITH_TABLE1_SQL).
    await this._engine.call("apply_user_actions", [
      ["UpdateRecord", "_grist_DocInfo", 1, {
        timezone: settings.timezone,
        documentSettings: JSON.stringify({ locale: settings.locale, engine: "python3" }),
      }],
      ["AddEmptyTable", null],
    ]);
  }

  private async _loadSnapshot(snapshot: DocSnapshotPayload) {
    // Which columns are private as of the snapshot (metadata tables are never sealed).
    const privacy = ColumnPrivacy.fromMetaTables(snapshot.tables._grist_Tables, snapshot.tables._grist_Tables_column,
      this._keyring.bindingsAt(snapshot.actionNum));
    this._sealedCells.loadSnapshot(snapshot.tables, snapshot.blobs || []);
    let tables = await unsealTables(snapshot.tables, snapshot.blobs || [], this._keyring, privacy,
      snapshot.actionNum, message => this._log("Snapshot content not respecting private columns", message));
    const docVersion = tables._grist_DocInfo?.[3].schemaVersion?.[0];
    const engineVersion = await this._engine.call("get_version");
    if (typeof docVersion !== "number") { throw new Error("Encrypted snapshot has no schema version"); }
    if (docVersion > engineVersion) {
      throw new Error(`Document was saved by a newer version of Grist (schema ${docVersion} > ${engineVersion})`);
    }
    if (docVersion < engineVersion) {
      tables = await this._migrate(tables);
    }
    const others: string[] = await this._engine.call("load_meta_tables_repr",
      tables._grist_Tables, tables._grist_Tables_column);
    for (const tableId of others) {
      await this._engine.call("load_table_repr", tables[tableId] || ["TableData", tableId, [], {}]);
    }
    // Before computing anything, keep the engine from evaluating what it can't.
    await this._updatePrivacy();
  }

  /** Brings a snapshot made by an older version of Grist up to the current schema. */
  private async _migrate(tables: { [tableId: string]: TableDataAction }) {
    const migrations: DocAction[] = await this._engine.call("create_migrations_repr", tables);
    this._log("Migrating encrypted snapshot", migrations.length);
    const docData = new DocData(async tableId => ({ tableData: tables[tableId] }), null);
    for (const tableId of Object.keys(tables)) { await docData.syncTable(tableId); }
    for (const action of migrations) { docData.receiveAction(action); }
    const result: { [tableId: string]: TableDataAction } = {};
    for (const [tableId, tableData] of docData.getTables()) {
      result[tableId] = tableData.getTableDataAction();
    }
    return result;
  }

  /** Recomputes which columns are private from the engine's metadata, and what not to compute. */
  private async _computePrivacy(): Promise<ColumnPrivacy> {
    return ColumnPrivacy.fromMetaTables(
      await this._engine.call("fetch_table", "_grist_Tables"),
      await this._engine.call("fetch_table", "_grist_Tables_column"),
      this._keyring.bindingsAt(this._head));
  }

  private async _updatePrivacy(privacy?: ColumnPrivacy) {
    this._privacy = privacy || await this._computePrivacy();
    const frozen = this._privacy.frozenColumns(scope => this._keyring.canUseScope(scope));
    if (!isEqual(frozen, this._frozen)) {
      await this._engine.call("set_frozen_columns", frozen);
      this._frozen = frozen;
    }
    // The engine keeps formulas from reading private columns they don't mention.
    const entries = this._privacy.scopeEntries();
    if (!isEqual(entries, this._scopeEntries)) {
      await this._engine.call("set_column_scopes", entries);
      this._scopeEntries = entries;
    }
  }

  private async _exclusive<T>(callback: () => Promise<T>): Promise<T> {
    return this._mutex.runExclusive(async () => {
      if (this._closed) { throw new Error("Document is closed"); }
      return callback();
    });
  }

  private _assertCanEdit() {
    if (!this.canEdit) { throw new Error("No write access"); }
  }

  private _snapshotEvery() { return this._options.snapshotEvery ?? 50; }

  /**
   * Applies user actions locally, and pushes the result to the server, retrying on top of
   * others' changes until accepted. Must be called while holding the mutex.
   */
  private async _applyAndPush(actions: UserAction[], options: ApplyUAOptions,
    flags: { internal?: boolean, skipIfEmpty?: boolean } = {}): Promise<ApplyUAResult> {
    for (let attempt = 1; ; attempt++) {
      if (!this._loading) { await this._rotateKeysIfNeeded(); }
      const result: EngineResult = await this._engine.call("apply_user_actions", actions, this._options.engineUser);
      const stored = result.stored.map(env => env[1]);
      const undo = result.undo.map(env => env[1]);
      if (stored.length === 0 && (flags.skipIfEmpty || !flags.internal)) {
        // Nothing changed, so there's nothing to share.
        return { actionNum: 0, actionHash: null, retValues: result.retValues, isModification: false };
      }
      try {
        this._privacy.checkChange(stored, scope => this._keyring.canUseScope(scope));
      } catch (e) {
        await this._revert(undo);
        throw e;
      }
      // The change may change which columns are private (e.g. new formulas using them): seal
      // values according to both the state before and after it.
      const privacy = stored.some(touchesColumns) ? await this._computePrivacy() : this._privacy;
      const changePrivacy = new ChangePrivacy(this._privacy, privacy);
      const bundle: DocChangeBundle = {
        v: 1,
        userActions: actions,
        stored,
        undo,
        retValues: result.retValues,
        info: {
          time: Date.now(),
          user: this._options.userName,
          inst: "encrypted",
          desc: options.desc,
          otherId: options.otherId || 0,
          linkId: options.linkId || (this._bundling ? this._lastOwnActionNum : 0),
        },
        ...(flags.internal ? { internal: true } : {}),
      };
      let pushResult: EncryptedPushResult;
      let payload: Uint8Array;
      let shared: DocChangeBundle;
      try {
        shared = await this._sealChange(bundle, changePrivacy, this._head + 1);
        payload = await encryptBundle(this._keyring, this._keyring.currentKeyId(DOC_SCOPE), shared);
        pushResult = await this._relay.pushAction(this._head, this._keyring.currentKeyId(DOC_SCOPE),
          bytesToBase64(payload));
      } catch (e) {
        // We don't know if it got through. Revert locally, then check with the server: if it did
        // get through, we'll get it back from there like anyone else's change.
        await this._revert(undo);
        await this._catchUp([]).catch(err => this._log("Could not catch up after failed push", err));
        throw e;
      }
      if (pushResult.accepted) {
        const actionNum = pushResult.actionNum;
        const actionHash = await sha256Hex(payload);
        this._head = actionNum;
        this._rowCount = result.rowCount.total;
        this._sealedCells.applyActions(shared.stored);
        if (privacy !== this._privacy) { await this._updatePrivacy(privacy); }
        if (!flags.internal) { this._lastOwnActionNum = actionNum; }
        this._remember({ actionNum, actionHash, bundle, fromSelf: true });
        this._emit(bundle, stored, undo, result.retValues, { actionNum, actionHash, fromSelf: true });
        this._maybeSnapshotSoon();
        return { actionNum, actionHash, retValues: result.retValues, isModification: stored.length > 0 };
      }
      // Someone else's change got in first (or the document key changed). Undo ours, catch up,
      // and try again.
      this._log(`Push of change on top of ${this._head} refused (server at ${pushResult.head}), retrying`);
      await this._revert(undo);
      await this._catchUp([]);
      if (attempt >= MAX_PUSH_ATTEMPTS) {
        throw new Error("Could not save change: the document is changing too fast, please retry");
      }
    }
  }

  /** Seals the private values of a change (to be numbered actionNum) with their keys. */
  private async _sealChange(bundle: DocChangeBundle, privacy: ChangePrivacy, actionNum: number) {
    return privacy.hasProtectedColumns() ? {
      ...bundle,
      stored: await sealActions(bundle.stored, privacy, this._keyring, actionNum),
      undo: await sealActions(bundle.undo, privacy, this._keyring, actionNum),
      // User actions may include private values too. Others only use their names.
      userActions: bundle.userActions.map(a => a.slice(0, 1) as UserAction),
    } : bundle;
  }

  private async _revert(undo: DocAction[]) {
    if (undo.length === 0) { return; }
    await this._engine.call("apply_user_actions", [["ApplyUndoActions", undo]], this._options.engineUser);
  }

  /**
   * Applies the given changes (typically just received from the server), after fetching any
   * the server has that precede them or that we don't have. Must be called while holding the mutex.
   */
  private async _catchUp(records: EncryptedActionRecord[]) {
    let pending = records.filter(r => r.actionNum > this._head).sort((a, b) => a.actionNum - b.actionNum);
    if (records.length === 0 || (pending.length > 0 && pending[0].actionNum !== this._head + 1)) {
      // Either asked to sync, or there is a gap: get everything after our head.
      pending = await this._fetchAllAfter(this._head);
    }
    for (const record of pending) {
      if (record.actionNum <= this._head) { continue; }
      if (record.actionNum !== this._head + 1) {
        // The server pruned changes we missed (they are covered by snapshots).
        throw new NeedsReloadError("This document changed too much while you were away: please reload it");
      }
      await this._applyRemote(record);
    }
  }

  private async _fetchAllAfter(actionNum: number): Promise<EncryptedActionRecord[]> {
    const result: EncryptedActionRecord[] = [];
    for (;;) {
      const batch = await this._relay.fetchActions(actionNum);
      result.push(...batch);
      if (batch.length === 0) { return result; }
      actionNum = batch[batch.length - 1].actionNum;
    }
  }

  private async _applyRemote(record: EncryptedActionRecord) {
    if (record.kind === "key") {
      // A new key (or a column becoming private or public): get our copy of the key, if we have
      // one. Later entries use it.
      await this._keyring.refresh();
      this._head = record.actionNum;
      await this._updatePrivacy();
      return;
    }
    const payload = base64ToBytes(record.payload);
    let bundle: DocChangeBundle;
    let stored: DocAction[];
    try {
      if (record.keyId !== this._keyring.keyIdAt(DOC_SCOPE, record.actionNum)) {
        throw new Error("not encrypted with the document key");
      }
      bundle = await decryptBundle(this._keyring, record.keyId, payload);
      stored = await unsealActions(bundle.stored, this._keyring, record.actionNum,
        reason => this._reportInvalid(record, reason, false));
    } catch (e) {
      // Not having the key isn't a problem with the change: the member lost access.
      if (e instanceof MissingKeyError) { throw e; }
      return this._skipChange(record, e);
    }
    let result: EngineResult;
    try {
      result = await this._engine.call("apply_doc_actions_exactly", stored, this._options.engineUser);
    } catch (e) {
      return this._skipChange(record, e);
    }
    const localStored = result.stored.map(env => env[1]);
    const undo = result.undo.map(env => env[1]);
    // Changes must seal what's private, before or after them (as of this point in the history).
    const privacy = stored.some(touchesColumns) ? await this._computePrivacy() : this._privacy;
    try {
      checkSealing(bundle.stored, new ChangePrivacy(this._privacy, privacy),
        scope => this._keyring.keyIdAt(scope, record.actionNum));
    } catch (e) {
      await this._revert(undo);
      return this._skipChange(record, e);
    }
    const actionHash = await sha256Hex(payload);
    this._head = record.actionNum;
    this._rowCount = result.rowCount.total;
    this._sealedCells.applyActions(bundle.stored);
    if (privacy !== this._privacy) { await this._updatePrivacy(privacy); }
    // Keep the author's view of the change for history and redo, but our own undo (for our data).
    // The author is the one the server says made the change.
    const info = { ...bundle.info, user: await this._memberLabel(record.userId) };
    const localBundle: DocChangeBundle = { ...bundle, info, stored, undo };
    this._remember({ actionNum: record.actionNum, actionHash, bundle: localBundle, fromSelf: false });
    this._emit(localBundle, localStored, undo, bundle.retValues,
      { actionNum: record.actionNum, actionHash, fromSelf: false });
  }

  /** Shares the values of columns that were private and no longer are, with everyone. */
  private async _shareRevealedValues(before: ColumnPrivacy, after: ColumnPrivacy) {
    const revealed = before.scopeEntries().filter(([tableId, colId]) => after.scopesOf(tableId, colId).length === 0);
    for (let attempt = 1; ; attempt++) {
      const stored: DocAction[] = [];
      for (const [tableId, colId] of revealed) {
        const tableData: TableDataAction | null = await this._engine.call("fetch_table", tableId).catch(() => null);
        if (tableData && tableData[2].length > 0 && tableData[3][colId]) {
          stored.push(["BulkUpdateRecord", tableId, tableData[2], { [colId]: tableData[3][colId] }]);
        }
      }
      if (stored.length === 0) { return; }
      // The engine has these values already: share them as they are.
      const bundle: DocChangeBundle = {
        v: 1, userActions: [["Calculate"]], stored, undo: [], retValues: [null], internal: true,
        info: { time: Date.now(), user: this._options.userName, inst: "encrypted", otherId: 0, linkId: 0 },
      };
      const payload = await encryptBundle(this._keyring, this._keyring.currentKeyId(DOC_SCOPE), bundle);
      const result = await this._relay.pushAction(this._head, this._keyring.currentKeyId(DOC_SCOPE),
        bytesToBase64(payload));
      if (result.accepted) {
        this._head = result.actionNum;
        this._sealedCells.applyActions(stored);
        return;
      }
      await this._catchUp([]);
      if (attempt >= MAX_PUSH_ATTEMPTS) { throw new Error(TOO_FAST_ERROR); }
    }
  }

  /**
   * Skips a change from someone else that can't be applied (see the comment at the top): every
   * browser skips it alike.
   */
  private _skipChange(record: EncryptedActionRecord, error: unknown) {
    this._head = record.actionNum;
    this._reportInvalid(record, String((error as Error)?.message || error), true);
  }

  private _reportInvalid(record: EncryptedActionRecord, reason: string, skipped: boolean) {
    this._log(`${skipped ? "Skipping" : "Locking values of"} change ${record.actionNum} ` +
      `by user ${record.userId}: ${reason}`);
    this._options.onInvalidChange?.({ actionNum: record.actionNum, userId: record.userId, reason, skipped });
  }

  /** How a member appears in the history (their email, as the server knows it). */
  private async _memberLabel(userId: number | null): Promise<string> {
    if (userId === null) { return "?"; }
    if (!this._memberLabels.has(userId)) {
      try {
        for (const member of await this._relay.listMembers()) {
          this._memberLabels.set(member.userId, member.email || member.name);
        }
      } catch (e) {
        this._log("Could not list members", e);
      }
    }
    return this._memberLabels.get(userId) ?? `#${userId}`;
  }

  /** Creates a new key for a scope, recorded after the latest change. Holds the mutex. */
  private async _createKey(scope: string, recipients: (KeyRecipient & { userId: number })[],
    colRef?: number): Promise<string> {
    const wraps = await this._keyring.vault.createDocumentKey(recipients);
    const keyId = makeKeyId(scope);
    const request: NewKeyRequest = {
      scope,
      keyId,
      wraps: recipients.filter(r => wraps.has(r.vaultUserId)).map((r) => {
        const wrap = wraps.get(r.vaultUserId)!;
        return { userId: r.userId, wrappedKey: bytesToBase64(wrap.wrappedKey), keyVersion: wrap.keyVersion };
      }),
      baseActionNum: this._head,
      ...(colRef ? { colRef } : {}),
    };
    for (let attempt = 1; ; attempt++) {
      request.baseActionNum = this._head;
      const result = await this._relay.createKey(request);
      if (result.accepted) {
        this._head = result.actionNum;
        await this._keyring.refresh();
        await this._updatePrivacy();
        return keyId;
      }
      await this._catchUp([]);
      if (attempt >= MAX_PUSH_ATTEMPTS) { throw new Error("Could not create key: the document is changing too fast"); }
    }
  }

  /**
   * Replaces keys flagged for replacement (because someone who held them lost access), giving
   * the new ones to members who held the old ones. Holds the mutex.
   */
  private async _rotateKeysIfNeeded() {
    const scopes = this._keyring.scopesToRotate();
    if (scopes.length === 0) { return; }
    const members = await this._relay.listMembers();
    for (const scope of scopes) {
      const current = this._keyring.currentKey(scope);
      if (!current?.rotateOnNextEdit) { continue; }   // Someone else did it meanwhile.
      const recipients = members
        .filter(m => m.keyIds.includes(current.keyId))
        .map(m => ({ userId: m.userId, vaultUserId: this._options.vaultIdFor(m)!, email: m.email, name: m.name }))
        .filter(r => r.vaultUserId);
      this._log(`Replacing the key of ${scope}, for ${recipients.length} member(s)`);
      try {
        await this._createKey(scope, recipients);
      } catch (e) {
        // Someone else may have replaced it first.
        await this._keyring.refresh();
        if (this._keyring.currentKey(scope)?.keyId === current.keyId) { throw e; }
      }
    }
    // Re-encrypt the document with the new keys, dropping what the server had with the old ones.
    await this._saveSnapshot({ compact: true });
  }

  private _remember(entry: HistoryEntry) {
    this._history.set(entry.actionNum, entry);
    const maxHistory = this._options.maxHistory ?? 100;
    for (const actionNum of this._history.keys()) {
      if (this._history.size <= maxHistory) { break; }
      this._history.delete(actionNum);
    }
  }

  private _emit(bundle: DocChangeBundle, stored: DocAction[], undo: DocAction[], retValues: any[],
    meta: { actionNum: number, actionHash: string, fromSelf: boolean }) {
    for (const action of stored) { this.docData.receiveAction(action); }
    if (this._loading) { return; }
    const actionGroup = makeActionGroup(bundle, stored, undo, retValues, meta);
    this._options.onDocUserAction({
      docActions: stored, actionGroup, fromSelf: meta.fromSelf, rowCount: this._rowCount,
    });
  }

  private _maybeSnapshotSoon() {
    if (this._head - this._snapshotNum < this._snapshotEvery()) { return; }
    // Don't hold up the change that triggered it.
    setTimeout(() => {
      if (this._closed) { return; }
      this._exclusive(() => this._saveSnapshot()).catch(e => this._log("Saving snapshot failed", e));
    }, 0);
  }

  /**
   * Saves a snapshot. Private columns the member can't read are given by reference to the sealed
   * values the member received (see SealedCells.ts); if that's not possible (e.g. a column just
   * became private), the snapshot is left for others to make.
   */
  private async _saveSnapshot(options: { compact?: boolean } = {}) {
    if (!this._keyring.canUseScope(DOC_SCOPE)) { return; }
    if (this._snapshotNum === this._head && this._head > 0 && !options.compact) { return; }
    const tables = await this._engine.call("fetch_all_tables");
    const blobs = new BlobTable();
    let sealed: { [tableId: string]: any };
    try {
      sealed = await sealTables(tables, this._privacy, this._keyring, this._head, blobs,
        (tableId, colId, rowIds, values) => this._sealedCells.export(tableId, colId,
          this._privacy.getColumn(tableId, colId)?.type || "Any", rowIds, values, blobs));
    } catch (e) {
      if (!(e instanceof CannotCarryError)) { throw e; }
      this._log("Leaving the snapshot to members who can read all columns:", e.message);
      return;
    }
    const snapshot: DocSnapshotPayload = {
      v: 1,
      actionNum: this._head,
      tables: sealed,
      ...(blobs.blobs.length > 0 ? { blobs: blobs.blobs } : {}),
    };
    const keyId = this._keyring.currentKeyId(DOC_SCOPE);
    const payload = await encryptSnapshot(this._keyring, keyId, snapshot);
    await this._relay.saveSnapshot(snapshot.actionNum, keyId, bytesToBase64(payload), options);
    this._snapshotNum = snapshot.actionNum;
  }
}

// Whether an action may change which columns are private (or their formulas).
function touchesColumns(action: DocAction): boolean {
  const tableId = getTableId(action);
  return tableId === "_grist_Tables_column" || tableId === "_grist_Tables" || isSchemaAction(action);
}

function getPrimaryAction(bundle: DocChangeBundle): string {
  return String((bundle.userActions[0] || [""])[0]);
}

/** Builds the ActionGroup the client expects for a change (see asActionGroup on the server). */
function makeActionGroup(bundle: DocChangeBundle, stored: DocAction[], undo: DocAction[], retValues: any[],
  meta: { actionNum: number, actionHash: string, fromSelf: boolean }): ActionGroup {
  const localActionBundle: LocalActionBundle = {
    actionNum: meta.actionNum,
    actionHash: meta.actionHash,
    parentActionHash: null,
    envelopes: [],
    info: [0, bundle.info],
    stored: stored.map(a => [0, a]),
    calc: [],
    undo,
    userActions: bundle.userActions,
  };
  let rowIdHint = 0;
  for (const [i, action] of bundle.userActions.entries()) {
    if (action[0] === "AddRecord") { rowIdHint = retValues[i]; break; }
    if (action[0] === "BulkAddRecord") { rowIdHint = retValues[i]?.[0]; break; }
  }
  const primaryAction = getPrimaryAction(bundle);
  let actionSummary;
  try {
    actionSummary = summarizeAction(localActionBundle);
  } catch (e) {
    actionSummary = createEmptyActionSummary();
  }
  return {
    actionNum: meta.actionNum,
    actionHash: meta.actionHash,
    desc: bundle.info.desc,
    actionSummary,
    fromSelf: meta.fromSelf,
    linkId: bundle.info.linkId,
    otherId: bundle.info.otherId,
    time: bundle.info.time,
    user: bundle.info.user,
    rowIdHint: rowIdHint || 0,
    primaryAction,
    isUndo: primaryAction === "ApplyUndoActions",
    internal: Boolean(bundle.internal),
  };
}

export { EncryptionAccessError };
