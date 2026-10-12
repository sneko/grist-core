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
 * When a column is made public again, members holding its key share its values, in clear, with
 * everyone (see _revealIfNeeded()). Until that's done, which any of them can do (it's retried
 * whenever the document is opened or its keys change), snapshots aren't saved, as members
 * without the key would otherwise save the values they had locked as the column's values.
 *
 * The rest of the client sees nothing of this: it gets the same doc actions and action groups it
 * would get from the server for a regular document. This class has no browser dependencies, so
 * that it can be tested under Node; the engine, relay and vault are supplied by the caller.
 */
import { LocalActionBundle } from "app/common/ActionBundle";
import { ActionGroup, MinimalActionGroup } from "app/common/ActionGroup";
import { summarizeAction } from "app/common/ActionSummarizer";
import { createEmptyActionSummary } from "app/common/ActionSummary";
import {
  ApplyUAOptions, ApplyUAResult, QueryResult, ServerQuery, TableFetchResult,
} from "app/common/ActiveDocAPI";
import { CellValue, DocAction, getTableId, isSchemaAction, TableDataAction, UserAction } from "app/common/DocActions";
import { DocData } from "app/common/DocData";
import {
  BlobTable, ChangePrivacy, checkMetaAccess, checkSealing, ColumnPrivacy, EncryptionAccessError, hasPrivateMetaFields,
  isLockedCell, metaCellScopes, MetaContext, MetaLookup, MetaRows, sealActions, sealTables, unsealActions,
  unsealTables,
} from "app/common/encryption/ColumnPrivacy";
import { decryptFile, encryptFile, makeFileIdent, parseFileIdent } from "app/common/encryption/EncryptedAttachments";
import {
  decryptBundle, decryptKeyRecord, decryptSnapshot, decryptSuggestion, DocChangeBundle, DocSnapshotPayload,
  encryptBundle, encryptKeyRecord, encryptSnapshot, encryptSuggestion,
} from "app/common/encryption/EncryptedPayloads";
import { base64ToBytes, bytesToBase64, KeyRecipient, sha256Hex } from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, EncryptedActionRecord, EncryptedDocOpenResult,
  EncryptedInboxEntry, EncryptedPushResult, EncryptedSnapshotRecord, EncryptedSuggestion, EncryptionKeysResult,
  EncryptionMember, KeyChangeRecord, makeKeyId, NewKeyRequest,
} from "app/common/encryption/EncryptionTypes";
import { Keyring, MissingKeyError, TamperedKeysError } from "app/common/encryption/Keyring";
import { IDataEngine } from "app/common/encryption/PyodideEngine";
import { CannotCarryError, SealedCells } from "app/common/encryption/SealedCells";

import { Mutex } from "async-mutex";
import flatten from "lodash/flatten";
import isEqual from "lodash/isEqual";

/** The server side of an encrypted document, as LocalActiveDoc needs it. */
export interface IEncryptionRelay {
  fetchActions(afterActionNum: number): Promise<EncryptedActionRecord[]>;
  // With consumeInbox, answers to forms are removed from the inbox along with the change.
  pushAction(baseActionNum: number, keyId: string, payload: Base64,
    options?: { consumeInbox?: number[] }): Promise<EncryptedPushResult>;
  // Snapshots and files may be too big for a single message: the relay moves them by parts.
  saveSnapshot(actionNum: number, keyId: string, payload: Uint8Array, options?: { compact?: boolean }): Promise<void>;
  // The payload of a snapshot returned by opening the document, if it wasn't included.
  fetchSnapshot(snapshot: EncryptedSnapshotRecord): Promise<Uint8Array>;
  uploadFile(ciphertext: Uint8Array): Promise<{ fileId: string }>;
  fetchFile(fileId: string): Promise<Uint8Array>;
  getKeys(): Promise<EncryptionKeysResult>;
  listMembers(): Promise<EncryptionMember[]>;
  // With `snapshot`, it's saved along with the key change (see NewKeyRequest).
  createKey(request: NewKeyRequest, snapshot?: { payload: Uint8Array, compact: boolean }): Promise<EncryptedPushResult>;
  // With `record`, the encrypted KeyChangeRecord of the change (see KeyHistory).
  releaseScope(scope: string, baseActionNum: number, record?: Base64): Promise<EncryptedPushResult>;
  getSnapshot(actionNum: number): Promise<EncryptedSnapshotRecord>;
  restoreSnapshot(baseActionNum: number, keyId: string, payload: Uint8Array): Promise<EncryptedPushResult>;
  submitSuggestion(keyId: string, payload: Base64): Promise<number>;
  listInbox(): Promise<EncryptedInboxEntry[]>;
  dropInbox(ids: number[]): Promise<void>;
  listSuggestions(): Promise<EncryptedSuggestion[]>;
  resolveSuggestion(id: number): Promise<void>;
}

/** Changes suggested by a member, as listed for members who can apply them. */
export interface SuggestionInfo {
  id: number;
  userId: number | null;
  timeMs: number;
  desc: string;
  userActions: UserAction[];
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
  // For members who can't edit: whether they may suggest changes (made locally, and sent as a
  // suggestion for members who can edit to apply, see submitSuggestion()).
  canSuggest?: boolean;
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
  // Called when keys flagged for replacement couldn't be replaced before an edit: the edit still
  // goes through with the current keys, and replacing them is tried again on the next one.
  onRotationFailed?: (error: Error) => void;
  // Called as each step of opening the document is done (to measure them).
  onOpenStep?: (step: string) => void;
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

/** Thrown when someone restored an earlier version of the document: it must be reopened. */
export class DocRestoredError extends NeedsReloadError {
  constructor(public readonly userId: number | null) {
    super("An earlier version of this document was restored: please reload it");
  }
}

/** The whole content of the document, readable. */
export interface PlainDocContent {
  actionNum: number;
  tables: { [tableId: string]: TableDataAction };
}

// A snapshot ready to be saved (see _buildSnapshot()).
interface BuiltSnapshot {
  actionNum: number;
  keyId: string;
  payload: Uint8Array;
  sealed: { [tableId: string]: any };
  blobs: BlobTable;
}

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

// How many cells to share at once when revealing the values of columns made public (and how
// many times at most, in one go).
const REVEAL_BATCH_CELLS = 5000;
const MAX_REVEAL_BATCHES = 1000;

// Formulas depending on the current time are updated hourly, by one member for all.
const CURRENT_TIME_UPDATE_MS = 60 * 60 * 1000;

interface PushFlags {
  internal?: boolean;
  skipIfEmpty?: boolean;
  // Answers to forms the change adds (see importFormAnswers()).
  consumeInbox?: number[];
}

/** Raised to stop retrying a push (see _retryOnConflict). */
const CONFLICT = Symbol("conflict");

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
  // Why the document can't be used anymore, if not just closed (e.g. someone restored an earlier version).
  private _closedBy?: Error;
  // While loading, nobody is listening for changes yet: they are reflected in what gets fetched.
  private _loading = true;
  private _privacy = new ColumnPrivacy([]);
  private _frozen: [string, string][] = [];
  private _scopeEntries: [string, string, string[]][] = [];
  private _sealedCells = new SealedCells();
  private _memberLabels = new Map<number, string>();
  // The document key the latest snapshot is encrypted with.
  private _snapshotKeyId: string | null = null;
  // When formulas depending on the current time were last updated (by anyone), as known here.
  private _lastTimeUpdateMs = 0;
  private _revealScheduled = false;
  private _reservedTableRefs: number[] = [];
  private _reservedColRefs: number[] = [];
  // Changes made while suggesting (see submitSuggestion()), applied locally only, and changes from
  // others held back meanwhile (they're applied once the suggestion is sent or discarded).
  private _pending: { num: number, actions: UserAction[], undo: DocAction[] }[] = [];
  private _nextPendingNum = -1;
  private _heldBack: EncryptedActionRecord[] = [];
  private _nextQuerySubId = 1;

  private constructor(private _options: LocalActiveDocOptions) {
    this._engine = _options.engine;
    this._relay = _options.relay;
    this._keyring = _options.keyring;
    this._log = _options.log || (() => {});
  }

  // The member's user id (as the data engine knows it).
  private get _userId(): number | null {
    return (this._options.engineUser as { UserID?: number }).UserID ?? null;
  }

  /** The number of the latest change applied locally. */
  public get head() { return this._head; }

  public get canEdit() { return this._options.canEdit; }

  public get keyring() { return this._keyring; }

  /** Whether the member can read all of the document's content. */
  public get canReadAll() { return this._keyring.canReadAll(this._head); }

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

  /**
   * Serves the rows of a table matching a query, as the server does for "on-demand" tables
   * (which it doesn't load into its data engine). Here all tables are in the engine anyway: this
   * just filters them. Every change gets to the client anyway, so there's no subscription to keep.
   */
  public async useQuerySet(query: ServerQuery): Promise<QueryResult> {
    const { tableData } = await this.fetchTable(query.tableId);
    const [, tableId, rowIds, columns] = tableData;
    const filters = Object.entries(query.filters || {});
    const kept: number[] = [];
    for (const [i] of rowIds.entries()) {
      if (filters.every(([colId, values]) => values.some(v => isEqual(v, columns[colId]?.[i])))) { kept.push(i); }
      if (query.limit && kept.length >= query.limit) { break; }
    }
    const filtered: TableDataAction = ["TableData", tableId, kept.map(i => rowIds[i]),
      Object.fromEntries(Object.entries(columns).map(([colId, values]) => [colId, kept.map(i => values[i])]))];
    return { tableData: filtered, querySubId: this._nextQuerySubId++ };
  }

  public async applyUserActions(actions: UserAction[], options?: ApplyUAOptions): Promise<ApplyUAResult> {
    if (this.isSuggesting) { return this._exclusive(() => this._applySuggested(actions)); }
    this._assertCanEdit();
    return this._exclusive(() => this._applyAndPush(actions, options || {}));
  }

  /**
   * Adds answers to the document's forms, waiting in its inbox (see EncryptedForms.ts), as a
   * change that removes them from the inbox at the same time. `read` decrypts the inbox entries
   * given, and returns the user actions adding what can be added, and which entries can't (to be
   * dropped). Answers this member can't add (e.g. requiring keys they don't hold) are left for
   * others. Returns how many answers were added.
   */
  public async importFormAnswers(read: (entries: EncryptedInboxEntry[]) => Promise<{
    actions: UserAction[], ids: number[], invalid: number[],
  }>): Promise<number> {
    if (!this.canEdit || !this._keyring.canUseScope(DOC_SCOPE)) { return 0; }
    return this._exclusive(async () => {
      for (let attempt = 1; attempt <= MAX_PUSH_ATTEMPTS; attempt++) {
        const entries = await this._relay.listInbox();
        if (entries.length === 0) { return 0; }
        const { actions, ids, invalid } = await read(entries);
        if (invalid.length > 0) { await this._relay.dropInbox(invalid); }
        if (ids.length === 0) { return 0; }
        const result = await this._tryApplyAndPush(actions, { desc: "Form answers" }, { consumeInbox: ids });
        if (result !== CONFLICT) { return ids.length; }
        // Someone else's change got in first, or they added these answers: see what's left.
        await this._catchUp([]);
      }
      throw new Error(TOO_FAST_ERROR);
    });
  }

  /** Whether changes are suggestions (see submitSuggestion()). */
  public get isSuggesting() { return !this.canEdit && Boolean(this._options.canSuggest); }

  /** How many changes are waiting to be sent as a suggestion. */
  public get pendingSuggestionCount() { return this._pending.length; }

  /**
   * Sends the changes made while suggesting (for members who can't edit the document), as a
   * suggestion that members who can edit it may apply. They're undone locally meanwhile.
   */
  public async submitSuggestion(desc: string): Promise<number> {
    return this._exclusive(async () => {
      if (this._pending.length === 0) { throw new Error("There are no changes to suggest"); }
      const keyId = this._keyring.currentKeyId(DOC_SCOPE);
      const payload = await encryptSuggestion(this._keyring, keyId, {
        v: 1, userActions: flatten(this._pending.map(p => p.actions)), desc, time: Date.now(),
      });
      const id = await this._relay.submitSuggestion(keyId, bytesToBase64(payload));
      await this._dropPending();
      return id;
    });
  }

  /** Undoes the changes made while suggesting, without sending them. */
  public async discardSuggestion(): Promise<void> {
    return this._exclusive(() => this._dropPending());
  }

  /**
   * Suggestions waiting to be handled (all of them for members who can edit the document; their
   * own for others), readable.
   */
  public async listSuggestions(): Promise<SuggestionInfo[]> {
    const result: SuggestionInfo[] = [];
    for (const suggestion of await this._relay.listSuggestions()) {
      try {
        const bundle = await decryptSuggestion(this._keyring, suggestion.keyId, base64ToBytes(suggestion.payload));
        result.push({ id: suggestion.id, userId: suggestion.userId, timeMs: suggestion.timeMs, desc: bundle.desc,
          userActions: bundle.userActions });
      } catch (e) {
        this._log("Skipping a suggestion that can't be read", e);
      }
    }
    return result;
  }

  /** Applies a suggestion (as a change by this member, who must be able to edit), and removes it. */
  public async applySuggestion(id: number): Promise<ApplyUAResult> {
    this._assertCanEdit();
    const suggestion = (await this.listSuggestions()).find(s => s.id === id);
    if (!suggestion) { throw new Error("This suggestion was already handled"); }
    const label = await this._memberLabel(suggestion.userId);
    const result = await this.applyUserActions(suggestion.userActions,
      { desc: `Suggested by ${label}${suggestion.desc ? `: ${suggestion.desc}` : ""}` });
    await this._relay.resolveSuggestion(id);
    return result;
  }

  /** Removes a suggestion without applying it (or withdraws one's own). */
  public async dismissSuggestion(id: number): Promise<void> {
    await this._relay.resolveSuggestion(id);
  }

  /** Redo (or undo, if `undo` is set) changes identified by number and hash. */
  public async applyUserActionsById(actionNums: number[], actionHashes: string[], undo: boolean,
    options?: ApplyUAOptions): Promise<ApplyUAResult> {
    if (this.isSuggesting) {
      return this._exclusive(() => this._undoOrRedoSuggested(actionNums, undo));
    }
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

  /** The description of the document's structure given to an AI assistant, for a formula. */
  public async getFormulaPrompt(tableId: string, colId: string,
    options: { includeAllTables: boolean, includeLookups: boolean }): Promise<string> {
    return this._exclusive(() => this._engine.call("get_formula_prompt", tableId, colId,
      options.includeAllTables, options.includeLookups));
  }

  /** The formula an AI assistant's answer suggests (empty if none). */
  public async convertFormulaCompletion(completion: string): Promise<string> {
    return this._exclusive(() => this._engine.call("convert_formula_completion", completion));
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
      // Every member's browser calls this: only one needs to do it.
      if (Date.now() - this._lastTimeUpdateMs < CURRENT_TIME_UPDATE_MS) { return; }
      await this._applyAndPush([["UpdateCurrentTime"]], {}, { internal: true, skipIfEmpty: true });
      this._lastTimeUpdateMs = Date.now();
    });
  }

  /**
   * Creates the key of a new scope (e.g. for new private columns), for the given members. The
   * key change is recorded in the history, ordered like any change.
   */
  public async createScopeKey(scope: string, recipients: (KeyRecipient & { userId: number })[],
    colRef?: number, options: { compact?: boolean } = {}): Promise<string> {
    this._assertCanEdit();
    return this._exclusive(async () => {
      const keyId = (await this._createKey(scope, recipients, colRef, undefined, options))!;
      // If the snapshot couldn't go along (see _createKey()), drop the history now.
      if (options.compact && this._snapshotNum !== this._head) { await this._saveSnapshot({ compact: true }); }
      return keyId;
    });
  }

  /**
   * Replaces the content of the document with that of an earlier snapshot (by an owner who can
   * read all of it). It gets encrypted again with the current keys, and saved as a new snapshot,
   * recorded in the history: every browser then reloads the document.
   */
  public async restoreSnapshot(actionNum: number): Promise<void> {
    this._assertCanEdit();
    return this._exclusive(async () => {
      const record = await this._relay.getSnapshot(actionNum);
      const step = (name: string) => this._options.onOpenStep?.(name);
      const payload = record.payload ? base64ToBytes(record.payload) : await this._relay.fetchSnapshot(record);
      step(`fetch snapshot (${Math.round(payload.length / 1024)} KB)`);
      const snapshot = await decryptSnapshot(this._keyring, record.keyId, payload);
      step("decrypt snapshot");
      if (snapshot.actionNum !== record.actionNum) { throw new Error("Encrypted snapshot doesn't match the document"); }
      const privacyThen = ColumnPrivacy.fromMetaTables(snapshot.tables._grist_Tables,
        snapshot.tables._grist_Tables_column, this._keyring.bindingsAt(snapshot.actionNum));
      let tables = await unsealTables(snapshot.tables, snapshot.blobs || [], this._keyring, privacyThen,
        snapshot.actionNum, (message) => { throw new Error(`This version can't be restored: ${message}`); });
      if (hasLockedCells(tables)) { throw new Error("This version can't be restored: some of its values are locked"); }
      const docVersion = tables._grist_DocInfo?.[3].schemaVersion?.[0];
      if (typeof docVersion !== "number" || docVersion > await this._engine.call("get_version")) {
        throw new Error("This version can't be restored by this version of Grist");
      }
      tables = await this._migrate(tables);
      await this._retryOnConflict(async () => {
        const restoreNum = this._head + 1;
        const privacy = ColumnPrivacy.fromMetaTables(tables._grist_Tables, tables._grist_Tables_column,
          this._keyring.bindingsAt(restoreNum));
        const built = await this._buildSnapshot(restoreNum, privacy, tables, null);
        const result = await this._relay.restoreSnapshot(this._head, built!.keyId, built!.payload);
        if (!result.accepted) { return CONFLICT; }
        this._head = result.actionNum;
      });
      // This document is gone: it must be opened again.
      this._closed = true;
    });
  }

  /**
   * Returns the whole content of the document, readable (by a member who can read all of it), e.g.
   * to make it a regular document again. With `extraActions` (e.g. adding access rules), returns
   * the content as it would be after them (they're not applied to the document). Their results
   * are passed to the next ones (in a function), e.g. to refer to records added.
   */
  public async exportPlain(extraActions: ((previous: any[]) => UserAction[])[] = []): Promise<PlainDocContent> {
    return this._exclusive(async () => {
      await this._catchUp([]);
      if (!this._keyring.canReadAll(this._head)) {
        throw new Error("Only members who can read everything can do this");
      }
      const undos: DocAction[][] = [];
      try {
        let previous: any[] = [];
        for (const makeActions of extraActions) {
          const result: EngineResult = await this._engine.call("apply_user_actions", makeActions(previous),
            this._options.engineUser);
          undos.push(result.undo.map(env => env[1]));
          previous = result.retValues;
        }
        const tables: { [tableId: string]: TableDataAction } = await this._engine.call("fetch_all_tables");
        if (hasLockedCells(tables)) {
          throw new Error("Some values of this document are locked: they must be set again first");
        }
        return { actionNum: this._head, tables };
      } finally {
        for (const undo of undos.reverse()) { await this._revert(undo); }
      }
    });
  }

  /**
   * Returns a fresh snapshot of the whole content of the document, as a new document would start
   * from (all of it readable: for a member who can read all of it), e.g. for a copy of it.
   */
  public async exportSnapshotTables(): Promise<{ [tableId: string]: TableDataAction }> {
    return (await this.exportPlain()).tables;
  }

  /**
   * Makes a private column public again (its scope no longer protects it). Members who couldn't
   * read it get its values (and those of formulas that were private because of it) in a change
   * that follows.
   */
  public async releaseScope(scope: string): Promise<void> {
    this._assertCanEdit();
    return this._exclusive(async () => {
      await this._retryOnConflict(async () => {
        const record: KeyChangeRecord = {
          v: 1, actionNum: this._head + 1, scope, keyId: this._keyring.currentKeyId(scope), release: true,
        };
        const payload = await encryptKeyRecord(this._keyring, this._keyring.currentKeyId(DOC_SCOPE), record);
        const result = await this._relay.releaseScope(scope, this._head, bytesToBase64(payload));
        if (!result.accepted) { return CONFLICT; }
        this._head = result.actionNum;
        await this._keyring.refresh();
        this._keyring.recordKeyChange(record);
        await this._updatePrivacy();
      });
      // If this doesn't get done now, it gets done later (see _revealIfNeeded()).
      await this._revealIfNeeded().catch(e => this._log("Could not share the values made public yet", e));
    });
  }

  /** Gets the latest state of keys (e.g. when the server says they changed). */
  public async refreshKeys(): Promise<void> {
    return this._exclusive(async () => {
      await this._keyring.refresh();
      await this._updatePrivacy();
      await this._revealIfNeeded().catch(e => this._log("Could not share the values made public yet", e));
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
      const record = openResult.snapshot;
      const step = (name: string) => this._options.onOpenStep?.(name);
      const payload = record.payload ? base64ToBytes(record.payload) : await this._relay.fetchSnapshot(record);
      step(`fetch snapshot (${Math.round(payload.length / 1024)} KB)`);
      const snapshot = await decryptSnapshot(this._keyring, record.keyId, payload);
      step("decrypt snapshot");
      if (snapshot.actionNum !== record.actionNum) { throw new Error("Encrypted snapshot doesn't match the document"); }
      this._head = this._snapshotNum = snapshot.actionNum;
      this._snapshotKeyId = record.keyId;
      // What members recorded of keys and private columns (documents from before such records
      // start one from what the server says now).
      if (snapshot.keyHistory) {
        this._keyring.setHistory(snapshot.keyHistory);
      } else {
        await this._keyring.initHistory();
      }
      await this._loadSnapshot(snapshot);
      step("load snapshot into engine");
    } else if (openResult.actions.length > 0 || openResult.head > 0) {
      throw new Error("Encrypted document has changes but no snapshot to apply them to");
    } else if (this._options.newDocSettings) {
      await this._keyring.initHistory();
      await this._createNewDoc(this._options.newDocSettings);
      await this._updatePrivacy();
      await this._saveSnapshot();
    } else {
      throw new Error("Encrypted document is not initialized yet");
    }
    await this._engine.call("initialize", null);
    this._options.onOpenStep?.("initialize engine");
    // As the server does when it opens a document, evaluate all formulas (so the engine learns
    // what they depend on), but keeping the values everyone shares: re-evaluating NOW() or
    // RANDBETWEEN() in each browser would give each different values. This must come before
    // applying any change, which would evaluate them.
    await this._engine.call("calculate_exactly", this._options.engineUser);
    this._options.onOpenStep?.("calculate formulas");
    this.docData = new DocData(tableId => this.fetchTable(tableId), await this._engine.call("fetch_meta_tables"));
    // Changes since the snapshot; there may be more on the server than were returned.
    const headBefore = this._head;
    await this._catchUp(openResult.actions);
    this._options.onOpenStep?.(`apply changes since snapshot (${this._head - headBefore})`);

    this._loading = false;
    if (this.canEdit) {
      // Values of columns made public may not have been shared yet.
      await this._revealIfNeeded().catch(e => this._log("Could not share the values made public yet", e));
      if (this._isSnapshotDue()) { await this._saveSnapshot(); }
    }
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
    // Columns are made private by their row id: new columns mustn't get one of a removed private
    // column (see set_reserved_row_ids in direct_sandbox.py).
    const reserved = this._keyring.boundColRefs();
    if (!isEqual(reserved, this._reservedColRefs)) {
      await this._engine.call("set_reserved_row_ids", "_grist_Tables_column", reserved);
      this._reservedColRefs = reserved;
    }
    // Likewise for private tables.
    const reservedTables = this._keyring.boundTableRefs();
    if (!isEqual(reservedTables, this._reservedTableRefs)) {
      await this._engine.call("set_reserved_row_ids", "_grist_Tables", reservedTables);
      this._reservedTableRefs = reservedTables;
    }
  }

  /**
   * What deciding which metadata cells are private needs (see ColumnPrivacy.metaCellScopes()),
   * as of the latest change applied (the client's docData is updated after each change).
   */
  private _metaContext(lookup?: MetaLookup): MetaContext {
    const fromDocData: MetaLookup = (tableId, rowId, colId) => this.docData?.getTable(tableId)?.getValue(rowId, colId);
    return {
      rows: new MetaRows(lookup || fromDocData),
      keyScope: keyId => this._keyring.getKey(keyId)?.scope,
    };
  }

  /**
   * Pushes something to the history (calling tryOnce, which returns CONFLICT if the server
   * refused it), catching up and retrying when others' changes got in first.
   */
  private async _retryOnConflict<T>(tryOnce: () => Promise<T | typeof CONFLICT>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      const result = await tryOnce();
      if (result !== CONFLICT) { return result; }
      await this._catchUp([]);
      if (attempt >= MAX_PUSH_ATTEMPTS) { throw new Error(TOO_FAST_ERROR); }
    }
  }

  private async _exclusive<T>(callback: () => Promise<T>): Promise<T> {
    return this._mutex.runExclusive(async () => {
      if (this._closed) { throw this._closedBy || new Error("Document is closed"); }
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
   *
   * A change is only ever shared once accepted by the server, which only accepts it on top of
   * the latest change, and encrypted with the current document key. If someone else's change, or
   * a new key, got in first, the change is undone locally, and computed again on top of the
   * latest state (with the new key, if the member got it: otherwise, it fails).
   */
  private async _applyAndPush(actions: UserAction[], options: ApplyUAOptions,
    flags: PushFlags = {}): Promise<ApplyUAResult> {
    return this._retryOnConflict(() => this._tryApplyAndPush(actions, options, flags));
  }

  /** One attempt of _applyAndPush(): returns CONFLICT if the server refused the change. */
  private async _tryApplyAndPush(actions: UserAction[], options: ApplyUAOptions,
    flags: PushFlags = {}): Promise<ApplyUAResult | typeof CONFLICT> {
    if (!this._loading) { await this._tryRotatingKeys(); }
    const result: EngineResult = await this._engine.call("apply_user_actions", actions, this._options.engineUser);
    const stored = result.stored.map(env => env[1]);
    const undo = result.undo.map(env => env[1]);
    if (stored.length === 0 && (flags.skipIfEmpty || !flags.internal)) {
      // Nothing changed, so there's nothing to share.
      return { actionNum: 0, actionHash: null, retValues: result.retValues, isModification: false };
    }
    // The change may change which columns are private (e.g. new formulas using them): seal
    // values according to both the state before and after it.
    const privacy = stored.some(touchesColumns) ? await this._computePrivacy() : this._privacy;
    const changePrivacy = new ChangePrivacy(this._privacy, privacy);
    const canUseScope = (scope: string) => this._keyring.canUseScope(scope);
    try {
      this._privacy.checkChange(stored, canUseScope);
      checkMetaAccess([...stored, ...[...undo].reverse()], changePrivacy, this._metaContext(), canUseScope);
    } catch (e) {
      await this._revert(undo);
      throw e;
    }
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
        bytesToBase64(payload), flags.consumeInbox ? { consumeInbox: flags.consumeInbox } : undefined);
    } catch (e) {
      // We don't know if it got through. Revert locally, then check with the server: if it did
      // get through, we'll get it back from there like anyone else's change.
      await this._revert(undo);
      await this._catchUp([]).catch(err => this._log("Could not catch up after failed push", err));
      throw e;
    }
    if (!pushResult.accepted) {
      // Someone else's change got in first (or the document key changed). Undo ours, catch up,
      // and try again.
      this._log(`Push of change on top of ${this._head} refused (server at ${pushResult.head}), retrying`);
      await this._revert(undo);
      return CONFLICT;
    }
    const actionNum = pushResult.actionNum;
    const actionHash = await sha256Hex(payload);
    this._head = actionNum;
    this._rowCount = result.rowCount.total;
    this._sealedCells.applyActions(shared.stored);
    if (privacy !== this._privacy) { await this._updatePrivacy(privacy); }
    if (!flags.internal) { this._lastOwnActionNum = actionNum; }
    this._noteTimeUpdate(bundle);
    this._remember({ actionNum, actionHash, bundle, fromSelf: true });
    this._emit(bundle, stored, undo, result.retValues, { actionNum, actionHash, fromSelf: true });
    this._maybeSnapshotSoon();
    return { actionNum, actionHash, retValues: result.retValues, isModification: stored.length > 0 };
  }

  /**
   * Seals the private values of a change (to be numbered actionNum) with their keys. Changes
   * involving private values only share what can't reveal them in clear: the names of their user
   * actions (whose arguments may be values), and only numbers as results.
   */
  private async _sealChange(bundle: DocChangeBundle, privacy: ChangePrivacy, actionNum: number) {
    // Undo actions come after the change, so both are sealed with the same (continued) context.
    // (They're listed in reverse order, as ApplyUndoActions takes them.)
    const ctx = this._metaContext();
    const stored = await sealActions(bundle.stored, privacy, this._keyring, actionNum, ctx);
    const undo = (await sealActions([...bundle.undo].reverse(), privacy, this._keyring, actionNum, ctx)).reverse();
    const sealedAny = stored.some((a, i) => a !== bundle.stored[i]) || undo.some((a, i) => a !== bundle.undo[i]);
    if (!sealedAny && !privacy.hasProtectedColumns()) { return bundle; }
    return {
      ...bundle,
      stored,
      undo,
      userActions: bundle.userActions.map(a => a.slice(0, 1) as UserAction),
      retValues: bundle.retValues.map(onlyNumbers),
      info: { ...bundle.info, desc: undefined },
    };
  }

  /** Undoes a change applied locally (not shared), restoring formula values exactly. */
  private async _revert(undo: DocAction[]) {
    if (undo.length === 0) { return; }
    // (Undo actions are listed in reverse order, as ApplyUndoActions takes them.)
    await this._engine.call("apply_doc_actions_exactly", [...undo].reverse(), this._options.engineUser);
  }

  /**
   * Applies the given changes (typically just received from the server), after fetching any
   * the server has that precede them or that we don't have. Must be called while holding the mutex.
   */
  private async _catchUp(records: EncryptedActionRecord[]) {
    if (this._pending.length > 0) {
      // Changes from others wait until the suggestion being made is sent or discarded.
      this._heldBack.push(...records);
      return;
    }
    let pending = records.filter(r => r.actionNum > this._head).sort((a, b) => a.actionNum - b.actionNum);
    if (records.length === 0) {
      // Asked to sync: get everything after our head.
      pending = await this._fetchAllAfter(this._head);
    }
    for (let i = 0; i < pending.length; i++) {
      const record = pending[i];
      if (record.actionNum <= this._head) { continue; }
      if (record.actionNum !== this._head + 1) {
        // We missed some changes (e.g. while disconnected): get them, with all that follow.
        pending = await this._fetchAllAfter(this._head);
        if (pending[0]?.actionNum !== this._head + 1) {
          // The server pruned changes we missed (they are covered by snapshots).
          throw new NeedsReloadError("This document changed too much while you were away: please reload it");
        }
        i = -1;
        continue;
      }
      await this._applyRemote(record);
    }
  }

  private async _fetchAllAfter(actionNum: number): Promise<EncryptedActionRecord[]> {
    const result: EncryptedActionRecord[] = [];
    for (;;) {
      const batch = await this._relay.fetchActions(actionNum);
      if (batch.length === 0) { return result; }
      // Each batch must move forward, in order (or we'd never be done).
      for (const record of batch) {
        if (!(record.actionNum > actionNum)) { throw new Error("Invalid changes received from the server"); }
        actionNum = record.actionNum;
        result.push(record);
      }
    }
  }

  private async _applyRemote(record: EncryptedActionRecord) {
    if (record.kind === "restore") {
      // The document was replaced: this one can't be followed anymore.
      this._closed = true;
      this._closedBy = new DocRestoredError(record.userId);
      throw this._closedBy;
    }
    if (record.kind === "key") {
      // A new key (or a column becoming private or public): get our copy of the key, if we have
      // one. Later entries use it.
      await this._keyring.refresh();
      await this._checkKeyEntry(record);
      this._head = record.actionNum;
      await this._updatePrivacy();
      this._maybeRevealSoon();
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
        scope => this._keyring.keyIdAt(scope, record.actionNum), this._metaContext());
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
    this._noteTimeUpdate(bundle);
    this._remember({ actionNum: record.actionNum, actionHash, bundle: localBundle, fromSelf: false });
    this._emit(localBundle, localStored, undo, bundle.retValues,
      { actionNum: record.actionNum, actionHash, fromSelf: false });
  }

  /**
   * Applies changes as a suggestion (see submitSuggestion()): locally only. Suggestions can't
   * involve private values (they're readable by all who hold the document key).
   */
  private async _applySuggested(actions: UserAction[]): Promise<ApplyUAResult> {
    const result: EngineResult = await this._engine.call("apply_user_actions", actions, this._options.engineUser);
    const stored = result.stored.map(env => env[1]);
    const undo = result.undo.map(env => env[1]);
    if (stored.length === 0) {
      return { actionNum: 0, actionHash: null, retValues: result.retValues, isModification: false };
    }
    try {
      const noKeys = () => false;
      this._privacy.checkChange(stored, noKeys);
      const privacy = stored.some(touchesColumns) ? await this._computePrivacy() : this._privacy;
      if (!isEqual(privacy.scopeEntries(), this._privacy.scopeEntries())) {
        throw new EncryptionAccessError("Suggestions can't involve private columns");
      }
      checkMetaAccess([...stored, ...[...undo].reverse()], new ChangePrivacy(this._privacy, privacy),
        this._metaContext(), noKeys);
    } catch (e) {
      await this._revert(undo);
      throw e;
    }
    const num = this._nextPendingNum--;
    this._pending.push({ num, actions, undo });
    const actionHash = `suggestion${-num}`;
    this._emit(this._localBundle(actions), stored, undo, result.retValues,
      { actionNum: num, actionHash, fromSelf: true });
    return { actionNum: num, actionHash, retValues: result.retValues, isModification: true };
  }

  // Undoing (or redoing) changes made while suggesting.
  private async _undoOrRedoSuggested(actionNums: number[], undo: boolean): Promise<ApplyUAResult> {
    if (!undo) {
      // Redo isn't kept for suggestions: they're made again.
      throw new Error("Can't redo this suggested change: please make it again");
    }
    for (const num of [...actionNums].sort((a, b) => a - b)) {
      const index = this._pending.findIndex(p => p.num === num);
      if (index < 0) { throw new Error("This suggested change can't be undone anymore"); }
      // Undo the later ones first.
      for (const later of this._pending.splice(index).reverse()) { await this._unapply(later); }
    }
    return { actionNum: 0, actionHash: null, retValues: [], isModification: true };
  }

  // Undoes a change made while suggesting, letting the client know.
  private async _unapply(change: { num: number, actions: UserAction[], undo: DocAction[] }) {
    await this._revert(change.undo);
    const reverted = [...change.undo].reverse();
    this._emit({ ...this._localBundle([["ApplyUndoActions", change.undo]]), internal: true }, reverted, [], [],
      { actionNum: 0, actionHash: "", fromSelf: true });
  }

  // Undoes all changes made while suggesting, and applies changes from others held back meanwhile.
  private async _dropPending() {
    for (const change of this._pending.splice(0).reverse()) { await this._unapply(change); }
    await this._catchUp(this._heldBack.splice(0));
    await this._catchUp([]);
  }

  // A bundle describing a local change (see _applySuggested()).
  private _localBundle(actions: UserAction[]): DocChangeBundle {
    return {
      v: 1, userActions: actions, stored: [], undo: [], retValues: [],
      info: { time: Date.now(), user: this._options.userName, inst: "encrypted", otherId: 0, linkId: 0 },
    };
  }

  /**
   * Checks a key entry of the history against what the member who made it recorded (see
   * KeyHistory), and records it: the server can't make up key changes. Throws TamperedKeysError
   * if it doesn't check out (the document can't be used safely then).
   */
  private async _checkKeyEntry(entry: EncryptedActionRecord) {
    if (!this._keyring.history) { return; }
    let record: KeyChangeRecord;
    try {
      if (!entry.payload) {
        // Entries from before members recorded key changes: only those the record knows of.
        const history = this._keyring.history;
        const known = history.keys.some(k => k.keyId === entry.keyId && k.actionNum === entry.actionNum) ||
          history.bindings.some(b => b.releasedAt === entry.actionNum);
        if (!known) { throw new Error(`key change ${entry.actionNum} wasn't recorded by a member`); }
        return;
      }
      const docKeyBefore = this._keyring.keyIdAt(DOC_SCOPE, entry.actionNum - 1);
      if (!docKeyBefore) { throw new Error("no document key before it"); }
      record = await decryptKeyRecord(this._keyring, docKeyBefore, base64ToBytes(entry.payload));
      if (record.actionNum !== entry.actionNum || record.keyId !== entry.keyId) {
        throw new Error(`key change ${entry.actionNum} doesn't match what was recorded`);
      }
    } catch (e) {
      if (e instanceof MissingKeyError) { throw e; }
      this._closed = true;
      this._closedBy = e instanceof TamperedKeysError ? e : new TamperedKeysError(String(e?.message || e));
      throw this._closedBy;
    }
    this._keyring.recordKeyChange(record);
  }

  private _noteTimeUpdate(bundle: DocChangeBundle) {
    if (getPrimaryAction(bundle) === "UpdateCurrentTime") {
      this._lastTimeUpdateMs = Math.max(this._lastTimeUpdateMs, bundle.info.time);
    }
  }

  private _maybeRevealSoon() {
    if (this._loading || !this.canEdit || this._revealScheduled) { return; }
    this._revealScheduled = true;
    setTimeout(() => {
      this._revealScheduled = false;
      if (this._closed) { return; }
      this._exclusive(() => this._revealIfNeeded())
        .catch(e => this._log("Could not share the values made public yet", e));
    }, 0);
  }

  /**
   * Shares, with everyone, values that were private and no longer are (columns made public, and
   * formulas that were private because of them), as far as this member can read them: until
   * then, members who couldn't read them still have them locked. Attachments of such columns
   * get their keys replaced with ones everyone can use. Holds the mutex.
   */
  private async _revealIfNeeded() {
    if (!this.canEdit || !this._keyring.canUseScope(DOC_SCOPE)) { return; }
    for (let batch = 0; batch < MAX_REVEAL_BATCHES; batch++) {
      const done = await this._retryOnConflict(async () => {
        // (Computed again after catching up: what's left to share may have changed.)
        const stored = await this._nextReveal();
        if (stored.length === 0) { return true; }
        const bundle: DocChangeBundle = {
          v: 1, userActions: [["Calculate"]], stored, undo: [], retValues: [null], internal: true,
          info: { time: Date.now(), user: this._options.userName, inst: "encrypted", otherId: 0, linkId: 0 },
        };
        const keyId = this._keyring.currentKeyId(DOC_SCOPE);
        const payload = await encryptBundle(this._keyring, keyId, bundle);
        const result = await this._relay.pushAction(this._head, keyId, bytesToBase64(payload));
        if (!result.accepted) { return CONFLICT; }
        this._head = result.actionNum;
        this._sealedCells.applyActions(stored);
        // Our own engine has these values already; only attachments' new keys are new to it.
        const fileUpdates = stored.filter(a => a[1] === "_grist_Attachments");
        if (fileUpdates.length > 0) {
          await this._engine.call("apply_doc_actions_exactly", fileUpdates, this._options.engineUser);
          this._emit(bundle, fileUpdates, [], [null],
            { actionNum: result.actionNum, actionHash: await sha256Hex(payload), fromSelf: true });
        }
        return false;
      });
      if (done) { return; }
    }
  }

  /** The next batch of values to reveal (see _revealIfNeeded()), as doc actions. */
  private async _nextReveal(): Promise<DocAction[]> {
    const ctx = this._metaContext();
    let tableCache: { tableId: string, data: TableDataAction } | null = null;
    const getTable = async (tableId: string) => {
      if (tableCache?.tableId !== tableId) {
        tableCache = { tableId, data: await this._engine.call("fetch_table", tableId) };
      }
      return tableCache.data;
    };
    for (const [tableId, colId] of this._sealedCells.sealedColumns()) {
      const isMeta = tableId.startsWith("_grist");
      if (isMeta ? !hasPrivateMetaFields(tableId) :
        (!this._privacy.getColumn(tableId, colId) || this._privacy.scopesOf(tableId, colId).length > 0)) {
        continue;
      }
      const rowIds: number[] = [];
      const values: CellValue[] = [];
      for (const rowId of this._sealedCells.sealedRows(tableId, colId)) {
        if (isMeta && metaCellScopes(this._privacy, ctx, tableId, colId, rowId).length > 0) { continue; }
        let value: CellValue | undefined;
        if (isMeta) {
          value = this.docData.getTable(tableId)?.getValue(rowId, colId);
        } else {
          const data = await getTable(tableId);
          const index = data[2].indexOf(rowId);
          value = index >= 0 ? data[3][colId]?.[index] : undefined;
        }
        if (value === undefined || isLockedCell(value)) { continue; }   // Others will share it.
        rowIds.push(rowId);
        values.push(value);
        if (rowIds.length >= REVEAL_BATCH_CELLS) { break; }
      }
      if (rowIds.length > 0) { return [["BulkUpdateRecord", tableId, rowIds, { [colId]: values }]]; }
    }
    return this._nextAttachmentReveal();
  }

  /**
   * Attachments of columns made public have their file's key wrapped with the column's key: a
   * batch of them re-encrypted with the document's key, as doc actions (or none if none's left).
   */
  private async _nextAttachmentReveal(): Promise<DocAction[]> {
    const released = new Set(this._keyring.releasedScopes());
    if (released.size === 0) { return []; }
    const attachments = this.docData.getMetaTable("_grist_Attachments");
    const updates: { rowId: number, fileIdent: string }[] = [];
    for (const record of attachments.getRecords()) {
      const ref = parseFileIdent(record.fileIdent);
      const scope = ref && this._keyring.getKey(ref.keyId)?.scope;
      if (!ref || !scope || !released.has(scope) || !this._keyring.holds(ref.keyId)) { continue; }
      const data = await decryptFile(this._keyring, ref, await this._relay.fetchFile(ref.fileId));
      const { ciphertext, ref: newRef } = await encryptFile(this._keyring, DOC_SCOPE, data);
      const { fileId } = await this._relay.uploadFile(ciphertext);
      updates.push({ rowId: record.id, fileIdent: makeFileIdent({ fileId, ...newRef }) });
      if (updates.length >= 20) { break; }
    }
    if (updates.length === 0) { return []; }
    const rowIds = updates.map(u => u.rowId);
    const values = (colId: string) => rowIds.map(rowId => attachments.getValue(rowId, colId as any) as CellValue);
    return [["BulkUpdateRecord", "_grist_Attachments", rowIds, {
      fileIdent: updates.map(u => u.fileIdent),
      fileName: values("fileName"), fileSize: values("fileSize"),
      imageWidth: values("imageWidth"), imageHeight: values("imageHeight"),
    }]];
  }

  /** Whether some values made public haven't been shared with everyone yet (see _revealIfNeeded()). */
  private _hasUnrevealedValues(): boolean {
    const ctx = this._metaContext();
    return this._sealedCells.sealedColumns().some(([tableId, colId]) => {
      if (tableId.startsWith("_grist")) {
        return hasPrivateMetaFields(tableId) && this._sealedCells.sealedRows(tableId, colId)
          .some(rowId => metaCellScopes(this._privacy, ctx, tableId, colId, rowId).length === 0);
      }
      return Boolean(this._privacy.getColumn(tableId, colId)) && this._privacy.scopesOf(tableId, colId).length === 0;
    });
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

  /**
   * Creates a new key for a scope, recorded after the latest change. If `replacing` is given,
   * that's the key it replaces: if someone else replaced it meanwhile, returns null. Holds the
   * mutex.
   */
  private async _createKey(scope: string, recipients: (KeyRecipient & { userId: number })[],
    colRef?: number, replacing?: string, options: { compact?: boolean } = {}): Promise<string | null> {
    const wraps = await this._keyring.vault.createDocumentKey(recipients);
    const keyId = makeKeyId(scope);
    const myVaultId = recipients.find(r => r.userId === this._userId)?.vaultUserId;
    const myWrap = myVaultId ? wraps.get(myVaultId) : undefined;
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
    return this._retryOnConflict(async () => {
      if (replacing && this._keyring.currentKey(scope)?.keyId !== replacing) { return null; }
      request.baseActionNum = this._head;
      // What members record of the change (see KeyHistory), encrypted with the document key before it.
      const keyRecord: KeyChangeRecord = {
        v: 1, actionNum: this._head + 1, scope, keyId,
        ...(myWrap ? { check: await this._keyring.makeCheck(keyId, myWrap) } : {}),
        ...(colRef ? { colRef } : {}),
      };
      const docKeyBefore = this._keyring.keyIdAt(DOC_SCOPE, this._head);
      if (docKeyBefore) {
        request.record = bytesToBase64(await encryptKeyRecord(this._keyring, docKeyBefore, keyRecord));
      }
      const historyBefore = this._keyring.history;
      // The document under the new key goes along with it (so that members given only the new key
      // can open it, and so that content made private isn't kept readable), if it can be made.
      let built: BuiltSnapshot | null = null;
      let result: EncryptedPushResult | undefined;
      try {
        if (myWrap) { built = await this._snapshotWithKey({ keyId, scope, colRef, wrap: myWrap }, keyRecord); }
        result = await this._relay.createKey(request,
          built ? { payload: built.payload, compact: Boolean(options.compact) } : undefined);
      } finally {
        // Forget the pending key (see _snapshotWithKey()), and learn the outcome.
        if (!result?.accepted) { this._keyring.setHistory(historyBefore); }
        await this._keyring.refresh();
      }
      if (!result.accepted) {
        await this._updatePrivacy();
        return CONFLICT;
      }
      this._keyring.recordKeyChange(keyRecord);
      this._head = result.actionNum;
      await this._updatePrivacy();
      if (built) { this._noteSnapshot(built); }
      return keyId;
    });
  }

  /**
   * Builds the snapshot of the document as it will be once a key is created (see _createKey()),
   * with the key added to the keyring as pending. Returns null if it can't be made by this member.
   */
  private async _snapshotWithKey(key: { keyId: string, scope: string, colRef?: number,
    wrap: { wrappedKey: Uint8Array, keyVersion: number } }, record: KeyChangeRecord): Promise<BuiltSnapshot | null> {
    const actionNum = this._head + 1;
    this._keyring.addPendingKey(
      { keyId: key.keyId, scope: key.scope, current: true, rotateOnNextEdit: false, actionNum },
      key.wrap,
      key.colRef ? { scope: key.scope, colRef: key.colRef, boundAt: actionNum, releasedAt: null } : undefined);
    // (The snapshot carries the record of keys as it will be.)
    this._keyring.recordKeyChange(record);
    if (!this._keyring.canUseScope(DOC_SCOPE) || this._hasUnrevealedValues()) { return null; }
    const tables: { [tableId: string]: TableDataAction } = await this._engine.call("fetch_all_tables");
    const privacy = ColumnPrivacy.fromMetaTables(tables._grist_Tables, tables._grist_Tables_column,
      this._keyring.bindingsAt(actionNum));
    return this._buildSnapshot(actionNum, privacy, tables, this._sealedCells);
  }

  /**
   * Like _rotateKeysIfNeeded(), before an edit: a failure (e.g. the encryption service being
   * unavailable) doesn't block editing. Nothing was changed then (a key and the document under it
   * are saved together, or not at all), and the keys stay flagged, so it's tried again next time.
   * Meanwhile, those who lost access no longer get changes from the server.
   */
  private async _tryRotatingKeys() {
    try {
      await this._rotateKeysIfNeeded();
    } catch (e) {
      this._log("Could not replace keys, will try again on the next edit", e);
      this._options.onRotationFailed?.(e as Error);
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
        await this._createKey(scope, recipients, undefined, current.keyId);
      } catch (e) {
        // Someone else may have replaced it first.
        await this._keyring.refresh();
        if (this._keyring.currentKey(scope)?.keyId === current.keyId) { throw e; }
      }
    }
    // Save the document under the new keys (members given only the new ones can then open it).
    await this._saveSnapshot();
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

  /** Whether a new snapshot should be saved: after enough changes, or under a new key. */
  private _isSnapshotDue(): boolean {
    if (this._head - this._snapshotNum >= this._snapshotEvery()) { return true; }
    const keyId = this._keyring.currentKey(DOC_SCOPE)?.keyId;
    return Boolean(keyId && this._snapshotKeyId && keyId !== this._snapshotKeyId);
  }

  private _maybeSnapshotSoon() {
    if (!this._isSnapshotDue()) { return; }
    // Don't hold up the change that triggered it.
    setTimeout(() => {
      if (this._closed) { return; }
      this._exclusive(() => this._saveSnapshot()).catch(e => this._log("Saving snapshot failed", e));
    }, 0);
  }

  /**
   * Saves a snapshot. Private columns the member can't read are given by reference to the sealed
   * values the member received (see SealedCells.ts); if that's not possible (e.g. a column just
   * became private), the snapshot is left for others to make. So it is while values made public
   * haven't been shared yet (see _revealIfNeeded()).
   */
  private async _saveSnapshot(options: { compact?: boolean } = {}) {
    if (!this._keyring.canUseScope(DOC_SCOPE)) { return; }
    const keyId = this._keyring.currentKeyId(DOC_SCOPE);
    if (this._snapshotNum === this._head && this._head > 0 && !options.compact && this._snapshotKeyId === keyId) {
      return;
    }
    if (this._hasUnrevealedValues()) {
      this._log("Leaving the snapshot until values made public are shared");
      return;
    }
    const tables: { [tableId: string]: TableDataAction } = await this._engine.call("fetch_all_tables");
    const built = await this._buildSnapshot(this._head, this._privacy, tables, this._sealedCells);
    if (!built) { return; }
    await this._relay.saveSnapshot(built.actionNum, built.keyId, built.payload, options);
    this._noteSnapshot(built);
  }

  /**
   * Builds a snapshot of the given tables as of actionNum, encrypted with the current document
   * key. Private columns the member can't read are given by reference to the sealed values they
   * received (`sealedCells`): if that's not possible, returns null (others will make it).
   */
  private async _buildSnapshot(actionNum: number, privacy: ColumnPrivacy,
    tables: { [tableId: string]: TableDataAction }, sealedCells: SealedCells | null): Promise<BuiltSnapshot | null> {
    const keyId = this._keyring.currentKeyId(DOC_SCOPE);
    const blobs = new BlobTable();
    let sealed: { [tableId: string]: any };
    try {
      // Which metadata cells are private is decided by the snapshot's own metadata.
      const ctx = this._metaContext((tableId, rowId, colId) => {
        const table = tables[tableId];
        const index = table ? table[2].indexOf(rowId) : -1;
        return index >= 0 ? table[3][colId]?.[index] : undefined;
      });
      const carrier = sealedCells ?
        sealedCells.makeCarrier((tableId, colId) => privacy.getColumn(tableId, colId)?.type || "Any") :
        new SealedCells().makeCarrier(() => "Any");
      sealed = await sealTables(tables, privacy, this._keyring, actionNum, blobs, ctx, carrier);
    } catch (e) {
      if (!(e instanceof CannotCarryError)) { throw e; }
      if (!sealedCells) { throw new Error("Only members who can read everything can do this"); }
      this._log("Leaving the snapshot to members who can read all columns:", e.message);
      return null;
    }
    const snapshot: DocSnapshotPayload = {
      v: 1,
      actionNum,
      tables: sealed,
      ...(blobs.blobs.length > 0 ? { blobs: blobs.blobs } : {}),
      ...(this._keyring.history ? { keyHistory: this._keyring.history } : {}),
    };
    return { actionNum, keyId, payload: await encryptSnapshot(this._keyring, keyId, snapshot), sealed, blobs };
  }

  // Once a snapshot was saved.
  private _noteSnapshot(built: BuiltSnapshot) {
    this._snapshotNum = built.actionNum;
    this._snapshotKeyId = built.keyId;
    // That's how the document is shared now (e.g. with values sealed that weren't before).
    this._sealedCells.loadSnapshot(built.sealed, built.blobs.blobs);
  }
}

// Whether some values are locked (see LockedCell.ts).
function hasLockedCells(tables: { [tableId: string]: TableDataAction }): boolean {
  return Object.values(tables).some(table => Object.values(table[3]).some(values => values.some(isLockedCell)));
}

// Whether an action may change which columns are private (or their formulas).
function touchesColumns(action: DocAction): boolean {
  const tableId = getTableId(action);
  return tableId === "_grist_Tables_column" || tableId === "_grist_Tables" || isSchemaAction(action);
}

// What can be shared of a user action's result, in changes involving private values.
function onlyNumbers(value: any): any {
  if (value === null || typeof value === "number" || typeof value === "boolean") { return value; }
  if (Array.isArray(value) && value.every(v => v === null || typeof v === "number")) { return value; }
  return null;
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
