/**
 * The keys of an encrypted document, from the point of view of one member: which keys exist and
 * for what scope (see EncryptionTypes.ts), and which of them the member holds a copy of. Uses
 * the member's vault (the encryption service) to encrypt and decrypt with them.
 */
import {
  base64ToBytes, bytesToBase64, IKeyVault, utf8Decode, utf8Encode, WrappedKey,
} from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, DocKeyInfo, DocKeyRecord, EncryptionKeysResult, KeyChangeRecord, KeyHistory, KeyHistoryEntry,
  ScopeBinding,
} from "app/common/encryption/EncryptionTypes";

const MIN_REFRESH_INTERVAL_MS = 5000;

export class MissingKeyError extends Error {
  constructor(public readonly keyId: string) {
    super("You don't have access to the key needed to read this content");
  }
}

/** Thrown when the server gives keys that members didn't make (see KeyHistory). */
export class TamperedKeysError extends Error {
  constructor(message: string) {
    super(`The server gave keys that weren't made by members of this document (${message}): ` +
      "it can't be used safely");
  }
}

export class Keyring {
  private _keys = new Map<string, DocKeyInfo>();
  private _myKeys = new Map<string, WrappedKey>();
  private _bindings: ScopeBinding[] = [];
  // What members recorded (null for documents that don't have such a record yet).
  private _history: KeyHistory | null = null;
  // Keys being created by this member (see addPendingKey()).
  private _pending = new Set<string>();
  // Copies of keys checked against their record: keyId -> wrapped key checked.
  private _checked = new Map<string, string>();
  private _lastRefreshMs = 0;
  private _refreshing?: Promise<void>;

  constructor(
    public readonly vault: IKeyVault,
    // Fetches the document's keys and the member's copies of them.
    private _fetchKeys: () => Promise<EncryptionKeysResult>,
    keys?: EncryptionKeysResult,
  ) {
    if (keys) { this.update(keys); }
  }

  public update(result: EncryptionKeysResult) {
    this._keys = new Map(result.keys.map(k => [k.keyId, k]));
    this._myKeys = new Map(result.myKeys.map(k => [k.keyId, fromKeyRecord(k)]));
    this._bindings = result.bindings || [];
    this._pending.clear();
  }

  /** What members recorded of keys and private columns (see KeyHistory), if known. */
  public get history(): KeyHistory | null {
    return this._history ? { keys: [...this._history.keys], bindings: this._history.bindings.map(b => ({ ...b })) } :
      null;
  }

  public setHistory(history: KeyHistory | null) {
    this._history = history ? { keys: [...history.keys], bindings: history.bindings.map(b => ({ ...b })) } : null;
  }

  /**
   * Starts a record from what the server says now, for documents without one (trusting the server
   * once, as when first seeing a document). Keys the member holds get checks.
   */
  public async initHistory(): Promise<KeyHistory> {
    const keys: KeyHistoryEntry[] = [];
    for (const key of this._keys.values()) {
      const wrap = this._myKeys.get(key.keyId);
      keys.push({ keyId: key.keyId, scope: key.scope, actionNum: key.actionNum,
        ...(wrap ? { check: bytesToBase64(await this.vault.encrypt(utf8Encode(key.keyId), wrap)) } : {}) });
    }
    this.setHistory({ keys, bindings: this._bindings });
    return this.history!;
  }

  /** The check to record for a new key (see KeyHistoryEntry), given the creator's copy of it. */
  public async makeCheck(keyId: string, wrap: WrappedKey): Promise<Base64> {
    return bytesToBase64(await this.vault.encrypt(utf8Encode(keyId), wrap));
  }

  /** Applies a key change members recorded (see KeyChangeRecord) to the record of keys. */
  public recordKeyChange(record: KeyChangeRecord) {
    const history = this._history;
    if (!history) { return; }
    if (record.release) {
      for (const b of history.bindings) {
        if (b.scope === record.scope && b.releasedAt === null) { b.releasedAt = record.actionNum; }
      }
      return;
    }
    if (!history.keys.some(k => k.keyId === record.keyId)) {
      history.keys.push({ keyId: record.keyId, scope: record.scope, actionNum: record.actionNum,
        ...(record.check ? { check: record.check } : {}) });
    }
    if (record.colRef && !history.bindings.some(b => b.scope === record.scope)) {
      history.bindings.push(
        { scope: record.scope, colRef: record.colRef, boundAt: record.actionNum, releasedAt: null });
    }
  }

  /** Whether a key is one members recorded (always true for documents without a record). */
  public isRecorded(keyId: string): boolean {
    return !this._history || this._pending.has(keyId) || this._history.keys.some(k => k.keyId === keyId);
  }

  public async refresh() {
    this._lastRefreshMs = Date.now();
    this.update(await this._fetchKeys());
  }

  /**
   * Refreshes keys if some of the given ones aren't known yet (e.g. just created by another
   * member). Content asking for unknown keys may also be bogus: this refreshes at most once every
   * few seconds.
   */
  public async refreshIfUnknown(keyIds: string[]): Promise<void> {
    if (keyIds.every(keyId => this._keys.has(keyId))) { return; }
    if (this._refreshing) { return this._refreshing; }
    if (Date.now() - this._lastRefreshMs < MIN_REFRESH_INTERVAL_MS) { return; }
    this._refreshing = this.refresh().finally(() => { this._refreshing = undefined; });
    return this._refreshing;
  }

  /**
   * Adds a key as if it had been created (current for its scope from the entry actionNum, held by
   * the member, and making a column private if `binding` is given), before it actually is: e.g.
   * to save a snapshot with it along with its creation. refresh() undoes it if it doesn't happen.
   */
  public addPendingKey(key: DocKeyInfo, wrap: WrappedKey, binding?: ScopeBinding) {
    for (const other of this._keys.values()) {
      if (other.scope === key.scope && other.current) { this._keys.set(other.keyId, { ...other, current: false }); }
    }
    this._keys.set(key.keyId, key);
    this._myKeys.set(key.keyId, wrap);
    this._pending.add(key.keyId);
    if (binding) { this._bindings = [...this._bindings, binding]; }
  }

  public getKeys(): DocKeyInfo[] {
    return [...this._keys.values()];
  }

  public getKey(keyId: string): DocKeyInfo | undefined {
    return this._keys.get(keyId);
  }

  /**
   * The key to use for new content of a scope. With a record of keys (see KeyHistory), it's the
   * latest one recorded (the server can't get members to use an older one, or one of its own).
   */
  public currentKey(scope: string): DocKeyInfo | undefined {
    const pending = [...this._pending].map(keyId => this._keys.get(keyId)).find(k => k?.scope === scope);
    if (pending) { return pending; }
    if (this._history) {
      const recorded = this._latestRecorded(scope, Infinity);
      if (!recorded) { return undefined; }
      return this._keys.get(recorded.keyId) ??
        { keyId: recorded.keyId, scope, current: true, rotateOnNextEdit: false, actionNum: recorded.actionNum };
    }
    return [...this._keys.values()].find(k => k.scope === scope && k.current);
  }

  public currentKeyId(scope: string): string {
    const key = this.currentKey(scope);
    if (!key) { throw new Error(`No key for ${scope}`); }
    return key.keyId;
  }

  /**
   * The key that was current for a scope for the entry actionNum of the history (and the state of
   * the document after it), i.e. the latest one created before it. Null if there was none.
   */
  public keyIdAt(scope: string, actionNum: number): string | null {
    if (this._history) { return this._latestRecorded(scope, actionNum)?.keyId ?? null; }
    let found: DocKeyInfo | null = null;
    for (const key of this._keys.values()) {
      if (key.scope === scope && key.actionNum <= actionNum && (!found || key.actionNum > found.actionNum)) {
        found = key;
      }
    }
    return found?.keyId ?? null;
  }

  /** The columns that are private as of the entry actionNum of the history: colRef -> scope. */
  public bindingsAt(actionNum: number): Map<number, string> {
    // A column is private if either the server or members' record says so (see KeyHistory).
    const result = new Map<number, string>();
    for (const b of [...this._bindings, ...(this._history?.bindings || [])]) {
      if (b.boundAt <= actionNum && (b.releasedAt === null || b.releasedAt > actionNum)) {
        if (!result.has(b.colRef)) { result.set(b.colRef, b.scope); }
      }
    }
    // (The record's say on which scope protects a column wins.)
    for (const b of this._history?.bindings || []) {
      if (b.boundAt <= actionNum && (b.releasedAt === null || b.releasedAt > actionNum)) {
        result.set(b.colRef, b.scope);
      }
    }
    return result;
  }

  /** The columns that are or were private (whose ids mustn't be given to new columns). */
  public boundColRefs(): number[] {
    const all = [...this._bindings, ...(this._history?.bindings || [])];
    return [...new Set(all.map(b => b.colRef))].sort((a, b) => a - b);
  }

  /** Column scopes that were made public again (and aren't used anymore), as members recorded. */
  public releasedScopes(): string[] {
    const bindings = this._history?.bindings ?? this._bindings;
    const active = new Set(bindings.filter(b => b.releasedAt === null).map(b => b.scope));
    return [...new Set(bindings.filter(b => b.releasedAt !== null && !active.has(b.scope)).map(b => b.scope))];
  }

  /** The scope protecting a column now, if it's private. */
  public currentScopeOf(colRef: number): string | null {
    const binding = (this._history?.bindings || []).find(b => b.colRef === colRef && b.releasedAt === null) ??
      this._bindings.find(b => b.colRef === colRef && b.releasedAt === null);
    return binding?.scope ?? null;
  }

  public holds(keyId: string): boolean {
    return this._myKeys.has(keyId);
  }

  /** Whether the member can read and write content of a scope (i.e. holds its current key). */
  public canUseScope(scope: string): boolean {
    const key = this.currentKey(scope);
    return Boolean(key && this.holds(key.keyId));
  }

  /**
   * Whether the member can read everything in the document as of the entry actionNum: holds the
   * current keys of the document and of the columns private then.
   */
  public canReadAll(actionNum: number): boolean {
    return [DOC_SCOPE, ...this.bindingsAt(actionNum).values()].every(scope => this.canUseScope(scope));
  }

  /** Whether the member holds the current key of every scope. */
  public holdsAllScopes(): boolean {
    return [...new Set([...this._keys.values()].map(k => k.scope))].every(scope => this.canUseScope(scope));
  }

  /** Scopes whose current key is held by the member and flagged to be replaced. */
  public scopesToRotate(): string[] {
    return [...this._keys.values()]
      .filter(k => k.current && k.rotateOnNextEdit && this.holds(k.keyId))
      .map(k => k.scope)
      // Replace the document key first, so that later key changes use it.
      .sort((a, b) => (a === DOC_SCOPE ? -1 : b === DOC_SCOPE ? 1 : a.localeCompare(b)));
  }

  /**
   * The member's copy of a key, refreshing keys once if it's not known yet. With a record of keys
   * (see KeyHistory), only for keys recorded, and checked to be of the key recorded.
   */
  public async getWrap(keyId: string): Promise<WrappedKey> {
    if (!this._myKeys.has(keyId)) { await this.refresh(); }
    const wrap = this._myKeys.get(keyId);
    if (!wrap) { throw new MissingKeyError(keyId); }
    if (!this.isRecorded(keyId)) { throw new TamperedKeysError(`unknown key ${keyId}`); }
    const check = this._history?.keys.find(k => k.keyId === keyId)?.check;
    const wrapId = bytesToBase64(wrap.wrappedKey);
    if (check && this._checked.get(keyId) !== wrapId) {
      let matches = false;
      try {
        matches = utf8Decode(await this.vault.decrypt(base64ToBytes(check), wrap)) === keyId;
      } catch (e) {
        matches = false;
      }
      if (!matches) { throw new TamperedKeysError(`your copy of ${keyId} is of another key`); }
      this._checked.set(keyId, wrapId);
    }
    return wrap;
  }

  public async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    return this.vault.encrypt(data, await this.getWrap(keyId));
  }

  public async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    return this.vault.decrypt(data, await this.getWrap(keyId));
  }

  /** Encrypts data successively with several keys: reading it requires all of them. */
  public async encryptWithAll(keyIds: string[], data: Uint8Array): Promise<Uint8Array> {
    for (const keyId of keyIds) { data = await this.encrypt(keyId, data); }
    return data;
  }

  public async decryptWithAll(keyIds: string[], data: Uint8Array): Promise<Uint8Array> {
    for (const keyId of [...keyIds].reverse()) { data = await this.decrypt(keyId, data); }
    return data;
  }

  // The latest key of a scope recorded at or before actionNum.
  private _latestRecorded(scope: string, actionNum: number): KeyHistoryEntry | null {
    let found: KeyHistoryEntry | null = null;
    for (const key of this._history?.keys || []) {
      if (key.scope === scope && key.actionNum <= actionNum && (!found || key.actionNum > found.actionNum)) {
        found = key;
      }
    }
    return found;
  }
}

export function fromKeyRecord(key: DocKeyRecord): WrappedKey {
  return { wrappedKey: base64ToBytes(key.wrappedKey), keyVersion: key.keyVersion };
}
