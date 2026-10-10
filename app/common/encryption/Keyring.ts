/**
 * The keys of an encrypted document, from the point of view of one member: which keys exist and
 * for what scope (see EncryptionTypes.ts), and which of them the member holds a copy of. Uses
 * the member's vault (the encryption service) to encrypt and decrypt with them.
 */
import { base64ToBytes, IKeyVault, WrappedKey } from "app/common/encryption/EncryptionCrypto";
import {
  DOC_SCOPE, DocKeyInfo, DocKeyRecord, EncryptionKeysResult, ScopeBinding,
} from "app/common/encryption/EncryptionTypes";

const MIN_REFRESH_INTERVAL_MS = 5000;

export class MissingKeyError extends Error {
  constructor(public readonly keyId: string) {
    super("You don't have access to the key needed to read this content");
  }
}

export class Keyring {
  private _keys = new Map<string, DocKeyInfo>();
  private _myKeys = new Map<string, WrappedKey>();
  private _bindings: ScopeBinding[] = [];
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

  public getKeys(): DocKeyInfo[] {
    return [...this._keys.values()];
  }

  public getKey(keyId: string): DocKeyInfo | undefined {
    return this._keys.get(keyId);
  }

  /** The key to use for new content of a scope. */
  public currentKey(scope: string): DocKeyInfo | undefined {
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
    return new Map(this._bindings
      .filter(b => b.boundAt <= actionNum && (b.releasedAt === null || b.releasedAt > actionNum))
      .map(b => [b.colRef, b.scope]));
  }

  /** The columns that are or were private (whose ids mustn't be given to new columns). */
  public boundColRefs(): number[] {
    return [...new Set(this._bindings.map(b => b.colRef))].sort((a, b) => a - b);
  }

  /** Column scopes that were made public again (and aren't used anymore). */
  public releasedScopes(): string[] {
    const active = new Set(this._bindings.filter(b => b.releasedAt === null).map(b => b.scope));
    return [...new Set(this._bindings.filter(b => b.releasedAt !== null && !active.has(b.scope)).map(b => b.scope))];
  }

  /** The scope protecting a column now, if it's private. */
  public currentScopeOf(colRef: number): string | null {
    return this._bindings.find(b => b.colRef === colRef && b.releasedAt === null)?.scope ?? null;
  }

  public holds(keyId: string): boolean {
    return this._myKeys.has(keyId);
  }

  /** Whether the member can read and write content of a scope (i.e. holds its current key). */
  public canUseScope(scope: string): boolean {
    const key = this.currentKey(scope);
    return Boolean(key && this.holds(key.keyId));
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

  /** The member's copy of a key, refreshing keys once if it's not known yet. */
  public async getWrap(keyId: string): Promise<WrappedKey> {
    if (!this._myKeys.has(keyId)) { await this.refresh(); }
    const wrap = this._myKeys.get(keyId);
    if (!wrap) { throw new MissingKeyError(keyId); }
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
}

export function fromKeyRecord(key: DocKeyRecord): WrappedKey {
  return { wrappedKey: base64ToBytes(key.wrappedKey), keyVersion: key.keyVersion };
}
