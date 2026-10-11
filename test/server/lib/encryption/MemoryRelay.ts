/**
 * An in-memory stand-in for the server side of encrypted documents, for tests of the browser-side
 * logic. It follows the same rules as the real relay (see EncryptionRelay.ts): changes are
 * accepted only on top of the latest one, with the current document key, and from members holding
 * it; keys are recorded in the history, and members only get the keys they're given.
 */
import { base64ToBytes, bytesToBase64 } from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, DocKeyInfo, DocKeyRecord, EncryptedActionRecord, EncryptedDocOpenResult,
  EncryptedInboxEntry, EncryptedPushResult, EncryptedSnapshotRecord, EncryptedSuggestion, EncryptionMember,
  isColumnScope, NewKeyRequest,
  ScopeBinding,
} from "app/common/encryption/EncryptionTypes";
import { IEncryptionRelay, LocalActiveDoc } from "app/common/encryption/LocalActiveDoc";

export interface MemoryMember {
  userId: number;
  email: string;
  name: string;
  access: string;
}

export class MemoryRelay {
  public actions: EncryptedActionRecord[] = [];
  public snapshots: EncryptedSnapshotRecord[] = [];
  public keys: DocKeyInfo[] = [];
  public wraps: DocKeyRecord[] = [];
  public bindings: ScopeBinding[] = [];
  public members: MemoryMember[] = [];
  public pushes = { accepted: 0, refused: 0, denied: 0 };
  // Every push attempt, in order, by member.
  public pushLog: { userId: number, baseActionNum: number, keyId: string, outcome: string }[] = [];
  public files = new Map<string, Base64>();
  public suggestions: EncryptedSuggestion[] = [];
  public inbox: EncryptedInboxEntry[] = [];
  // How many snapshots were saved along with key changes.
  public keyChangeSnapshots = 0;
  // Broadcasts can be held back, to simulate changes crossing in flight.
  public holdBroadcasts = false;

  private _clients = new Set<RelayClient>();
  private _held: (() => Promise<void>)[] = [];

  // Changes covered by snapshots may have been pruned.
  public get head() {
    return Math.max(0, ...this.actions.map(a => a.actionNum), ...this.snapshots.map(s => s.actionNum));
  }

  public addMember(member: MemoryMember) { this.members.push(member); }

  public open(userId: number): EncryptedDocOpenResult {
    const member = this.members.find(m => m.userId === userId)!;
    const snapshot = this.snapshots[this.snapshots.length - 1] || null;
    return {
      snapshot,
      actions: this.actions.filter(a => a.actionNum > (snapshot?.actionNum ?? 0)),
      head: this.head,
      ...this.getKeys(userId),
      access: member.access,
      user: { id: userId, email: member.email, name: member.name, ref: null, vaultUserId: null },
    };
  }

  public connect(userId: number): RelayClient {
    const client = new RelayClient(this, userId);
    this._clients.add(client);
    return client;
  }

  public disconnect(client: RelayClient) {
    this._clients.delete(client);
  }

  public getKeys(userId: number) {
    return {
      keys: this.keys.map(k => ({ ...k })),
      myKeys: this.wraps.filter(w => w.userId === userId),
      bindings: this.bindings.map(b => ({ ...b })),
    };
  }

  public holds(userId: number, keyId: string) {
    return this.wraps.some(w => w.userId === userId && w.keyId === keyId);
  }

  public currentKey(scope: string) {
    return this.keys.find(k => k.scope === scope && k.current);
  }

  public push(from: RelayClient, baseActionNum: number, keyId: string, payload: Base64): EncryptedPushResult {
    const log = (outcome: string) => this.pushLog.push({ userId: from.userId, baseActionNum, keyId, outcome });
    if (this.currentKey(DOC_SCOPE)?.keyId !== keyId) {
      this.pushes.refused++;
      log("refused");
      return { accepted: false, head: this.head };
    }
    if (!this.holds(from.userId, keyId)) {
      this.pushes.denied++;
      log("denied");
      throw new Error("Only members holding the document key can change it");
    }
    if (baseActionNum !== this.head) {
      this.pushes.refused++;
      log("refused");
      return { accepted: false, head: this.head };
    }
    this.pushes.accepted++;
    log("accepted");
    const record = this._append({ kind: "change", keyId, payload, userId: from.userId });
    this._broadcast(from, record);
    return { accepted: true, actionNum: record.actionNum, timeMs: record.timeMs };
  }

  public createKey(from: RelayClient, request: NewKeyRequest,
    snapshot?: { payload: Uint8Array, compact: boolean }): EncryptedPushResult {
    const current = this.currentKey(request.scope);
    if (current) {
      const holders = new Set(this.wraps.filter(w => w.keyId === current.keyId).map(w => w.userId));
      if (!holders.has(from.userId) || !request.wraps.every(w => holders.has(w.userId))) {
        throw new Error("Only members holding a key can replace it, for those who held it");
      }
    }
    const isFirstDocKey = request.scope === DOC_SCOPE && !current;
    if (!isFirstDocKey && request.baseActionNum !== this.head) {
      return { accepted: false, head: this.head };
    }
    const bindsColumn = !current && isColumnScope(request.scope);
    if (bindsColumn && !request.colRef) { throw new Error("A new column scope must say which column it protects"); }
    for (const key of this.keys) {
      if (key.scope === request.scope) { key.current = false; key.rotateOnNextEdit = false; }
    }
    const actionNum = isFirstDocKey ? 0 : this.head + 1;
    this.keys.push({ keyId: request.keyId, scope: request.scope, current: true, rotateOnNextEdit: false, actionNum });
    if (bindsColumn) {
      this.bindings.push({ scope: request.scope, colRef: request.colRef!, boundAt: actionNum, releasedAt: null });
    }
    this.wraps.push(...request.wraps.map(w => ({ ...w, keyId: request.keyId })));
    if (isFirstDocKey) { return { accepted: true, actionNum: 0, timeMs: Date.now() }; }
    const record = this._append(
      { kind: "key", keyId: request.keyId, payload: request.record || "", userId: from.userId });
    if (snapshot) {
      // Saved with the key change, encrypted with the document key current after it.
      this.keyChangeSnapshots++;
      this.saveSnapshot(from.userId, record.actionNum, this.currentKey(DOC_SCOPE)!.keyId,
        bytesToBase64(snapshot.payload), snapshot.compact);
    }
    this._broadcast(from, record);
    return { accepted: true, actionNum: record.actionNum, timeMs: record.timeMs };
  }

  public restore(from: RelayClient, baseActionNum: number, keyId: string, payload: Base64): EncryptedPushResult {
    if (this.members.find(m => m.userId === from.userId)?.access !== "owners") {
      throw new Error("Only owners can restore a document");
    }
    if (this.currentKey(DOC_SCOPE)?.keyId !== keyId || baseActionNum !== this.head) {
      return { accepted: false, head: this.head };
    }
    const record = this._append({ kind: "restore", keyId, payload: "", userId: from.userId });
    this.saveSnapshot(from.userId, record.actionNum, keyId, payload);
    this._broadcast(from, record);
    return { accepted: true, actionNum: record.actionNum, timeMs: record.timeMs };
  }

  public releaseScope(from: RelayClient, scope: string, baseActionNum: number, payload?: Base64): EncryptedPushResult {
    if (this.members.find(m => m.userId === from.userId)?.access !== "owners") {
      throw new Error("Only owners can make columns public");
    }
    const binding = this.bindings.find(b => b.scope === scope && b.releasedAt === null);
    const current = this.currentKey(scope);
    if (!binding || !current || !this.wraps.some(w => w.keyId === current.keyId && w.userId === from.userId)) {
      throw new Error("Only members holding a column's key can make it public");
    }
    if (baseActionNum !== this.head) { return { accepted: false, head: this.head }; }
    binding.releasedAt = this.head + 1;
    const record = this._append({ kind: "key", keyId: current.keyId, payload: payload || "", userId: from.userId });
    this._broadcast(from, record);
    return { accepted: true, actionNum: record.actionNum, timeMs: record.timeMs };
  }

  /**
   * Appends a change as a member would, bypassing their browser's checks (as a modified client
   * could): the change is the given payload, encrypted by the caller.
   */
  public pushRaw(userId: number, keyId: string, payload: Base64): EncryptedActionRecord {
    const record = this._append({ kind: "change", keyId, payload, userId });
    this._broadcast(null, record);
    return record;
  }

  /** Takes keys away (all of them, or those of a scope), flagging affected scopes for rotation. */
  public revoke(userIds: number[], scope?: string) {
    const keyIds = new Set(this.keys.filter(k => !scope || k.scope === scope).map(k => k.keyId));
    const revoked = this.wraps.filter(w => userIds.includes(w.userId) && keyIds.has(w.keyId));
    this.wraps = this.wraps.filter(w => !revoked.includes(w));
    const scopes = new Set(revoked.map(w => this.keys.find(k => k.keyId === w.keyId)!.scope));
    for (const key of this.keys) {
      if (key.current && scopes.has(key.scope)) { key.rotateOnNextEdit = true; }
    }
  }

  public share(wraps: DocKeyRecord[]) {
    this.wraps.push(...wraps);
  }

  public listMembers(): EncryptionMember[] {
    return this.members.map(m => ({
      ...m, vaultUserId: null, keyIds: this.wraps.filter(w => w.userId === m.userId).map(w => w.keyId),
    }));
  }

  /** Delivers broadcasts held back while holdBroadcasts was set. */
  public async releaseBroadcasts() {
    this.holdBroadcasts = false;
    const held = this._held.splice(0);
    await Promise.all(held.map(deliver => deliver()));
  }

  public saveSnapshot(userId: number, actionNum: number, keyId: string, payload: Base64, compact?: boolean) {
    if (actionNum > this.head) { throw new Error("Snapshot is ahead of the document"); }
    if (this.currentKey(DOC_SCOPE)?.keyId !== keyId) { throw new Error("Snapshots must use the current key"); }
    if (!this.holds(userId, keyId)) { throw new Error("Only members holding the document key can save it"); }
    if (compact && this.members.find(m => m.userId === userId)?.access !== "owners") {
      throw new Error("Only owners can drop the history of a document");
    }
    if (compact) {
      this.snapshots = [];
      this.actions = this.actions.filter(a => a.actionNum > actionNum);
    }
    const latest = this.snapshots[this.snapshots.length - 1];
    if (latest && (actionNum < latest.actionNum || (actionNum === latest.actionNum && latest.keyId === keyId))) {
      return;
    }
    this.snapshots = this.snapshots.filter(s => s.actionNum !== actionNum);
    this.snapshots.push({ actionNum, keyId, payload, size: base64ToBytes(payload).length, timeMs: Date.now() });
  }

  private _append(record: Omit<EncryptedActionRecord, "actionNum" | "timeMs">): EncryptedActionRecord {
    const full = { ...record, actionNum: this.head + 1, timeMs: Date.now() };
    this.actions.push(full);
    return full;
  }

  private _broadcast(from: RelayClient | null, record: EncryptedActionRecord) {
    for (const client of this._clients) {
      if (client !== from) {
        // (Failures show in the browser's next use of the document.)
        const deliver = () => client.doc ? client.doc.receiveAction(record).catch(() => {}) : Promise.resolve();
        if (this.holdBroadcasts) { this._held.push(deliver); } else { void deliver(); }
      }
    }
  }
}

export class RelayClient implements IEncryptionRelay {
  public doc?: LocalActiveDoc;
  constructor(private _relay: MemoryRelay, public readonly userId: number) {}

  public async fetchActions(afterActionNum: number) {
    return this._relay.actions.filter(a => a.actionNum > afterActionNum);
  }

  public async pushAction(baseActionNum: number, keyId: string, payload: Base64,
    options?: { consumeInbox?: number[] }) {
    const consume = options?.consumeInbox || [];
    // (As the server does: answers leave the inbox with the change, or the change is refused.)
    if (!consume.every(id => this._relay.inbox.some(e => e.id === id))) {
      return { accepted: false as const, head: this._relay.head };
    }
    const result = this._relay.push(this, baseActionNum, keyId, payload);
    if (result.accepted) { this._relay.inbox = this._relay.inbox.filter(e => !consume.includes(e.id)); }
    return result;
  }

  public async saveSnapshot(actionNum: number, keyId: string, payload: Uint8Array, options?: { compact?: boolean }) {
    this._relay.saveSnapshot(this.userId, actionNum, keyId, bytesToBase64(payload), options?.compact);
  }

  public async fetchSnapshot(snapshot: EncryptedSnapshotRecord) {
    const found = this._relay.snapshots.find(s => s.actionNum === snapshot.actionNum);
    if (!found) { throw new Error("Snapshot not found"); }
    return base64ToBytes(found.payload);
  }

  public async uploadFile(ciphertext: Uint8Array) {
    const fileId = Math.random().toString(16).slice(2).padEnd(32, "0").slice(0, 32);
    this._relay.files.set(fileId, bytesToBase64(ciphertext));
    return { fileId };
  }

  public async fetchFile(fileId: string) {
    const payload = this._relay.files.get(fileId);
    if (payload === undefined) { throw new Error("File not found"); }
    return base64ToBytes(payload);
  }

  public async getKeys() {
    return this._relay.getKeys(this.userId);
  }

  public async listMembers() {
    return this._relay.listMembers();
  }

  public async createKey(request: NewKeyRequest, snapshot?: { payload: Uint8Array, compact: boolean }) {
    return this._relay.createKey(this, request, snapshot);
  }

  public async getSnapshot(actionNum: number) {
    const found = this._relay.snapshots.find(s => s.actionNum === actionNum);
    if (!found) { throw new Error("Snapshot not found"); }
    return found;
  }

  public async restoreSnapshot(baseActionNum: number, keyId: string, payload: Uint8Array) {
    return this._relay.restore(this, baseActionNum, keyId, bytesToBase64(payload));
  }

  public async listInbox() {
    return this._relay.inbox.slice(0, 200);
  }

  public async dropInbox(ids: number[]) {
    this._relay.inbox = this._relay.inbox.filter(e => !ids.includes(e.id));
  }

  public async submitSuggestion(keyId: string, payload: Base64) {
    if (this._relay.currentKey(DOC_SCOPE)?.keyId !== keyId) { throw new Error("Not the current document key"); }
    const id = this._relay.suggestions.length + 1;
    this._relay.suggestions.push({ id, keyId, payload, userId: this.userId, timeMs: Date.now() });
    return id;
  }

  public async listSuggestions() {
    const member = this._relay.members.find(m => m.userId === this.userId)!;
    return this._relay.suggestions.filter(s => member.access !== "viewers" || s.userId === this.userId);
  }

  public async resolveSuggestion(id: number) {
    this._relay.suggestions = this._relay.suggestions.filter(s => s.id !== id);
  }

  public async releaseScope(scope: string, baseActionNum: number, record?: Base64) {
    return this._relay.releaseScope(this, scope, baseActionNum, record);
  }
}
