/**
 * The server side of encrypted documents. The server can't read them, so instead of opening them
 * (as ActiveDoc does for regular documents), it relays ciphertext between the browsers that have
 * them open, and stores it (see EncryptedDocStorage):
 *  - openEncryptedDoc returns the latest snapshot and the changes since, the document's keys and
 *    the caller's copies of them, and subscribes the browser to further changes;
 *  - pushEncryptedAction appends a change if it was computed on top of the latest one, and
 *    forwards it to the other subscribed browsers;
 *  - saveEncryptedSnapshot stores a snapshot, which browsers save periodically;
 *  - listEncryptionMembers, shareEncryptionKeys, createEncryptionKey, revokeEncryptionKeys and
 *    requestKeyRotation manage keys (see EncryptionTypes.ts);
 *  - createEncryptionKey (for a new column scope) and releaseEncryptionScope make columns private
 *    and public again: the server keeps track of which columns are private (ScopeBinding), as
 *    members could otherwise change it in the document;
 *  - uploadEncryptedFile and fetchEncryptedFile store and return encrypted attachments.
 *
 * Access is checked on every call, against the document's regular permissions: viewers can read,
 * editors can also write. Keys can only be given out by owners holding them, and only to members.
 * Members who lose access lose their copies of the keys, which get replaced on the next edit.
 */
import { ApiError } from "app/common/ApiError";
import { CommEncryptionMessage } from "app/common/CommTypes";
import {
  Base64, DOC_SCOPE, DocKeyRecord, EncryptedActionRecord, EncryptedDocOpenResult, EncryptedPushResult,
  EncryptionKeysResult,
  EncryptionMember, isColumnScope, isEncryptedDoc, NewKeyRequest,
} from "app/common/encryption/EncryptionTypes";
import { ANONYMOUS_USER_EMAIL, EVERYONE_EMAIL, getRealAccess } from "app/common/UserAPI";
import { User } from "app/gen-server/entity/User";
import { HomeDBManager } from "app/gen-server/lib/homedb/HomeDBManager";
import { Client } from "app/server/lib/Client";
import { Comm } from "app/server/lib/Comm";
import { DocAuthorizer, DocAuthorizerImpl } from "app/server/lib/DocAuthorizer";
import { EncryptedDocFile, EncryptedDocStorage } from "app/server/lib/encryption/EncryptedDocStorage";
import { EncryptionStore } from "app/server/lib/encryption/EncryptionStore";
import { IDocStorageManager } from "app/server/lib/IDocStorageManager";
import log from "app/server/lib/log";

import { In } from "typeorm";

// Base64 of a snapshot, change or file can't be bigger than this (the websocket limit is 100MB).
const MAX_PAYLOAD_LENGTH = 90e6;
const MAX_KEY_LENGTH = 64 * 1024;

type Role = "viewers" | "editors" | "owners";

interface Subscription {
  auth: DocAuthorizer;
}

class Refused extends Error {
  constructor(public head: number) { super("refused"); }
}

export class EncryptionRelay {
  private _keys: EncryptionStore;
  private _storage: EncryptedDocStorage;
  // For each docId, the clients that have it open.
  private _subscribers = new Map<string, Map<Client, Subscription>>();

  constructor(private _dbManager: HomeDBManager, storageManager: IDocStorageManager) {
    this._keys = new EncryptionStore(_dbManager);
    this._storage = new EncryptedDocStorage(storageManager);
  }

  public registerCommMethods(comm: Comm) {
    comm.registerMethods({
      openEncryptedDoc: (client: Client, docId: string) => this.openDoc(client, docId),
      closeEncryptedDoc: (client: Client, docId: string) => this.closeDoc(client, docId),
      fetchEncryptedActions: (client: Client, docId: string, afterActionNum: number) =>
        this.fetchActions(client, docId, afterActionNum),
      pushEncryptedAction: (client: Client, docId: string, baseActionNum: number, keyId: string, payload: Base64) =>
        this.pushAction(client, docId, baseActionNum, keyId, payload),
      saveEncryptedSnapshot: (client: Client, docId: string, actionNum: number, keyId: string, payload: Base64,
        options?: { compact?: boolean }) => this.saveSnapshot(client, docId, actionNum, keyId, payload, options),
      getEncryptionKeys: (client: Client, docId: string) => this.getKeys(client, docId),
      listEncryptionMembers: (client: Client, docId: string) => this.listMembers(client, docId),
      shareEncryptionKeys: (client: Client, docId: string, wraps: DocKeyRecord[]) =>
        this.shareKeys(client, docId, wraps),
      createEncryptionKey: (client: Client, docId: string, request: NewKeyRequest) =>
        this.createKey(client, docId, request),
      revokeEncryptionKeys: (client: Client, docId: string, userIds: number[], scope?: string) =>
        this.revokeKeys(client, docId, userIds, scope),
      requestKeyRotation: (client: Client, docId: string, scope: string) =>
        this.requestRotation(client, docId, scope),
      releaseEncryptionScope: (client: Client, docId: string, scope: string, baseActionNum: number) =>
        this.releaseScope(client, docId, scope, baseActionNum),
      uploadEncryptedFile: (client: Client, docId: string, payload: Base64) => this.uploadFile(client, docId, payload),
      fetchEncryptedFile: (client: Client, docId: string, fileId: string) => this.fetchFile(client, docId, fileId),
    });
  }

  public async close() {
    await this._storage.close();
  }

  public async openDoc(client: Client, docId: string): Promise<EncryptedDocOpenResult> {
    const auth = await this._authorize(client, docId, "viewers");
    this._subscribe(client, docId, auth);
    if (auth.getCachedAuth().access !== "viewers") {
      // Members who lost access shouldn't keep their copies of the keys.
      await this._getMembers(client, docId);
    }
    const userId = this._getUserId(client);
    const { snapshot, actions, head } = await this._storage.withDoc(docId, { write: false }, async (file) => {
      const latest = await file.getLatestSnapshot();
      return {
        snapshot: latest,
        actions: await file.getActions(latest?.actionNum ?? 0),
        head: await file.getHead(),
      };
    });
    const fullUser = client.authSession.fullUser;
    const user = userId ? await this._dbManager.getUser(userId) : null;
    return {
      snapshot,
      actions,
      head,
      ...await this._getKeysFor(docId, userId),
      access: auth.getCachedAuth().access!,
      user: {
        id: userId,
        email: fullUser?.email ?? null,
        name: fullUser?.name ?? null,
        ref: fullUser?.ref ?? null,
        vaultUserId: user?.options?.authSubject ?? null,
      },
    };
  }

  public async closeDoc(client: Client, docId: string): Promise<void> {
    this._unsubscribe(client, docId);
  }

  public async fetchActions(client: Client, docId: string, afterActionNum: number) {
    // Fetching changes also (re)subscribes to them: browsers do it after reconnecting.
    this._subscribe(client, docId, await this._authorize(client, docId, "viewers"));
    afterActionNum = checkActionNum(afterActionNum);
    return this._storage.withDoc(docId, { write: false }, file => file.getActions(afterActionNum));
  }

  public async pushAction(client: Client, docId: string, baseActionNum: number, keyId: string,
    payload: Base64): Promise<EncryptedPushResult> {
    await this._authorize(client, docId, "editors");
    checkPayload(payload);
    baseActionNum = checkActionNum(baseActionNum);
    const userId = this._getUserId(client);
    // Changes must use the current document key: after a key change, changes made with the
    // previous one are refused, and their author catches up (getting the new key) and retries.
    const docKey = await this._keys.getCurrentKey(docId, DOC_SCOPE);
    if (docKey?.keyId !== keyId) {
      return { accepted: false, head: await this._getHead(docId) };
    }
    const result = await this._storage.withDoc(docId, { write: true }, file =>
      file.appendAction(baseActionNum, { kind: "change", keyId, payload, userId }));
    if (!result.accepted) { return result; }
    this._broadcast(docId, client, { type: "encryptedDocAction", data: { docId, action: result.action } });
    return { accepted: true, actionNum: result.action.actionNum, timeMs: result.action.timeMs };
  }

  public async saveSnapshot(client: Client, docId: string, actionNum: number, keyId: string,
    payload: Base64, options: { compact?: boolean } = {}): Promise<void> {
    await this._authorize(client, docId, "editors");
    checkPayload(payload);
    actionNum = checkActionNum(actionNum);
    const userId = this._requireUserId(client);
    const docKey = await this._keys.getCurrentKey(docId, DOC_SCOPE);
    if (docKey?.keyId !== keyId) {
      throw new ApiError("Snapshots must use the current document key", 409);
    }
    if (!(await this._keys.getWraps(docId, { userId, keyIds: [keyId] })).length) {
      throw new ApiError("Only a member holding the document key can save it", 403);
    }
    await this._storage.withDoc(docId, { write: true }, file =>
      file.saveSnapshot(actionNum, keyId, payload, userId, { compact: Boolean(options?.compact) }));
  }

  public async getKeys(client: Client, docId: string): Promise<EncryptionKeysResult> {
    await this._authorize(client, docId, "viewers");
    return this._getKeysFor(docId, this._getUserId(client));
  }

  /** Lists members of the document (those with access to it), and the keys they hold. */
  public async listMembers(client: Client, docId: string): Promise<EncryptionMember[]> {
    await this._authorize(client, docId, "viewers");
    const members = await this._getMembers(client, docId);
    const wraps = await this._keys.getWraps(docId);
    return members.map(m => ({ ...m, keyIds: wraps.filter(w => w.userId === m.userId).map(w => w.keyId) }));
  }

  /**
   * Stores members' copies of existing keys. Only owners holding a key can give it, and only to
   * members of the document (this is how members get access to encrypted content, and to private
   * columns).
   */
  public async shareKeys(client: Client, docId: string, wraps: DocKeyRecord[]): Promise<void> {
    await this._authorize(client, docId, "owners");
    const callerId = this._requireUserId(client);
    checkWraps(wraps, { withKeyId: true });
    const held = new Set((await this._keys.getWraps(docId, { userId: callerId })).map(w => w.keyId));
    if (!wraps.every(w => held.has(w.keyId))) {
      throw new ApiError("Only members holding a key can share it", 403);
    }
    await this._checkMembers(client, docId, wraps.map(w => w.userId));
    await this._keys.setWraps(docId, wraps, callerId);
    this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
  }

  /**
   * Creates a key, with copies for some members:
   *  - the document's first key (by an owner, when setting up a new document);
   *  - the first key of a new column scope (by an owner), which makes the column request.colRef
   *    private;
   *  - a new key replacing the current one of a scope, for members who held it (by any editor
   *    holding it). This is how keys get replaced after someone lost access to them.
   * Except for the document's first key, the key change gets recorded in the document's history,
   * after baseActionNum if that's still the latest change (otherwise it's refused, as a change
   * would be), so that all browsers switch to the new key at the same point.
   */
  public async createKey(client: Client, docId: string, request: NewKeyRequest): Promise<EncryptedPushResult> {
    const auth = await this._authorize(client, docId, "editors");
    const callerId = this._requireUserId(client);
    const { scope, keyId, baseActionNum } = request;
    if (scope !== DOC_SCOPE && !(isColumnScope(scope) && /^column:[a-z0-9]{1,64}$/.test(scope))) {
      throw new ApiError("Invalid key scope", 400);
    }
    if (typeof keyId !== "string" || !keyId.startsWith(`${scope}~`) || keyId.length > 200) {
      throw new ApiError("Invalid key id", 400);
    }
    checkActionNum(baseActionNum);
    const wraps = (request.wraps || []).map(w => ({ ...w, keyId }));
    checkWraps(wraps, { withKeyId: true });
    if (!wraps.some(w => w.userId === callerId)) {
      throw new ApiError("A new key must include a copy for its creator", 400);
    }
    const isOwner = auth.getCachedAuth().access === "owners";
    const current = await this._keys.getCurrentKey(docId, scope);
    if (current) {
      // Replacing a key: only for those who held it, by one of them.
      const holders = new Set((await this._keys.getWraps(docId, { keyIds: [current.keyId] })).map(w => w.userId));
      if (!holders.has(callerId)) {
        throw new ApiError("Only members holding a key can replace it", 403);
      }
      if (!wraps.every(w => holders.has(w.userId))) {
        throw new ApiError("A new key can only be given to those who held the one it replaces", 403);
      }
    } else if (!isOwner) {
      throw new ApiError("Only owners can create keys", 403);
    } else if (scope !== DOC_SCOPE && !(await this._keys.getCurrentKey(docId, DOC_SCOPE))) {
      throw new ApiError("The document key must be created first", 400);
    }
    const colRef = request.colRef;
    const bindsColumn = !current && isColumnScope(scope);
    if (bindsColumn) {
      if (!Number.isInteger(colRef) || colRef! <= 0) {
        throw new ApiError("A new column scope must say which column it makes private", 400);
      }
      const bindings = await this._keys.getBindings(docId);
      if (bindings.some(b => b.scope === scope)) {
        throw new ApiError("This scope was already used", 409);
      }
      if (bindings.some(b => b.colRef === colRef && b.releasedAt === null)) {
        throw new ApiError("This column is already private", 409);
      }
    }
    await this._checkMembers(client, docId, wraps.map(w => w.userId));

    if (scope === DOC_SCOPE && !current) {
      // Setting up a new document: nothing to order it against.
      const initialized = await this._storage.withDoc(docId, { write: false }, file => file.hasSnapshot());
      if (initialized || await this._keys.hasAnyKey(docId)) {
        throw new ApiError("Encrypted document is already initialized", 409);
      }
      await this._dbManager.connection.transaction(manager =>
        this._keys.addKey(manager, docId, scope, keyId, wraps, callerId, 0));
      this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
      return { accepted: true, actionNum: 0, timeMs: Date.now() };
    }

    let action: EncryptedActionRecord;
    try {
      // The key and its entry in the history are added together, or not at all. The entry, if
      // accepted, follows baseActionNum.
      const actionNum = baseActionNum + 1;
      action = await this._storage.withDoc(docId, { write: true }, (file: EncryptedDocFile) =>
        this._dbManager.connection.transaction(async (manager) => {
          await this._keys.addKey(manager, docId, scope, keyId, wraps, callerId, actionNum);
          if (bindsColumn) {
            await this._keys.bindScope(manager, docId, scope, colRef!, actionNum, callerId);
          }
          const res = await file.appendAction(baseActionNum, { kind: "key", keyId, payload: "", userId: callerId });
          if (!res.accepted) { throw new Refused(res.head); }
          return res.action;
        }));
    } catch (e) {
      if (e instanceof Refused) { return { accepted: false, head: e.head }; }
      throw e;
    }
    this._broadcast(docId, client, { type: "encryptedDocAction", data: { docId, action } });
    this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
    return { accepted: true, actionNum: action.actionNum, timeMs: action.timeMs };
  }

  /**
   * Makes a private column public again (by an owner holding its key). Recorded in the history
   * like a key change, after baseActionNum if that's still the latest change. Its keys stay, to
   * read older content.
   */
  public async releaseScope(client: Client, docId: string, scope: string,
    baseActionNum: number): Promise<EncryptedPushResult> {
    await this._authorize(client, docId, "owners");
    const callerId = this._requireUserId(client);
    checkActionNum(baseActionNum);
    if (typeof scope !== "string" || !isColumnScope(scope)) { throw new ApiError("Invalid key scope", 400); }
    if (!(await this._keys.getBindings(docId)).some(b => b.scope === scope && b.releasedAt === null)) {
      throw new ApiError("This column is not private", 409);
    }
    const current = await this._keys.getCurrentKey(docId, scope);
    if (!current || !(await this._keys.getWraps(docId, { userId: callerId, keyIds: [current.keyId] })).length) {
      throw new ApiError("Only members holding a column's key can make it public", 403);
    }
    let action: EncryptedActionRecord;
    try {
      action = await this._storage.withDoc(docId, { write: true }, (file: EncryptedDocFile) =>
        this._dbManager.connection.transaction(async (manager) => {
          await this._keys.releaseScope(manager, docId, scope, baseActionNum + 1);
          const res = await file.appendAction(baseActionNum,
            { kind: "key", keyId: current.keyId, payload: "", userId: callerId });
          if (!res.accepted) { throw new Refused(res.head); }
          return res.action;
        }));
    } catch (e) {
      if (e instanceof Refused) { return { accepted: false, head: e.head }; }
      throw e;
    }
    this._broadcast(docId, client, { type: "encryptedDocAction", data: { docId, action } });
    this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
    return { accepted: true, actionNum: action.actionNum, timeMs: action.timeMs };
  }

  /**
   * Takes keys away from members (e.g. when removing them from those who can read some private
   * columns): their copies are deleted, and the current keys of the affected scopes get replaced
   * on the next edit.
   */
  public async revokeKeys(client: Client, docId: string, userIds: number[], scope?: string): Promise<void> {
    await this._authorize(client, docId, "owners");
    if (!Array.isArray(userIds) || !userIds.every(id => Number.isInteger(id))) {
      throw new ApiError("Invalid users", 400);
    }
    const keyIds = scope ? (await this._keys.getKeys(docId)).filter(k => k.scope === scope).map(k => k.keyId) :
      undefined;
    await this._keys.revokeWraps(docId, userIds, keyIds);
    this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
  }

  /** Flags the current key of a scope to be replaced on the next edit. */
  public async requestRotation(client: Client, docId: string, scope: string): Promise<void> {
    await this._authorize(client, docId, "owners");
    await this._keys.requestRotation(docId, scope);
    this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
  }

  public async uploadFile(client: Client, docId: string, payload: Base64): Promise<{ fileId: string }> {
    await this._authorize(client, docId, "editors");
    checkPayload(payload);
    const maxBytes = Number(process.env.GRIST_MAX_UPLOAD_ATTACHMENT_MB) * 1024 * 1024;
    if (maxBytes && payload.length * 3 / 4 > maxBytes * 1.1) {
      throw new ApiError("Attachment is too large", 413);
    }
    const userId = this._getUserId(client);
    const fileId = await this._storage.withDoc(docId, { write: true }, file => file.saveFile(payload, userId));
    return { fileId };
  }

  public async fetchFile(client: Client, docId: string, fileId: string): Promise<Base64> {
    await this._authorize(client, docId, "viewers");
    if (typeof fileId !== "string" || !/^[0-9a-f]{32}$/.test(fileId)) { throw new ApiError("Invalid file", 400); }
    const payload = await this._storage.withDoc(docId, { write: false }, file => file.getFile(fileId));
    if (payload === null) { throw new ApiError("File not found", 404); }
    return payload;
  }

  private async _getHead(docId: string) {
    return this._storage.withDoc(docId, { write: false }, file => file.getHead());
  }

  private async _getKeysFor(docId: string, userId: number | null): Promise<EncryptionKeysResult> {
    return {
      keys: await this._keys.getKeys(docId),
      myKeys: userId ? await this._keys.getWraps(docId, { userId }) : [],
      bindings: await this._keys.getBindings(docId),
    };
  }

  private async _authorize(client: Client, docId: string, role: Role): Promise<DocAuthorizer> {
    if (typeof docId !== "string" || !docId) { throw new ApiError("Missing document id", 400); }
    const sub = this._subscribers.get(docId)?.get(client);
    const auth = sub?.auth ?? new DocAuthorizerImpl({
      dbManager: this._dbManager, urlId: docId, openMode: "default", authSession: client.authSession,
    });
    try {
      // This re-checks access each time (with the home db's caching), so that revoked access
      // takes effect for open documents too.
      await auth.assertAccess(role);
    } catch (e) {
      if (role === "viewers") { this._unsubscribe(client, docId); }
      throw e;
    }
    const docAuth = auth.getCachedAuth();
    if (docAuth.docId !== docId) {
      throw new ApiError(`Expected docId ${docAuth.docId}, not ${docId}`, 400);
    }
    if (!isEncryptedDoc(docAuth.cachedDoc)) {
      throw new ApiError("Document is not end-to-end encrypted", 400);
    }
    return auth;
  }

  /**
   * Returns the members of the document, i.e. users with access to it. As a side effect, takes
   * keys away from users who no longer have access (flagging those keys for replacement).
   */
  private async _getMembers(client: Client, docId: string): Promise<Omit<EncryptionMember, "keyIds">[]> {
    const scope = { userId: client.authSession.userId ?? this._dbManager.getAnonymousUserId(), urlId: docId };
    const result = await this._dbManager.getDocAccess(scope, { flatten: true, excludeUsersWithoutAccess: true });
    if (result.status !== 200 || !result.data) {
      throw new ApiError(result.errMessage || "Cannot list members", result.status || 500);
    }
    const permissionData = result.data;
    const users = permissionData.users.filter(u =>
      !u.anonymous && u.email !== EVERYONE_EMAIL && u.email !== ANONYMOUS_USER_EMAIL);
    const records = users.length === 0 ? [] :
      await this._dbManager.connection.manager.find(User, { where: { id: In(users.map(u => u.id)) } });
    const byId = new Map(records.map(r => [r.id, r]));
    const members = users.map(u => ({
      userId: u.id,
      email: u.email,
      name: u.name,
      access: getRealAccess(u, permissionData) || "",
      vaultUserId: byId.get(u.id)?.options?.authSubject ?? null,
    })).filter(m => m.access);

    // Key holders not listed may have lost access. The listing depends on who asks, so check
    // each one's access to the document directly before taking their keys away.
    const memberIds = new Set(members.map(m => m.userId));
    const unlisted = [...new Set((await this._keys.getWraps(docId)).map(w => w.userId))]
      .filter(id => !memberIds.has(id));
    const stale: number[] = [];
    for (const userId of unlisted) {
      const docAuth = await this._dbManager.getDocAuthCached({
        urlId: docId, userId, org: client.authSession.org || "",
      });
      if (!docAuth.access) { stale.push(userId); }
    }
    if (stale.length > 0) {
      log.info(`EncryptionRelay: revoking keys of ${stale.length} former member(s) of ${docId}`);
      await this._keys.revokeWraps(docId, stale);
      this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
    }
    return members;
  }

  private async _checkMembers(client: Client, docId: string, userIds: number[]) {
    const memberIds = new Set((await this._getMembers(client, docId)).map(m => m.userId));
    if (!userIds.every(id => memberIds.has(id))) {
      throw new ApiError("Keys can only be given to members of the document", 400);
    }
  }

  private _getUserId(client: Client): number | null {
    const userId = client.authSession.userId;
    return (!userId || userId === this._dbManager.getAnonymousUserId()) ? null : userId;
  }

  private _requireUserId(client: Client): number {
    const userId = this._getUserId(client);
    if (!userId) { throw new ApiError("Encryption keys require being logged in", 401); }
    return userId;
  }

  private _subscribe(client: Client, docId: string, auth: DocAuthorizer) {
    let subs = this._subscribers.get(docId);
    if (!subs) { this._subscribers.set(docId, subs = new Map()); }
    subs.set(client, { auth });
  }

  private _unsubscribe(client: Client, docId: string) {
    const subs = this._subscribers.get(docId);
    subs?.delete(client);
    if (subs?.size === 0) { this._subscribers.delete(docId); }
  }

  private _broadcast(docId: string, except: Client | null, message: CommEncryptionMessage) {
    const subs = this._subscribers.get(docId);
    if (!subs) { return; }
    for (const [client, sub] of [...subs.entries()]) {
      if (client.isDestroyed()) {
        this._unsubscribe(client, docId);
      } else if (client !== except) {
        this._sendIfAllowed(client, sub, docId, message).catch(e => log.warn("EncryptionRelay: broadcast failed", e));
      }
    }
  }

  // Members may have lost access since they opened the document: check again (this is cached).
  private async _sendIfAllowed(client: Client, sub: Subscription, docId: string, message: CommEncryptionMessage) {
    try {
      await sub.auth.assertAccess("viewers");
    } catch (e) {
      this._unsubscribe(client, docId);
      return;
    }
    await client.sendMessageOrInterrupt(message);
  }
}

function checkPayload(payload: unknown): asserts payload is string {
  if (typeof payload !== "string" || payload.length > MAX_PAYLOAD_LENGTH || !/^[A-Za-z0-9+/=]*$/.test(payload)) {
    throw new ApiError("Invalid encrypted payload", 400);
  }
}

function checkActionNum(actionNum: unknown): number {
  if (!Number.isInteger(actionNum) || (actionNum as number) < 0) {
    throw new ApiError("Invalid action number", 400);
  }
  return actionNum as number;
}

function checkWraps(wraps: unknown, options: { withKeyId: boolean }): asserts wraps is DocKeyRecord[] {
  if (!Array.isArray(wraps) || wraps.length === 0) { throw new ApiError("No keys given", 400); }
  for (const w of wraps) {
    if (!Number.isInteger(w?.userId) || typeof w.wrappedKey !== "string" || !w.wrappedKey ||
      w.wrappedKey.length > MAX_KEY_LENGTH || !Number.isInteger(w.keyVersion) ||
      (options.withKeyId && typeof w.keyId !== "string")) {
      throw new ApiError("Invalid key", 400);
    }
  }
}
