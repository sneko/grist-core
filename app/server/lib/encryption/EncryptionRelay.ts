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
 *  - uploadEncryptedFile and fetchEncryptedFile store and return encrypted attachments;
 *  - beginEncryptedUpload, appendEncryptedUpload and fetchEncryptedSnapshot move snapshots and
 *    files too big for a single message, by parts.
 *
 * Access is checked on every call, against the document's regular permissions: viewers can read,
 * editors holding the document key can also write. Keys can only be given out by owners holding
 * them, and only to members. Members who lose access lose their copies of the keys, which get
 * replaced on the next edit. Documents can't grow beyond the size their site's plan allows.
 */
import { ApiError } from "app/common/ApiError";
import { CommEncryptionMessage } from "app/common/CommTypes";
import {
  Base64, DOC_SCOPE, DocKeyRecord, DocLockInfo, EncryptedActionRecord, EncryptedDocOpenResult,
  EncryptedInboxEntry, EncryptedPushResult, EncryptedSnapshotInfo, EncryptedSnapshotRecord, EncryptedSuggestion,
  EncryptionKeysResult,
  EncryptionMember, isColumnScope, isEncryptedDoc, NewKeyRequest,
} from "app/common/encryption/EncryptionTypes";
import { Features } from "app/common/Features";
import { ANONYMOUS_USER_EMAIL, EVERYONE_EMAIL, getRealAccess } from "app/common/UserAPI";
import { User } from "app/gen-server/entity/User";
import { HomeDBManager } from "app/gen-server/lib/homedb/HomeDBManager";
import { Client } from "app/server/lib/Client";
import { Comm } from "app/server/lib/Comm";
import { DocAuthorizer, DocAuthorizerImpl } from "app/server/lib/DocAuthorizer";
import { DocLock, docLockedError, getDocLock, lockDoc, unlockDoc } from "app/server/lib/encryption/docLocks";
import {
  EncryptedDocFile, EncryptedDocStorage, MAX_INLINE_BYTES, PayloadSource,
} from "app/server/lib/encryption/EncryptedDocStorage";
import { getMaxEncryptedDocSize } from "app/server/lib/encryption/encryptionConfig";
import { EncryptionStore } from "app/server/lib/encryption/EncryptionStore";
import { expressWrap } from "app/server/lib/expressWrap";
import { getGoogleAuth } from "app/server/lib/GoogleAuth";
import { IDocNotificationManager } from "app/server/lib/IDocNotificationManager";
import { IDocStorageManager } from "app/server/lib/IDocStorageManager";
import log from "app/server/lib/log";

import * as express from "express";
import { In } from "typeorm";

import type { EncryptionConversion } from "app/server/lib/encryption/EncryptionConversion";

// Base64 of a change, or of a part of a snapshot or file, can't be bigger than this (the websocket
// limit is 100MB). Bigger snapshots and files go by parts (see beginEncryptedUpload).
const MAX_PAYLOAD_LENGTH = 90e6;
const MAX_KEY_LENGTH = 64 * 1024;
// Suggestions waiting to be handled, at most, per document.
const MAX_SUGGESTIONS = 1000;

type Role = "viewers" | "editors" | "owners";

/** What initializeEncryptedDoc takes. */
export interface EncryptedDocInit {
  docKey: { keyId: string, wraps: DocKeyRecord[] };
  columnKeys?: { scope: string, keyId: string, colRef?: number, wraps: DocKeyRecord[] }[];
  snapshot: PayloadSource;
}

/** Options of pushEncryptedAction. */
export interface PushOptions {
  // Answers to forms that the change adds to the document (see EncryptedForms.ts): removed from
  // the inbox along with it.
  consumeInbox?: number[];
}

// Limits for forms of encrypted documents: size of a form and of an answer (base64), answers
// waiting per document, answers handled at once, and answers taken per minute from one address
// for one document.
const MAX_FORM_SPEC_LENGTH = 4e6;
const MAX_ANSWER_LENGTH = 1e6;
const MAX_INBOX = 10000;
const MAX_INBOX_BATCH = 200;
// Files attached in answers: how many per answer, how big each, and how much in all waiting.
const MAX_ANSWER_FILES = 20;
const MAX_ANSWER_FILE_BYTES = 20 * 1024 * 1024;
const MAX_INBOX_FILES_BYTES = 500 * 1024 * 1024;
const ANSWERS_PER_MINUTE = 30;

export const Deps = {
  // Locks of documents (e.g. while converting them) are released if their holder stops renewing
  // them (they do it regularly) for this long, e.g. if their browser got closed.
  lockExpiryMs: 60 * 1000,
};

interface Subscription {
  auth: DocAuthorizer;
  stopListening: () => void;
}

class Refused extends Error {
  constructor(public head: number) { super("refused"); }
}

/** Counts recent events by key, to limit how many happen per minute. */
class RateLimiter {
  private _counts = new Map<string, { count: number, resetAt: number }>();
  constructor(private _perMinute: number) {}

  public allow(key: string): boolean {
    const now = Date.now();
    if (this._counts.size > 10000) {
      for (const [k, v] of this._counts) { if (v.resetAt < now) { this._counts.delete(k); } }
    }
    const entry = this._counts.get(key);
    if (!entry || entry.resetAt < now) {
      this._counts.set(key, { count: 1, resetAt: now + 60000 });
      return true;
    }
    entry.count++;
    return entry.count <= this._perMinute;
  }
}

export class EncryptionRelay {
  // Set when documents can be converted to and from encryption (see EncryptionConversion.ts).
  public conversions?: EncryptionConversion;
  private _keys: EncryptionStore;
  private _storage: EncryptedDocStorage;
  // For each docId, the clients that have it open.
  private _subscribers = new Map<string, Map<Client, Subscription>>();
  private _answersLimiter = new RateLimiter(ANSWERS_PER_MINUTE);

  constructor(private _dbManager: HomeDBManager, storageManager: IDocStorageManager,
    private _notifier?: IDocNotificationManager) {
    this._keys = new EncryptionStore(_dbManager);
    this._storage = new EncryptedDocStorage(storageManager);
  }

  public registerCommMethods(comm: Comm) {
    comm.registerMethods({
      openEncryptedDoc: (client: Client, docId: string) => this.openDoc(client, docId),
      closeEncryptedDoc: (client: Client, docId: string) => this.closeDoc(client, docId),
      fetchEncryptedActions: (client: Client, docId: string, afterActionNum: number) =>
        this.fetchActions(client, docId, afterActionNum),
      pushEncryptedAction: (client: Client, docId: string, baseActionNum: number, keyId: string, payload: Base64,
        options?: PushOptions) => this.pushAction(client, docId, baseActionNum, keyId, payload, options),
      saveEncryptedSnapshot: (client: Client, docId: string, actionNum: number, keyId: string,
        payload: PayloadSource, options?: { compact?: boolean }) =>
        this.saveSnapshot(client, docId, actionNum, keyId, payload, options),
      fetchEncryptedSnapshot: (client: Client, docId: string, actionNum: number, offset: number, length: number) =>
        this.fetchSnapshot(client, docId, actionNum, offset, length),
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
      initializeEncryptedDoc: (client: Client, docId: string, init: EncryptedDocInit) =>
        this.initializeDoc(client, docId, init),
      releaseEncryptionScope: (client: Client, docId: string, scope: string, baseActionNum: number,
        record?: Base64) => this.releaseScope(client, docId, scope, baseActionNum, record),
      uploadEncryptedFile: (client: Client, docId: string, payload: PayloadSource) =>
        this.uploadFile(client, docId, payload),
      fetchEncryptedFile: (client: Client, docId: string, fileId: string, offset?: number, length?: number) =>
        this.fetchFile(client, docId, fileId, offset, length),
      listEncryptedSnapshots: (client: Client, docId: string) => this.listSnapshots(client, docId),
      getEncryptedSnapshot: (client: Client, docId: string, actionNum: number) =>
        this.getSnapshot(client, docId, actionNum),
      restoreEncryptedSnapshot: (client: Client, docId: string, baseActionNum: number, keyId: string,
        payload: PayloadSource) => this.restoreSnapshot(client, docId, baseActionNum, keyId, payload),
      lockEncryptedDoc: (client: Client, docId: string, reason: DocLockInfo["reason"]) =>
        this.lockDoc(client, docId, reason),
      unlockEncryptedDoc: (client: Client, docId: string) => this.unlockDoc(client, docId),
      getDocLock: (client: Client, docId: string) => this.getLock(client, docId),
      getGoogleDriveToken: (client: Client, docId: string, code: string) =>
        this.getGoogleDriveToken(client, docId, code),
      renewDocLock: (client: Client, docId: string) => this.renewLock(client, docId),
      publishEncryptedForm: (client: Client, docId: string, formId: string, spec: Base64) =>
        this.publishForm(client, docId, formId, spec),
      unpublishEncryptedForm: (client: Client, docId: string, formId: string) =>
        this.unpublishForm(client, docId, formId),
      listEncryptedInbox: (client: Client, docId: string) => this.listInbox(client, docId),
      dropEncryptedInbox: (client: Client, docId: string, ids: number[]) => this.dropInbox(client, docId, ids),
      fetchEncryptedInboxFile: (client: Client, docId: string, fileId: string, offset: number, length: number) =>
        this.fetchInboxFile(client, docId, fileId, offset, length),
      submitEncryptedSuggestion: (client: Client, docId: string, keyId: string, payload: Base64) =>
        this.submitSuggestion(client, docId, keyId, payload),
      listEncryptedSuggestions: (client: Client, docId: string) => this.listSuggestions(client, docId),
      resolveEncryptedSuggestion: (client: Client, docId: string, id: number) =>
        this.resolveSuggestion(client, docId, id),
      beginEncryptedUpload: (client: Client, docId: string) => this.beginUpload(client, docId),
      appendEncryptedUpload: (client: Client, docId: string, uploadId: string, seq: number, chunk: Base64) =>
        this.appendUpload(client, docId, uploadId, seq, chunk),
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
      const fileHead = await file.getHead();
      // Key changes are recorded in the history and in the home database together (see
      // createKey()); if recording them in the history failed, they're undone.
      if (await this._keys.dropChangesAfter(docId, fileHead)) {
        log.warn(`EncryptionRelay: dropped key changes of ${docId} missing from its history`);
      }
      return {
        snapshot: latest,
        actions: await file.getActions(latest?.actionNum ?? 0),
        head: fileHead,
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
    payload: Base64, options: PushOptions = {}): Promise<EncryptedPushResult> {
    const consume = options?.consumeInbox;
    if (consume !== undefined && (!Array.isArray(consume) || consume.length > MAX_INBOX_BATCH ||
      !consume.every(id => Number.isInteger(id)))) {
      throw new ApiError("Invalid inbox entries", 400);
    }
    const auth = await this._authorize(client, docId, "editors");
    checkPayload(payload);
    baseActionNum = checkActionNum(baseActionNum);
    const userId = this._requireUserId(client);
    this._assertUnlocked(client, docId);
    // Changes must use the current document key: after a key change, changes made with the
    // previous one are refused, and their author catches up (getting the new key) and retries.
    const docKey = await this._keys.getCurrentKey(docId, DOC_SCOPE);
    if (docKey?.keyId !== keyId) {
      return { accepted: false, head: await this._getHead(docId) };
    }
    // Only members holding the key can make changes others can read.
    await this._requireHolder(docId, userId, keyId);
    const result = await this._storage.withDoc(docId, { write: true }, file => file.transaction(async () => {
      await this._checkSize(auth, file, payload.length);
      const appended = await file.appendAction(baseActionNum, { kind: "change", keyId, payload, userId });
      // Answers to forms the change adds to the document leave the inbox with it (if another
      // member's browser added them already, the change is refused).
      if (appended.accepted && consume && await file.removeFromInbox(consume) !== consume.length) {
        throw new Refused(appended.action.actionNum - 1);
      }
      return appended;
    })).catch((e) => {
      if (e instanceof Refused) { return { accepted: false as const, head: e.head }; }
      throw e;
    });
    if (!result.accepted) { return result; }
    this._broadcast(docId, client, { type: "encryptedDocAction", data: { docId, action: result.action } });
    // Subscribers to the document's changes can only be told that it changed, and by whom.
    this._notifier?.notifySubscribersOfEncryptedChange?.(docId, userId)
      .catch(e => log.warn("EncryptionRelay: notification failed", e));
    return { accepted: true, actionNum: result.action.actionNum, timeMs: result.action.timeMs };
  }

  public async saveSnapshot(client: Client, docId: string, actionNum: number, keyId: string,
    payload: PayloadSource, options: { compact?: boolean } = {}): Promise<void> {
    const auth = await this._authorize(client, docId, "editors");
    checkPayloadSource(payload);
    actionNum = checkActionNum(actionNum);
    const userId = this._requireUserId(client);
    const compact = Boolean(options?.compact);
    // Compacting drops the history and older snapshots, which are what to recover from if a
    // member damages the document: only owners can do it (e.g. when making a column private).
    if (compact && auth.getCachedAuth().access !== "owners") {
      throw new ApiError("Only owners can drop the history of a document", 403);
    }
    this._assertUnlocked(client, docId);
    const docKey = await this._keys.getCurrentKey(docId, DOC_SCOPE);
    if (docKey?.keyId !== keyId) {
      throw new ApiError("Snapshots must use the current document key", 409);
    }
    await this._requireHolder(docId, userId, keyId);
    await this._storage.withDoc(docId, { write: true }, async (file) => {
      await this._checkSize(auth, file, typeof payload === "string" ? payload.length : 0);
      return file.saveSnapshot(actionNum, keyId, payload, userId, { compact });
    });
  }

  /** Returns part of a snapshot too big to be returned whole by openEncryptedDoc. */
  public async fetchSnapshot(client: Client, docId: string, actionNum: number, offset: number,
    length: number): Promise<Base64> {
    await this._authorize(client, docId, "viewers");
    actionNum = checkActionNum(actionNum);
    checkRange(offset, length);
    return this._storage.withDoc(docId, { write: false }, file => file.readSnapshot(actionNum, offset, length));
  }

  /** Starts an upload of a snapshot or file too big for a single message. Returns its id. */
  public async beginUpload(client: Client, docId: string): Promise<string> {
    const staging = this.conversions?.getStagingFile(client, docId);
    if (staging) { return staging.beginUpload(); }
    await this._authorize(client, docId, "editors");
    this._requireUserId(client);
    return this._storage.withDoc(docId, { write: true }, file => file.beginUpload());
  }

  /** Adds a part to an upload (parts are numbered from 0, and added in order). */
  public async appendUpload(client: Client, docId: string, uploadId: string, seq: number,
    chunk: Base64): Promise<void> {
    checkUploadId(uploadId);
    seq = checkActionNum(seq);
    checkPayload(chunk);
    const staging = this.conversions?.getStagingFile(client, docId);
    if (staging) {
      await staging.appendUpload(uploadId, seq, chunk, client.authSession.userId ?? null);
      return;
    }
    const auth = await this._authorize(client, docId, "editors");
    const userId = this._requireUserId(client);
    await this._storage.withDoc(docId, { write: true }, async (file) => {
      await this._checkSize(auth, file, chunk.length);
      await file.appendUpload(uploadId, seq, chunk, userId);
    });
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
    if (request.record !== undefined) { checkRecord(request.record); }
    const wraps = (request.wraps || []).map(w => ({ ...w, keyId }));
    checkWraps(wraps, { withKeyId: true });
    if (!wraps.some(w => w.userId === callerId)) {
      throw new ApiError("A new key must include a copy for its creator", 400);
    }
    const isOwner = auth.getCachedAuth().access === "owners";
    this._assertUnlocked(client, docId);
    if (request.snapshot !== undefined) {
      checkPayloadSource(request.snapshot);
      if (request.compact && !isOwner) {
        throw new ApiError("Only owners can drop the history of a document", 403);
      }
    }
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
      // Setting up a new document: nothing to order it against. (Checked and done under the
      // document's lock, so that two owners opening it at once can't both do it.)
      await this._storage.withDoc(docId, { write: false }, async (file) => {
        if (await file.hasSnapshot() || await this._keys.hasAnyKey(docId)) {
          throw new ApiError("Encrypted document is already initialized", 409);
        }
        await this._dbManager.connection.transaction(manager =>
          this._keys.addKey(manager, docId, scope, keyId, wraps, callerId, 0));
      });
      this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
      return { accepted: true, actionNum: 0, timeMs: Date.now() };
    }

    // A snapshot saved with the key change is encrypted with the document key current after it.
    const snapshotKeyId = scope === DOC_SCOPE ? keyId : (await this._keys.getCurrentKey(docId, DOC_SCOPE))?.keyId;
    let action: EncryptedActionRecord;
    try {
      // The key, its entry in the history, and the snapshot that comes with it, if any, are
      // added together, or not at all: the entry and snapshot are saved first, but committed
      // only once the key is (if that fails, see dropChangesAfter()). The entry, if accepted,
      // follows baseActionNum.
      const actionNum = baseActionNum + 1;
      action = await this._storage.withDoc(docId, { write: true }, file => file.transaction(async () => {
        const res = await file.appendAction(baseActionNum,
          { kind: "key", keyId, payload: request.record || "", userId: callerId });
        if (!res.accepted) { throw new Refused(res.head); }
        if (request.snapshot !== undefined) {
          await this._checkSize(auth, file, typeof request.snapshot === "string" ? request.snapshot.length : 0);
          await file.saveSnapshot(actionNum, snapshotKeyId!, request.snapshot, callerId, { compact: request.compact });
        }
        await this._dbManager.connection.transaction(async (manager) => {
          await this._keys.addKey(manager, docId, scope, keyId, wraps, callerId, actionNum);
          if (bindsColumn) {
            await this._keys.bindScope(manager, docId, scope, colRef!, actionNum, callerId);
          }
        });
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
   * Sets up a new encrypted document in one step (e.g. a copy of another one), by an owner: its
   * document key, keys of its private columns, and its initial snapshot. All of it, or nothing.
   */
  public async initializeDoc(client: Client, docId: string, init: EncryptedDocInit): Promise<void> {
    const auth = await this._authorize(client, docId, "owners");
    const callerId = this._requireUserId(client);
    const keys = [{ scope: DOC_SCOPE, ...init?.docKey }, ...(Array.isArray(init?.columnKeys) ? init.columnKeys : [])];
    const colRefs = new Set<number>();
    for (const key of keys) {
      const isDoc = key.scope === DOC_SCOPE;
      if (typeof key.scope !== "string" || (!isDoc && !/^column:[a-z0-9]{1,64}$/.test(key.scope)) ||
        typeof key.keyId !== "string" || !key.keyId.startsWith(`${key.scope}~`) || key.keyId.length > 200 ||
        (!isDoc && (!Number.isInteger(key.colRef) || key.colRef! <= 0 || colRefs.has(key.colRef!)))) {
        throw new ApiError("Invalid key", 400);
      }
      if (!isDoc) { colRefs.add(key.colRef!); }
      key.wraps = (Array.isArray(key.wraps) ? key.wraps : []).map(w => ({ ...w, keyId: key.keyId }));
      checkWraps(key.wraps, { withKeyId: true });
      if (!key.wraps.some(w => w.userId === callerId)) {
        throw new ApiError("A new key must include a copy for its creator", 400);
      }
      await this._checkMembers(client, docId, key.wraps.map(w => w.userId));
    }
    checkPayloadSource(init.snapshot);
    await this._storage.withDoc(docId, { write: true }, file => file.transaction(async () => {
      if (await file.hasSnapshot() || await this._keys.hasAnyKey(docId)) {
        throw new ApiError("Encrypted document is already initialized", 409);
      }
      await this._checkSize(auth, file, typeof init.snapshot === "string" ? init.snapshot.length : 0);
      await file.saveSnapshot(0, init.docKey.keyId, init.snapshot, callerId);
      await this._dbManager.connection.transaction(async (manager) => {
        for (const key of keys) {
          await this._keys.addKey(manager, docId, key.scope, key.keyId, key.wraps, callerId, 0);
          if (key.scope !== DOC_SCOPE) {
            await this._keys.bindScope(manager, docId, key.scope, key.colRef!, 0, callerId);
          }
        }
      });
    }));
    this._broadcast(docId, null, { type: "encryptedDocKeys", data: { docId } });
  }

  /**
   * Makes a private column public again (by an owner holding its key). Recorded in the history
   * like a key change, after baseActionNum if that's still the latest change. Its keys stay, to
   * read older content.
   */
  public async releaseScope(client: Client, docId: string, scope: string,
    baseActionNum: number, record?: Base64): Promise<EncryptedPushResult> {
    if (record !== undefined) { checkRecord(record); }
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
    this._assertUnlocked(client, docId);
    let action: EncryptedActionRecord;
    try {
      // As for createKey(): recorded in the history first, committed once recorded in the home
      // database.
      action = await this._storage.withDoc(docId, { write: true }, file => file.transaction(async () => {
        const res = await file.appendAction(baseActionNum,
          { kind: "key", keyId: current.keyId, payload: record || "", userId: callerId });
        if (!res.accepted) { throw new Refused(res.head); }
        await this._dbManager.connection.transaction(manager =>
          this._keys.releaseScope(manager, docId, scope, baseActionNum + 1));
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

  public async uploadFile(client: Client, docId: string, payload: PayloadSource): Promise<{ fileId: string }> {
    checkPayloadSource(payload);
    // Files of a document being encrypted go with its new content (see EncryptionConversion.ts).
    const staging = this.conversions?.getStagingFile(client, docId);
    if (staging) { return { fileId: await staging.saveFile(payload, client.authSession.userId ?? null) }; }
    const auth = await this._authorize(client, docId, "editors");
    const userId = this._requireUserId(client);
    this._assertUnlocked(client, docId);
    const fileId = await this._storage.withDoc(docId, { write: true }, async (file) => {
      await this._checkSize(auth, file, typeof payload === "string" ? payload.length : 0);
      // As for regular attachments (encryption adds a little).
      const maxBytes = Number(process.env.GRIST_MAX_UPLOAD_ATTACHMENT_MB) * 1024 * 1024;
      const size = typeof payload === "string" ? payload.length * 3 / 4 : await file.getUploadSize(payload.uploadId);
      if (maxBytes && size > maxBytes * 1.1 + 1024) {
        throw new ApiError("Attachment is too large", 413);
      }
      return file.saveFile(payload, userId);
    });
    return { fileId };
  }

  /**
   * Returns an encrypted file, or part of it (from offset, up to length bytes), with its size.
   * Files bigger than what one message can take are returned by parts.
   */
  public async fetchFile(client: Client, docId: string, fileId: string, offset: number = 0,
    length: number = MAX_INLINE_BYTES): Promise<{ payload: Base64, size: number }> {
    await this._authorize(client, docId, "viewers");
    if (typeof fileId !== "string" || !/^[0-9a-f]{32}$/.test(fileId)) { throw new ApiError("Invalid file", 400); }
    checkRange(offset, length);
    return this._storage.withDoc(docId, { write: false }, async (file) => {
      const size = await file.getFileSize(fileId);
      if (size === null) { throw new ApiError("File not found", 404); }
      return { payload: (await file.readFile(fileId, offset, length))!, size };
    });
  }

  /**
   * Publishes a form (or updates it), given its spec, encrypted with its link key (see
   * EncryptedForms.ts). Anyone with its link can then get it, and send answers.
   */
  public async publishForm(client: Client, docId: string, formId: string, spec: Base64): Promise<void> {
    const auth = await this._authorize(client, docId, "editors");
    this._requireUserId(client);
    checkFormId(formId);
    checkPayload(spec);
    if (spec.length > MAX_FORM_SPEC_LENGTH) { throw new ApiError("This form is too big", 413); }
    await this._storage.withDoc(docId, { write: true }, async (file) => {
      await this._checkSize(auth, file, spec.length);
      await file.setForm(formId, spec);
    });
  }

  public async unpublishForm(client: Client, docId: string, formId: string): Promise<void> {
    await this._authorize(client, docId, "editors");
    checkFormId(formId);
    await this._storage.withDoc(docId, { write: true }, file => file.removeForm(formId));
  }

  /** Answers to forms waiting to be added to the document (for members who can edit it). */
  public async listInbox(client: Client, docId: string): Promise<EncryptedInboxEntry[]> {
    await this._authorize(client, docId, "editors");
    return this._storage.withDoc(docId, { write: false }, file => file.getInbox(MAX_INBOX_BATCH));
  }

  /** Returns part of a file attached in an answer waiting in the inbox (see addFormEndpoints()). */
  public async fetchInboxFile(client: Client, docId: string, fileId: string, offset: number,
    length: number): Promise<{ payload: Base64, size: number }> {
    await this._authorize(client, docId, "editors");
    if (typeof fileId !== "string" || !/^[0-9a-f]{32}$/.test(fileId)) { throw new ApiError("Invalid file", 400); }
    checkRange(offset, length);
    const result = await this._storage.withDoc(docId, { write: false },
      file => file.readInboxFile(fileId, offset, length));
    if (!result) { throw new ApiError("File not found", 404); }
    return result;
  }

  /** Drops answers that can't be added to the document (e.g. not readable). */
  public async dropInbox(client: Client, docId: string, ids: number[]): Promise<void> {
    await this._authorize(client, docId, "editors");
    if (!Array.isArray(ids) || ids.length > MAX_INBOX_BATCH || !ids.every(id => Number.isInteger(id))) {
      throw new ApiError("Invalid inbox entries", 400);
    }
    await this._storage.withDoc(docId, { write: true }, file => file.removeFromInbox(ids));
  }

  /**
   * Serves published forms of encrypted documents to anyone with their link, and takes their
   * answers (see EncryptedForms.ts): the server only sees ciphertext.
   *   GET /api/docs/:docId/encrypted-forms/:formId -> { spec }
   *   POST /api/docs/:docId/encrypted-forms/:formId { payload, fileIds? } -> stores an answer
   *   POST /api/docs/:docId/encrypted-forms/:formId/files (the encrypted file) -> { fileId }, for
   *     files attached in an answer, sent before it (with their ids in its fileIds)
   */
  public addFormEndpoints(app: express.Application) {
    const getForm = async (docId: string, formId: string) => {
      const doc = await this._dbManager.getRawDocById(docId).catch(() => null);
      if (!doc || !isEncryptedDoc(doc) || doc.removedAt || !/^[0-9a-f]{32}$/.test(formId)) { return null; }
      return this._storage.withDoc(docId, { write: false }, file => file.getForm(formId));
    };
    const notFound = () => new ApiError("Form not found", 404, { code: "FormNotFound" });
    app.get("/api/docs/:docId/encrypted-forms/:formId", expressWrap(async (req, res) => {
      const spec = await getForm(req.params.docId, req.params.formId);
      if (!spec) { throw notFound(); }
      res.set("Cache-Control", "no-store").json({ spec });
    }));
    const jsonBody = express.json({ limit: "2mb" });
    app.post("/api/docs/:docId/encrypted-forms/:formId", jsonBody, expressWrap(async (req, res) => {
      const { docId, formId } = req.params;
      const payload = req.body?.payload;
      const fileIds = req.body?.fileIds ?? [];
      checkPayload(payload);
      if (payload.length > MAX_ANSWER_LENGTH) { throw new ApiError("This answer is too big", 413); }
      if (!Array.isArray(fileIds) || fileIds.length > MAX_ANSWER_FILES ||
        !fileIds.every(id => typeof id === "string" && /^[0-9a-f]{32}$/.test(id))) {
        throw new ApiError("Invalid files", 400);
      }
      if (!this._answersLimiter.allow(`${req.ip} ${docId}`)) {
        throw new ApiError("Too many answers sent: please try again later", 429);
      }
      if (!await getForm(docId, formId)) { throw notFound(); }
      await this._storage.withDoc(docId, { write: true }, async (file) => {
        if (await file.countInbox() >= MAX_INBOX) {
          throw new ApiError("This form can't take more answers for now: please try again later", 429);
        }
        await file.addToInboxWithFiles(formId, payload, fileIds);
      });
      this._broadcast(docId, null, { type: "encryptedDocInbox", data: { docId } });
      res.json({ ok: true });
    }));
    const rawBody = express.raw({ type: () => true, limit: MAX_ANSWER_FILE_BYTES + 1024 });
    app.post("/api/docs/:docId/encrypted-forms/:formId/files", rawBody, expressWrap(async (req, res) => {
      const { docId, formId } = req.params;
      if (!Buffer.isBuffer(req.body) || req.body.length === 0) { throw new ApiError("No file", 400); }
      if (!this._answersLimiter.allow(`${req.ip} ${docId} files`)) {
        throw new ApiError("Too many files sent: please try again later", 429);
      }
      if (!await getForm(docId, formId)) { throw notFound(); }
      const fileId = await this._storage.withDoc(docId, { write: true }, async (file) => {
        if (await file.getInboxFilesSize() + req.body.length > MAX_INBOX_FILES_BYTES) {
          throw new ApiError("This form can't take more files for now: please try again later", 429);
        }
        return file.addInboxFile(formId, req.body);
      });
      res.json({ fileId });
    }));
  }

  /**
   * Stores changes suggested by a member (see EncryptedSuggestion), for documents that accept
   * suggestions (or from members who can edit them). Members who can edit the document are told.
   */
  public async submitSuggestion(client: Client, docId: string, keyId: string, payload: Base64): Promise<number> {
    const auth = await this._authorize(client, docId, "viewers");
    checkPayload(payload);
    const userId = this._requireUserId(client);
    this._assertUnlocked(client, docId);
    const access = auth.getCachedAuth().access;
    const accepts = Boolean((auth.getCachedAuth().cachedDoc as any)?.options?.proposedChanges?.acceptProposals);
    if (access === "viewers" && !accepts) {
      throw new ApiError("This document doesn't accept suggestions", 403);
    }
    const docKey = await this._keys.getCurrentKey(docId, DOC_SCOPE);
    if (docKey?.keyId !== keyId) { throw new ApiError("Suggestions must use the current document key", 409); }
    await this._requireHolder(docId, userId, keyId);
    const id = await this._storage.withDoc(docId, { write: true }, async (file) => {
      await this._checkSize(auth, file, payload.length);
      if (await file.countSuggestions() >= MAX_SUGGESTIONS) {
        throw new ApiError("This document has too many suggestions waiting: please try again later", 429);
      }
      return file.addSuggestion(keyId, payload, userId);
    });
    this._broadcast(docId, null, { type: "encryptedDocSuggestions", data: { docId } });
    return id;
  }

  /** Suggestions waiting: all of them for members who can edit, their own for others. */
  public async listSuggestions(client: Client, docId: string): Promise<EncryptedSuggestion[]> {
    const auth = await this._authorize(client, docId, "viewers");
    const userId = this._requireUserId(client);
    const canEdit = auth.getCachedAuth().access !== "viewers";
    return this._storage.withDoc(docId, { write: false }, file => file.getSuggestions(canEdit ? {} : { userId }));
  }

  /** Removes a suggestion, once applied or dismissed (by a member who can edit, or its author). */
  public async resolveSuggestion(client: Client, docId: string, id: number): Promise<void> {
    const auth = await this._authorize(client, docId, "viewers");
    const userId = this._requireUserId(client);
    if (!Number.isInteger(id)) { throw new ApiError("Invalid suggestion", 400); }
    const canEdit = auth.getCachedAuth().access !== "viewers";
    await this._storage.withDoc(docId, { write: true }, async (file) => {
      const suggestion = await file.getSuggestion(id);
      if (!suggestion) { return; }
      if (!canEdit && suggestion.userId !== userId) {
        throw new ApiError("Only members who can edit the document handle suggestions", 403);
      }
      await file.removeSuggestion(id);
    });
    this._broadcast(docId, null, { type: "encryptedDocSuggestions", data: { docId } });
  }

  /** The snapshots the server keeps of the document (that it can be restored to). */
  public async listSnapshots(client: Client, docId: string): Promise<EncryptedSnapshotInfo[]> {
    await this._authorize(client, docId, "viewers");
    return this._storage.withDoc(docId, { write: false }, file => file.listSnapshots());
  }

  /** A snapshot kept by the server (its payload may need fetching by parts, see fetchSnapshot()). */
  public async getSnapshot(client: Client, docId: string, actionNum: number): Promise<EncryptedSnapshotRecord> {
    await this._authorize(client, docId, "viewers");
    actionNum = checkActionNum(actionNum);
    const snapshot = await this._storage.withDoc(docId, { write: false }, file => file.getSnapshot(actionNum));
    if (!snapshot) { throw new ApiError("Snapshot not found: the document may have changed, please reload it", 404); }
    return snapshot;
  }

  /**
   * Replaces the content of the document (by an owner holding its key, typically with an earlier
   * version of it, re-encrypted with the current keys): records a "restore" entry in the history
   * after baseActionNum (if that's still the latest one), with the new content saved as its
   * snapshot. Browsers reload the document when they get to it.
   */
  public async restoreSnapshot(client: Client, docId: string, baseActionNum: number, keyId: string,
    payload: PayloadSource): Promise<EncryptedPushResult> {
    const auth = await this._authorize(client, docId, "owners");
    checkPayloadSource(payload);
    baseActionNum = checkActionNum(baseActionNum);
    const userId = this._requireUserId(client);
    this._assertUnlocked(client, docId);
    const docKey = await this._keys.getCurrentKey(docId, DOC_SCOPE);
    if (docKey?.keyId !== keyId) {
      throw new ApiError("Snapshots must use the current document key", 409);
    }
    await this._requireHolder(docId, userId, keyId);
    const result = await this._storage.withDoc(docId, { write: true }, file => file.transaction(async () => {
      await this._checkSize(auth, file, typeof payload === "string" ? payload.length : 0);
      const res = await file.appendAction(baseActionNum, { kind: "restore", keyId, payload: "", userId });
      if (!res.accepted) {
        await file.dropUpload(payload);
        return res;
      }
      await file.saveSnapshot(res.action.actionNum, keyId, payload, userId);
      return res;
    }));
    if (!result.accepted) { return result; }
    this._broadcast(docId, client, { type: "encryptedDocAction", data: { docId, action: result.action } });
    return { accepted: true, actionNum: result.action.actionNum, timeMs: result.action.timeMs };
  }

  /**
   * Locks the document for a while (e.g. while an owner restores an earlier version of it): others
   * can't change it meanwhile, and see that it's in progress, until unlockDoc() (or until the
   * owner disconnects).
   */
  public async lockDoc(client: Client, docId: string, reason: DocLockInfo["reason"]): Promise<void> {
    await this._authorize(client, docId, "owners");
    this._requireUserId(client);
    if (reason !== "restoring" && reason !== "decrypting") { throw new ApiError("Invalid reason", 400); }
    this.lock(client, docId, reason);
  }

  /** Whether a document (encrypted or not) is locked, e.g. being converted to or from encryption. */
  public async getLock(client: Client, docId: string): Promise<DocLockInfo | null> {
    const auth = new DocAuthorizerImpl({
      dbManager: this._dbManager, urlId: docId, openMode: "default", authSession: client.authSession,
    });
    await auth.assertAccess("viewers");
    const lock = getDocLock(auth.getCachedAuth().docId || docId);
    return lock ? { reason: lock.reason, userName: lock.userName } : null;
  }

  public async unlockDoc(client: Client, docId: string): Promise<void> {
    await this._authorize(client, docId, "viewers");
    const lock = getDocLock(docId);
    if (lock?.client === client) { this.unlock(docId, lock); }
  }

  /** Locks a document for a client (see docLocks.ts), until unlock() or the client disconnects. */
  public lock(client: Client, docId: string, reason: DocLockInfo["reason"],
    options: { onRelease?: () => Promise<void> } = {}): DocLock {
    const fullUser = client.authSession.fullUser;
    const lock: DocLock = { reason, userName: fullUser?.name || fullUser?.email || "", client };
    lockDoc(docId, lock);
    lock.onRelease = options.onRelease;
    const interrupted = (why: string) => {
      log.warn(`EncryptionRelay: ${reason} of ${docId} interrupted: ${why}`);
      this.unlock(docId, lock);
    };
    const stopListening = client.onDestroy(() => interrupted("its author disconnected"));
    // Its holder keeps it (see renewLock()) as long as they're working on it.
    let timer: ReturnType<typeof setTimeout>;
    lock.renew = () => {
      clearTimeout(timer);
      timer = setTimeout(() => interrupted("its author stopped working on it"), Deps.lockExpiryMs);
    };
    lock.renew();
    lock.stopListening = () => { stopListening(); clearTimeout(timer); };
    this._broadcast(docId, client,
      { type: "encryptedDocLock", data: { docId, lock: { reason, userName: lock.userName } } });
    return lock;
  }

  public unlock(docId: string, lock: DocLock, options: { decrypted?: boolean } = {}) {
    if (getDocLock(docId) !== lock) { return; }
    unlockDoc(docId, lock);
    lock.stopListening?.();
    lock.onRelease?.().catch(e => log.warn(`EncryptionRelay: cleaning up after ${lock.reason} failed`, e));
    this._broadcast(docId, null, {
      type: "encryptedDocLock", data: { docId, lock: null, ...(options.decrypted ? { decrypted: true } : {}) },
    });
  }

  /**
   * Checks that a member may convert the document back to a regular one: an owner holding the
   * current key of every scope (who can read everything).
   */
  public async authorizeConversion(client: Client, docId: string) {
    await this._authorize(client, docId, "owners");
    const userId = this._requireUserId(client);
    const held = new Set((await this._keys.getWraps(docId, { userId })).map(w => w.keyId));
    const keys = await this._keys.getKeys(docId);
    // The document key, and those of columns that are private now.
    const scopes = new Set([DOC_SCOPE,
      ...(await this._keys.getBindings(docId)).filter(b => b.releasedAt === null).map(b => b.scope)]);
    if (!keys.filter(k => k.current && scopes.has(k.scope)).every(k => held.has(k.keyId))) {
      throw new ApiError("Only owners who can read all of a document's content can decrypt it", 403);
    }
  }

  /** The members of a document (whether encrypted or not). */
  public async getMembers(client: Client, docId: string) {
    return this._getMembers(client, docId);
  }

  public checkWraps(wraps: unknown): asserts wraps is DocKeyRecord[] {
    checkWraps(wraps, { withKeyId: true });
  }

  public async getHead(docId: string) {
    return this._getHead(docId);
  }

  /** The bytes of a payload sent by a member, for the document they locked. */
  public async takePayload(client: Client, docId: string, source: PayloadSource): Promise<Buffer> {
    checkPayloadSource(source);
    const lock = getDocLock(docId);
    if (lock?.client !== client) { throw new ApiError("Document is not locked", 409); }
    return this._storage.withDoc(docId, { write: true }, file => file.takePayload(source));
  }

  /** Closes the document's file (e.g. before replacing it). */
  public async closeStorage(docId: string) {
    await this._storage.closeDoc(docId);
  }

  /**
   * For importing a file from Google Drive into an encrypted document: turns the authorization
   * code the user got from Google (see app/client/ui/googleAuth.ts) into an access token, with
   * which their browser downloads the file. The server doesn't download it: it mustn't see the
   * document's content.
   */
  public async getGoogleDriveToken(client: Client, docId: string, code: string): Promise<{ accessToken: string }> {
    await this._authorize(client, docId, "editors");
    this._requireUserId(client);
    if (typeof code !== "string" || !code || code.length > 2048) { throw new ApiError("Invalid code", 400); }
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      throw new ApiError("Google Drive is not configured on this server", 400);
    }
    const { tokens } = await getGoogleAuth().getToken(code);
    if (!tokens.access_token) { throw new ApiError("Google did not grant access", 403); }
    return { accessToken: tokens.access_token };
  }

  /** Keeps a lock held by the client (locks expire otherwise, see Deps.lockExpiryMs). */
  public async renewLock(client: Client, docId: string): Promise<void> {
    const lock = getDocLock(docId);
    if (lock?.client !== client) { throw new ApiError("Document is not locked", 409); }
    lock.renew?.();
  }

  private _assertUnlocked(client: Client, docId: string) {
    const lock = getDocLock(docId);
    if (lock && lock.client !== client) { throw docLockedError(lock); }
    lock?.renew?.();
  }

  private async _requireHolder(docId: string, userId: number, keyId: string) {
    if (!(await this._keys.getWraps(docId, { userId, keyIds: [keyId] })).length) {
      throw new ApiError("Only members holding the document key can change it", 403);
    }
  }

  /**
   * Refuses to store more if the document would take more than its site's plan allows (for its
   * data and attachments together, since the server can't tell them apart), or than configured.
   */
  private async _checkSize(auth: DocAuthorizer, file: EncryptedDocFile, incomingBase64Length: number) {
    const maxSize = getMaxSize(auth.getCachedAuth().cachedDoc);
    if (!maxSize) { return; }
    if (await file.getSize() + incomingBase64Length * 3 / 4 > maxSize) {
      throw new ApiError("This document has reached its maximum size", 413);
    }
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
    const existing = subs.get(client);
    if (existing) {
      existing.auth = auth;
    } else {
      // Forget clients as soon as they're gone (rather than on the next broadcast).
      subs.set(client, { auth, stopListening: client.onDestroy(() => this._unsubscribe(client, docId)) });
    }
  }

  private _unsubscribe(client: Client, docId: string) {
    const subs = this._subscribers.get(docId);
    subs?.get(client)?.stopListening();
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

// What members record of a key change (see KeyChangeRecord): small, and opaque to the server.
function checkRecord(record: unknown): asserts record is Base64 {
  checkPayload(record);
  if (record.length > MAX_KEY_LENGTH) { throw new ApiError("Invalid key change record", 400); }
}

function checkFormId(formId: unknown): asserts formId is string {
  if (typeof formId !== "string" || !/^[0-9a-f]{32}$/.test(formId)) { throw new ApiError("Invalid form", 400); }
}

function checkPayloadSource(source: unknown): asserts source is PayloadSource {
  if (typeof source === "string") { return checkPayload(source); }
  checkUploadId((source as any)?.uploadId);
}

function checkUploadId(uploadId: unknown): asserts uploadId is string {
  if (typeof uploadId !== "string" || !/^[0-9a-f]{32}$/.test(uploadId)) {
    throw new ApiError("Invalid upload", 400);
  }
}

function checkRange(offset: unknown, length: unknown) {
  if (!Number.isInteger(offset) || (offset as number) < 0 || !Number.isInteger(length) || (length as number) <= 0 ||
    (length as number) > MAX_INLINE_BYTES) {
    throw new ApiError("Invalid range", 400);
  }
}

/** The most a document may take, given its site's plan (or the configuration), if limited. */
function getMaxSize(doc: any): number | undefined {
  const billingAccount = doc?.workspace?.org?.billingAccount;
  const features: Features | undefined = billingAccount?.getEffectiveFeatures?.() ?? billingAccount?.product?.features;
  const dataSize = features?.baseMaxDataSizePerDocument;
  const attachmentsSize = features?.baseMaxAttachmentsBytesPerDocument;
  if (dataSize !== undefined && attachmentsSize !== undefined) { return dataSize + attachmentsSize; }
  return getMaxEncryptedDocSize();
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
