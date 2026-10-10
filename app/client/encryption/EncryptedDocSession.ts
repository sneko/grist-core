/**
 * Opens an encrypted document in this browser, and serves the document methods the rest of the
 * client uses (fetchTable, applyUserActions, ...) from the local data engine.
 *
 * Opening an encrypted document goes as follows:
 *  1. Ask the server (the relay) for the document's latest snapshot, its changes since, its keys
 *     and the current user's copies of them.
 *  2. Make sure the user can decrypt: they need keys in the encryption service (otherwise they're
 *     offered to set them up), and a copy of the document key (otherwise they wait for an owner
 *     holding one to give them one). The owner opening a new document creates its key.
 *  3. Start the data engine in a Web Worker, and load the document into it (LocalActiveDoc).
 *  4. Follow changes from other browsers, as the server forwards them.
 *
 * It also offers what the rest of the client needs to manage keys (giving them to members,
 * private columns) and encrypted attachments.
 */
import { Comm } from "app/client/components/Comm";
import { reportKeyGrant } from "app/client/encryption/EncryptionUI";
import { getKeyVault } from "app/client/encryption/keyVaults";
import { IDocEncryption, KeyGrantResult } from "app/client/encryption/types";
import { WorkerEngine } from "app/client/encryption/WorkerEngine";
import { makeT } from "app/client/lib/localization";
import { checkBrowserUploadSizeLimit } from "app/client/lib/uploads";
import { reportError, reportMessage } from "app/client/models/errors";
import { bigBasicButton, bigPrimaryButton } from "app/client/ui2018/buttons";
import { cssModalBody, cssModalButtons, cssModalTitle, modal } from "app/client/ui2018/modals";
import { ActiveDocAPI } from "app/common/ActiveDocAPI";
import { CommEncryptedDocAction, CommEncryptedDocKeys } from "app/common/CommTypes";
import { CellValue } from "app/common/DocActions";
import { OpenLocalDocResult } from "app/common/DocListAPI";
import { decryptFile, encryptFile, makeFileIdent, parseFileIdent } from "app/common/encryption/EncryptedAttachments";
import { base64ToBytes, bytesToBase64, IKeyVault, KeyRecipient } from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, DocKeyRecord, ENCRYPTED_PART_BYTES, EncryptedActionRecord, EncryptedDocOpenResult,
  EncryptedPushResult, EncryptedSnapshotRecord, EncryptionKeysResult, EncryptionMember, makeColumnScope, makeKeyId,
  NewKeyRequest,
} from "app/common/encryption/EncryptionTypes";
import { Keyring } from "app/common/encryption/Keyring";
import {
  IEncryptionRelay, InvalidChange, LocalActiveDoc, LocalDocUserAction, NeedsReloadError,
} from "app/common/encryption/LocalActiveDoc";
import { addParsedTables, parseFileLocally } from "app/common/encryption/LocalImport";
import { EncryptionClientConfig } from "app/common/gristUrls";
import { User } from "app/common/User";

import { Semaphore } from "async-mutex";
import { Disposable, dom, Emitter } from "grainjs";

const t = makeT("EncryptedDocSession");

// Keep formulas depending on the current time up to date, as the server does for regular docs.
const UPDATE_CURRENT_TIME_MS = 60 * 60 * 1000;

// Decrypted attachments kept around (as blob URLs), and how many get fetched at once.
const MAX_CACHED_ATTACHMENTS = 50;
const MAX_PARALLEL_ATTACHMENT_FETCHES = 4;

// docFDs for encrypted documents are made up locally; negative ones never collide with the
// server's.
let _nextDocFD = -1;

/** The server side of an encrypted document, over the client's websocket connection. */
export class CommRelay implements IEncryptionRelay {
  constructor(private _comm: Comm, private _docId: string) {}

  public open(): Promise<EncryptedDocOpenResult> { return this._call("openEncryptedDoc"); }
  public close(): Promise<void> { return this._call("closeEncryptedDoc"); }
  public fetchActions(afterActionNum: number): Promise<EncryptedActionRecord[]> {
    return this._call("fetchEncryptedActions", afterActionNum);
  }

  public pushAction(baseActionNum: number, keyId: string, payload: Base64): Promise<EncryptedPushResult> {
    return this._call("pushEncryptedAction", baseActionNum, keyId, payload);
  }

  public async saveSnapshot(actionNum: number, keyId: string, payload: Uint8Array, options?: { compact?: boolean }) {
    await this._call("saveEncryptedSnapshot", actionNum, keyId, await this._send(payload), options || {});
  }

  public fetchSnapshot(snapshot: EncryptedSnapshotRecord): Promise<Uint8Array> {
    return this._receive(snapshot.size, (offset, length) =>
      this._call("fetchEncryptedSnapshot", snapshot.actionNum, offset, length));
  }

  public getKeys(): Promise<EncryptionKeysResult> { return this._call("getEncryptionKeys"); }
  public listMembers(): Promise<EncryptionMember[]> { return this._call("listEncryptionMembers"); }
  public createKey(request: NewKeyRequest): Promise<EncryptedPushResult> {
    return this._call("createEncryptionKey", request);
  }

  public releaseScope(scope: string, baseActionNum: number): Promise<EncryptedPushResult> {
    return this._call("releaseEncryptionScope", scope, baseActionNum);
  }

  public shareKeys(wraps: DocKeyRecord[]): Promise<void> { return this._call("shareEncryptionKeys", wraps); }
  public revokeKeys(userIds: number[], scope?: string): Promise<void> {
    return this._call("revokeEncryptionKeys", userIds, scope);
  }

  public requestRotation(scope: string): Promise<void> { return this._call("requestKeyRotation", scope); }

  public async uploadFile(ciphertext: Uint8Array): Promise<{ fileId: string }> {
    return this._call("uploadEncryptedFile", await this._send(ciphertext));
  }

  public async fetchFile(fileId: string): Promise<Uint8Array> {
    const first: { payload: Base64, size: number } =
      await this._call("fetchEncryptedFile", fileId, 0, ENCRYPTED_PART_BYTES);
    if (first.size <= ENCRYPTED_PART_BYTES) { return base64ToBytes(first.payload); }
    return this._receive(first.size, async (offset, length) => offset === 0 ? first.payload :
      (await this._call("fetchEncryptedFile", fileId, offset, length)).payload);
  }

  // A payload as the server takes it: inline if small enough, or uploaded by parts first.
  private async _send(payload: Uint8Array): Promise<Base64 | { uploadId: string }> {
    if (payload.length <= ENCRYPTED_PART_BYTES) { return bytesToBase64(payload); }
    const uploadId: string = await this._call("beginEncryptedUpload");
    for (let seq = 0, offset = 0; offset < payload.length; seq++, offset += ENCRYPTED_PART_BYTES) {
      await this._call("appendEncryptedUpload", uploadId, seq,
        bytesToBase64(payload.subarray(offset, offset + ENCRYPTED_PART_BYTES)));
    }
    return { uploadId };
  }

  // Gets a payload of the given size by parts.
  private async _receive(size: number, fetchPart: (offset: number, length: number) => Promise<Base64>) {
    const result = new Uint8Array(size);
    for (let offset = 0; offset < size; offset += ENCRYPTED_PART_BYTES) {
      const part = base64ToBytes(await fetchPart(offset, Math.min(ENCRYPTED_PART_BYTES, size - offset)));
      if (offset + part.length > size) { throw new Error("Invalid content received from the server"); }
      result.set(part, offset);
    }
    return result;
  }

  private _call(method: string, ...args: any[]): Promise<any> {
    return this._comm._makeRequest(null, this._docId, method, this._docId, ...args);
  }
}

export class EncryptedDocSession extends Disposable implements IDocEncryption {
  /**
   * Opens the document, interacting with the user if needed (to set up keys, or to wait for
   * access). Returns the session, and what the rest of the client expects from opening a doc.
   */
  public static async open(comm: Comm, docId: string, config: EncryptionClientConfig,
    options: { isCancelled?: () => boolean } = {},
  ): Promise<{ session: EncryptedDocSession, openResponse: OpenLocalDocResult }> {
    const relay = new CommRelay(comm, docId);
    const cancellation = new Cancellation(options.isCancelled);
    let engine: WorkerEngine | undefined;
    let session: EncryptedDocSession | undefined;
    try {
      let openResult = await relay.open();
      cancellation.check();
      const vault = await getKeyVault(config, openResult.user.vaultUserId);
      while (!await vault.hasKeys()) {
        await promptKeySetup(vault, cancellation);
      }
      const vaultIdFor = (m: { userId: number, vaultUserId: string | null }) =>
        m.vaultUserId || (config.mockVault ? mockVaultUserId(m.userId) : null);

      const keyring = new Keyring(vault, () => relay.getKeys(), openResult);
      while (!keyring.canUseScope(DOC_SCOPE)) {
        cancellation.check();
        if (openResult.keys.length === 0 && openResult.access === "owners" && openResult.user.id) {
          await createDocumentKey(vault, relay, openResult, vaultIdFor).catch((e) => {
            // Another owner may have set it up at the same time: then wait for them to give
            // us its key, as for any member.
            if (!String(e?.message).includes("already initialized")) { throw e; }
          });
        } else {
          await waitForKey(comm, docId, relay, openResult, cancellation);
        }
        openResult = await relay.open();
        keyring.update(openResult);
      }

      engine = await WorkerEngine.create();
      cancellation.check();
      session = new EncryptedDocSession(comm, docId, relay, keyring, engine, openResult, vaultIdFor);
      await session._open(openResult);
      cancellation.check();
      return { session, openResponse: await session._makeOpenResponse(openResult) };
    } catch (e) {
      // Don't leave the data engine running, nor the server sending us changes.
      if (session) { session.dispose(); } else { engine?.terminate(); }
      relay.close().catch(() => {});
      throw e;
    } finally {
      cancellation.dispose();
    }
  }

  public readonly docFD = _nextDocFD--;
  // Emitted when keys or members change, or which columns are private.
  public readonly keysChanged = this.autoDispose(new Emitter());

  private _localDoc: LocalActiveDoc;
  // Changes from others are held back until the document is shown (see resume()).
  private _paused = true;
  private _heldActions: EncryptedActionRecord[] = [];
  private _timer?: ReturnType<typeof setInterval>;
  // Most recently used last.
  private _attachmentUrls = new Map<number, Promise<string>>();
  private _attachmentFetches = new Semaphore(MAX_PARALLEL_ATTACHMENT_FETCHES);
  private _lastPrivacy = "";

  private constructor(
    private _comm: Comm,
    private _docId: string,
    private _relay: CommRelay,
    private _keyring: Keyring,
    private _engine: WorkerEngine,
    private _openResult: EncryptedDocOpenResult,
    private _vaultIdFor: (m: { userId: number, vaultUserId: string | null }) => string | null,
  ) {
    super();
    this.onDispose(() => {
      if (this._timer) { clearInterval(this._timer); }
      this._localDoc?.close();
      this._engine.terminate();
      this._comm.stopListening(this._comm, "encryptedDocAction", this._onDocAction);
      this._comm.stopListening(this._comm, "encryptedDocKeys", this._onDocKeys);
      this._comm.stopListening(this._comm, "clientConnect", this._onConnect);
      for (const url of this._attachmentUrls.values()) { url.then(u => URL.revokeObjectURL(u)).catch(() => {}); }
    });
  }

  public get canEdit() { return this._localDoc.canEdit; }
  public get isOwner() { return this._openResult.access === "owners"; }
  public get userId() { return this._openResult.user.id; }
  public get keyring() { return this._keyring; }
  public get privacy() { return this._localDoc.privacy; }

  public columnScopes(tableId: string, colId: string): string[] {
    return this.privacy.scopesOf(tableId, colId);
  }

  public columnOwnScope(colRef: number): string | null {
    const column = this._localDoc.docData.getMetaTable("_grist_Tables_column").getRecord(colRef);
    return this._keyring.currentScopeOf(colRef) ??
      (column?.summarySourceCol ? this._keyring.currentScopeOf(column.summarySourceCol) : null);
  }

  public canReadScope(scope: string): boolean {
    return this._keyring.canUseScope(scope);
  }

  /** Starts delivering changes from others, once the client is ready to receive them. */
  public resume() {
    if (!this._paused) { return; }
    this._paused = false;
    for (const record of this._heldActions.splice(0)) {
      this._track(this._localDoc.receiveAction(record));
    }
    // Catch up on anything that happened while we were loading.
    this._track(this._localDoc.sync());
    if (this.canEdit) {
      // Each member's browser checks, at a time of its own, whether it's time to do it (see
      // LocalActiveDoc.updateCurrentTime(): only one does it each hour).
      this._timer = setInterval(() => this._track(this._localDoc.updateCurrentTime()),
        UPDATE_CURRENT_TIME_MS / 6 + Math.random() * 60 * 1000);
    }
    this._offerPendingKeys().catch(e => console.warn("Encryption: could not check members' keys", e));
  }

  /** Serves the ActiveDocAPI method `name` for this document. */
  public async callMethod(name: keyof ActiveDocAPI, ...args: any[]): Promise<any> {
    const doc = this._localDoc;
    switch (name) {
      case "fetchTable": return doc.fetchTable(args[0]);
      case "useQuerySet": return doc.useQuerySet(args[0]);
      case "disposeQuerySet": return;
      case "applyUserActions": return doc.applyUserActions(args[0], args[1]);
      case "applyUserActionsById": return doc.applyUserActionsById(args[0], args[1], args[2], args[3]);
      case "findColFromValues": return doc.findColFromValues(args[0], args[1], args[2]);
      case "getFormulaError": return doc.getFormulaError(args[0], args[1], args[2]);
      case "autocomplete": return doc.autocomplete(args[0], args[1], args[2], args[3]);
      case "fetchPythonCode": return doc.fetchPythonCode();
      case "getActionSummaries": return { actions: doc.getActionSummaries(), censored: false };
      case "startBundleUserActions": return doc.startBundleUserActions();
      case "stopBundleUserActions": return doc.stopBundleUserActions();
      case "waitForInitialization": return;
      case "listActiveUserProfiles": return [];
      case "closeDoc": {
        this._localDoc.close();
        await this._relay.close().catch(() => {});
        return;
      }
      case "reloadDoc": {
        window.location.reload();
        return;
      }
      default:
        throw new Error(t("This is not available for end-to-end encrypted documents"));
    }
  }

  /** Members of the document, with the keys they hold. */
  public listMembers(): Promise<EncryptionMember[]> {
    return this._relay.listMembers();
  }

  /** Members with access to the document who don't yet hold its key. */
  public async getPendingMembers(): Promise<EncryptionMember[]> {
    const docKeyId = this._keyring.currentKeyId(DOC_SCOPE);
    return (await this.listMembers()).filter(m => !m.keyIds.includes(docKeyId));
  }

  /**
   * Gives the keys of a scope (all of them, so that older content stays readable) to members
   * who set up their own encryption keys. Only owners can. Returns who got them, and who couldn't.
   */
  public async shareScope(scope: string, members: EncryptionMember[]): Promise<KeyGrantResult> {
    const { ready, notReady } = await this._splitByReadiness(members);
    const recipients = ready.map(m => ({ vaultUserId: this._vaultIdFor(m)!, email: m.email, name: m.name, member: m }));
    if (recipients.length === 0) { return { granted: [], notReady }; }
    const wraps: DocKeyRecord[] = [];
    const granted = new Set<EncryptionMember>();
    for (const key of this._keyring.getKeys().filter(k => k.scope === scope && this._keyring.holds(k.keyId))) {
      const keyWraps = await this._keyring.vault.shareDocumentKey(await this._keyring.getWrap(key.keyId), recipients);
      for (const r of recipients) {
        const wrap = keyWraps.get(r.vaultUserId);
        if (!wrap) { continue; }
        wraps.push({ keyId: key.keyId, userId: r.member.userId, wrappedKey: bytesToBase64(wrap.wrappedKey),
          keyVersion: wrap.keyVersion });
        granted.add(r.member);
      }
    }
    if (wraps.length > 0) {
      await this._relay.shareKeys(wraps);
      await this._localDoc.refreshKeys();
      this.keysChanged.emit();
    }
    return { granted: [...granted], notReady: [...notReady, ...ready.filter(m => !granted.has(m))] };
  }

  /** Gives the document's keys to members who have access to it but can't read it yet. */
  public async grantPendingKeys(): Promise<KeyGrantResult> {
    return this.shareScope(DOC_SCOPE, await this.getPendingMembers());
  }

  /**
   * Makes a column private: only the given members (and the current user) will be able to read
   * it, and formulas using it. Its current values are re-encrypted, and the server drops what it
   * had of them in readable form (older changes and snapshots).
   */
  public async makeColumnPrivate(colRef: number, userIds: number[]): Promise<KeyGrantResult> {
    const members = await this.listMembers();
    const chosen = members.filter(m => m.userId === this.userId || userIds.includes(m.userId));
    const { ready, notReady } = await this._splitByReadiness(chosen);
    if (!ready.some(m => m.userId === this.userId)) {
      throw new Error(t("Your account is not known to the encryption service"));
    }
    const recipients: (KeyRecipient & { userId: number })[] = ready.map(m =>
      ({ userId: m.userId, vaultUserId: this._vaultIdFor(m)!, email: m.email, name: m.name }));
    await this._localDoc.createScopeKey(makeColumnScope(), recipients, colRef);
    // Values shared so far were readable by all members: keep only the private version.
    await this._localDoc.saveSnapshot({ compact: true });
    this.keysChanged.emit();
    return { granted: ready.filter(m => m.userId !== this.userId), notReady };
  }

  /** Makes a private column readable by all members again. */
  public async makeColumnPublic(colRef: number): Promise<void> {
    const scope = this._keyring.currentScopeOf(colRef);
    if (!scope) { return; }
    await this._localDoc.releaseScope(scope);
    this.keysChanged.emit();
  }

  /**
   * Changes who can read the private columns of a scope: newcomers get its keys, and those
   * removed lose them (the scope's key then gets replaced on the next edit).
   */
  public async setScopeAudience(scope: string, userIds: number[]): Promise<KeyGrantResult> {
    const members = await this.listMembers();
    const holders = members.filter(m => m.keyIds.some(keyId => this._keyring.getKey(keyId)?.scope === scope));
    const toAdd = members.filter(m => userIds.includes(m.userId) && !holders.includes(m));
    const toRemove = holders.filter(m => !userIds.includes(m.userId) && m.userId !== this.userId);
    const result: KeyGrantResult = toAdd.length > 0 ? await this.shareScope(scope, toAdd) :
      { granted: [], notReady: [] };
    if (toRemove.length > 0) {
      await this._relay.revokeKeys(toRemove.map(m => m.userId), scope);
      await this._localDoc.refreshKeys();
      await this._localDoc.rotateKeys();
    }
    this.keysChanged.emit();
    return result;
  }

  /** Who holds the keys of a scope. */
  public async getScopeAudience(scope: string): Promise<EncryptionMember[]> {
    const current = this._keyring.currentKey(scope);
    return (await this.listMembers()).filter(m => current && m.keyIds.includes(current.keyId));
  }

  /** Asks for the document's keys to be replaced (on the next edit). */
  public async requestKeyRotation(scope: string = DOC_SCOPE): Promise<void> {
    await this._relay.requestRotation(scope);
    await this._localDoc.refreshKeys();
    await this._localDoc.rotateKeys();
  }

  /**
   * Encrypts and stores files, and adds them as attachments to the document. Each file gets a key
   * of its own, wrapped with the key of the column it's attached in (if it's private) or of the
   * document. Returns the ids of the new attachment records.
   */
  public async uploadAttachments(files: File[], target?: { tableId: string, colId: string }): Promise<number[]> {
    checkBrowserUploadSizeLimit(files, "attachment");
    const scopes = target ? this.privacy.scopesOf(target.tableId, target.colId) : [];
    const scope = scopes[0] || DOC_SCOPE;
    const records: Record<string, any>[] = [];
    for (const file of files) {
      const data = new Uint8Array(await file.arrayBuffer());
      const { ciphertext, ref } = await encryptFile(this._keyring, scope, data);
      const { fileId } = await this._relay.uploadFile(ciphertext);
      const size = await getImageSize(file);
      records.push({
        fileName: file.name,
        fileSize: file.size,
        fileIdent: makeFileIdent({ fileId, ...ref }),
        timeUploaded: Date.now() / 1000,
        imageWidth: size?.width || 0,
        imageHeight: size?.height || 0,
      });
    }
    const result = await this._localDoc.applyUserActions([
      ["BulkAddRecord", "_grist_Attachments", records.map(() => null), {
        fileName: records.map(r => r.fileName),
        fileSize: records.map(r => r.fileSize),
        fileIdent: records.map(r => r.fileIdent),
        timeUploaded: records.map(r => r.timeUploaded),
        imageWidth: records.map(r => r.imageWidth),
        imageHeight: records.map(r => r.imageHeight),
      }],
    ]);
    return result.retValues[0];
  }

  /** Imports files as new tables, parsing them in the browser (the server mustn't see them). */
  public async importFiles(files: File[]): Promise<string[]> {
    const tableIds: string[] = [];
    for (const file of files) {
      const parsed = await parseFileLocally(this._engine, file.name, new Uint8Array(await file.arrayBuffer()));
      tableIds.push(...await addParsedTables(parsed, file.name, this._localDoc.docData,
        (actions, options) => this._localDoc.applyUserActions(actions, options)));
    }
    return tableIds;
  }

  /** Builds an Excel workbook in the browser (with the data engine's own library). */
  public async exportXlsx(sheets: [string, string[], CellValue[][]][]): Promise<Uint8Array> {
    return base64ToBytes(await this._engine.call("export_xlsx", sheets));
  }

  /** Returns a (local, blob) URL to the decrypted content of an attachment. */
  public getAttachmentUrl(attId: number): Promise<string> {
    let url = this._attachmentUrls.get(attId);
    if (url) {
      this._attachmentUrls.delete(attId);
    } else {
      url = this._attachmentFetches.runExclusive(() => this._fetchAttachment(attId)).then(({ data, fileName }) =>
        URL.createObjectURL(new Blob([data as BlobPart], { type: guessMimeType(fileName) })));
      url.catch(() => this._attachmentUrls.delete(attId));
    }
    this._attachmentUrls.set(attId, url);
    // Release the least recently used ones (what's shown already stays shown).
    for (const [oldId, oldUrl] of this._attachmentUrls) {
      if (this._attachmentUrls.size <= MAX_CACHED_ATTACHMENTS) { break; }
      this._attachmentUrls.delete(oldId);
      oldUrl.then(u => setTimeout(() => URL.revokeObjectURL(u), 10000)).catch(() => {});
    }
    return url;
  }

  /** Downloads an attachment, decrypted, as a file. */
  public async downloadAttachment(attId: number): Promise<void> {
    const url = await this.getAttachmentUrl(attId);
    const record = this._localDoc.docData.getMetaTable("_grist_Attachments").getRecord(attId);
    const link = document.createElement("a");
    link.href = url;
    link.download = record?.fileName || "attachment";
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  // Members who set up their keys with the encryption service (who can be given keys), and others.
  private async _splitByReadiness(members: EncryptionMember[]) {
    const known = members.filter(m => this._vaultIdFor(m));
    const registered = known.length === 0 ? new Set<string>() :
      await this._keyring.vault.getRegisteredUsers(known.map(m => this._vaultIdFor(m)!));
    const ready = known.filter(m => registered.has(this._vaultIdFor(m)!));
    return { ready, notReady: members.filter(m => !ready.includes(m)) };
  }

  private async _fetchAttachment(attId: number) {
    const record = this._localDoc.docData.getMetaTable("_grist_Attachments").getRecord(attId);
    const ref = record && parseFileIdent(record.fileIdent);
    if (!ref) { throw new Error(t("Attachment not found")); }
    const ciphertext = await this._relay.fetchFile(ref.fileId);
    return { data: await decryptFile(this._keyring, ref, ciphertext), fileName: record.fileName };
  }

  private async _open(openResult: EncryptedDocOpenResult) {
    const user = openResult.user;
    this._localDoc = await LocalActiveDoc.open({
      engine: this._engine,
      relay: this._relay,
      keyring: this._keyring,
      engineUser: makeUser(openResult).toJSON(),
      userName: user.email || "",
      canEdit: openResult.access === "owners" || openResult.access === "editors",
      onDocUserAction: action => this._emitDocUserAction(action),
      vaultIdFor: this._vaultIdFor,
      newDocSettings: (openResult.access === "owners") ? {
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
        locale: navigator.language || "en-US",
      } : undefined,
      onInvalidChange: change => this._onInvalidChange(change),
      log: (...args) => console.log("[encryption]", ...args),
    }, openResult);
    this._comm.listenTo(this._comm, "encryptedDocAction", this._onDocAction);
    this._comm.listenTo(this._comm, "encryptedDocKeys", this._onDocKeys);
    this._comm.listenTo(this._comm, "clientConnect", this._onConnect);
  }

  private async _makeOpenResponse(openResult: EncryptedDocOpenResult): Promise<OpenLocalDocResult> {
    return {
      docFD: this.docFD,
      clientId: "encrypted",
      doc: await this._localDoc.fetchMetaTables(),
      log: this._localDoc.getRecentMinimalActions(),
      isTimingOn: false,
      user: makeUser(openResult).toUserInfo(),
    };
  }

  private _onDocAction = (message: CommEncryptedDocAction) => {
    if (message.data.docId !== this._docId || this.isDisposed()) { return; }
    if (this._paused) {
      this._heldActions.push(message.data.action);
    } else {
      this._track(this._localDoc.receiveAction(message.data.action));
    }
  };

  private _onDocKeys = (message: CommEncryptedDocKeys) => {
    if (message.data.docId !== this._docId || this.isDisposed()) { return; }
    this._track(this._localDoc.refreshKeys().then(() => this.keysChanged.emit()));
  };

  // After a reconnect, we may have missed changes (and the server may have forgotten we have the
  // document open): fetching changes resubscribes us.
  private _onConnect = () => {
    if (this.isDisposed() || this._paused) { return; }
    this._track(this._localDoc.sync());
  };

  // Background work on the document counts as pending requests (see Comm.trackLocalWork).
  private _track(work: Promise<void>) {
    this._comm.trackLocalWork(work).catch((e) => {
      // Work in progress fails when the document gets closed: that's expected.
      if (this.isDisposed()) { return; }
      if (e instanceof NeedsReloadError) {
        offerReload(e.message);
      } else {
        reportError(e);
      }
    });
  }

  // Changes from others that every browser skips or partly locks (see LocalActiveDoc): let the
  // user know.
  private _onInvalidChange(change: InvalidChange) {
    console.warn("[encryption] Invalid change", change);
    reportMessage(change.skipped ?
      t("A change by another member couldn't be applied, and was ignored.") :
      t("A change by another member contained invalid private values, which are shown as locked."),
    { level: "warning" });
  }

  private _emitDocUserAction(action: LocalDocUserAction) {
    this._comm.trigger("docUserAction", {
      type: "docUserAction",
      docFD: this.docFD,
      fromSelf: action.fromSelf,
      data: {
        docActions: action.docActions,
        actionGroup: action.actionGroup,
        docUsage: null,
      },
    });
    // Settings showing private columns need updating if which columns are private changed.
    const privacy = JSON.stringify(this.privacy.scopeEntries());
    if (privacy !== this._lastPrivacy) {
      this._lastPrivacy = privacy;
      this.keysChanged.emit();
    }
  }

  // Like Docs, give keys to members who are waiting for them when an owner opens the document.
  private async _offerPendingKeys() {
    if (!this.isOwner) { return; }
    const pending = (await this.getPendingMembers()).filter(m => this._vaultIdFor(m));
    if (pending.length === 0 || this.isDisposed()) { return; }
    reportMessage(() => dom("div",
      t("{{count}} member(s) can't read this encrypted document yet.", { count: pending.length }),
    ), {
      key: "encryption-pending-keys",
      level: "info",
      actions: [{
        label: t("Give access"),
        action: () => {
          this.grantPendingKeys().then(reportKeyGrant).catch(reportError);
        },
      }],
    });
  }
}

function makeUser(openResult: EncryptedDocOpenResult): User {
  const user = openResult.user;
  return new User({
    Name: user.name,
    Email: user.email,
    Access: openResult.access,
    UserID: user.id,
    UserRef: user.ref,
    SessionID: user.id ? `u${user.id}` : null,
    IsLoggedIn: Boolean(user.id),
    LinkKey: {},
  });
}

function mockVaultUserId(userId: number) {
  return `grist-user-${userId}`;
}

/** Creates the key of a new document, for its owner. */
async function createDocumentKey(vault: IKeyVault, relay: CommRelay, openResult: EncryptedDocOpenResult,
  vaultIdFor: (m: { userId: number, vaultUserId: string | null }) => string | null) {
  const user = openResult.user;
  const vaultUserId = user.id ? vaultIdFor({ userId: user.id, vaultUserId: user.vaultUserId }) : null;
  if (!user.id || !vaultUserId) { throw new Error(t("Your account is not known to the encryption service")); }
  const wraps = await vault.createDocumentKey([{ vaultUserId, email: user.email || "", name: user.name || "" }]);
  const myKey = wraps.get(vaultUserId);
  if (!myKey) { throw new Error(t("The encryption service did not create a key for you")); }
  await relay.createKey({
    scope: DOC_SCOPE,
    keyId: makeKeyId(DOC_SCOPE),
    baseActionNum: 0,
    wraps: [{ userId: user.id, wrappedKey: bytesToBase64(myKey.wrappedKey), keyVersion: myKey.keyVersion }],
  });
}

/**
 * Lets dialogs shown while opening a document close when opening gets cancelled (e.g. the user
 * navigated away).
 */
class Cancellation {
  public readonly whenCancelled: Promise<never>;
  private _timer?: ReturnType<typeof setInterval>;

  constructor(private _isCancelled?: () => boolean) {
    this.whenCancelled = new Promise<never>((_resolve, reject) => {
      if (!_isCancelled) { return; }
      this._timer = setInterval(() => {
        if (_isCancelled()) { this.dispose(); reject(new Error("Opening cancelled")); }
      }, 300);
    });
    this.whenCancelled.catch(() => {});
  }

  public check() {
    if (this._isCancelled?.()) { throw new Error("Opening cancelled"); }
  }

  public dispose() {
    if (this._timer) { clearInterval(this._timer); }
  }
}

/** Shows a dialog until the user has set up their encryption keys (or gives up). */
function promptKeySetup(vault: IKeyVault, cancellation: Cancellation): Promise<void> {
  return new Promise((resolve, reject) => {
    modal((ctl, owner) => {
      cancellation.whenCancelled.catch((e: Error) => {
        if (!owner.isDisposed()) { ctl.close(); }
        reject(e);
      });
      return [
        cssModalTitle(t("Enable encryption")),
        cssModalBody(t("This document is encrypted. You must enable encryption on your account to access it.")),
        cssModalButtons(
          vault.openOnboarding ? bigPrimaryButton(t("Enable encryption"),
            dom.on("click", () => vault.openOnboarding!())) : null,
          bigBasicButton(t("Continue"), dom.on("click", () => { ctl.close(); resolve(); })),
          bigBasicButton(t("Cancel"), dom.on("click", () => {
            ctl.close();
            reject(new Error(t("Encryption keys are required to open this document")));
          })),
        ),
      ];
    }, { noClickAway: true, noEscapeKey: true });
  });
}

/**
 * Shows a dialog explaining that the user has access to the document but no key to read it,
 * until an owner holding the key gives them one (or something else changed, e.g. reconnecting,
 * after which the document gets opened again to check).
 */
function waitForKey(comm: Comm, docId: string, relay: CommRelay, openResult: EncryptedDocOpenResult,
  cancellation: Cancellation): Promise<void> {
  return new Promise((resolve, reject) => {
    modal((ctl, owner) => {
      const done = () => { if (!owner.isDisposed()) { ctl.close(); } resolve(); };
      const onKeys = (message: CommEncryptedDocKeys) => { if (message.data.docId === docId) { done(); } };
      comm.listenTo(comm, "encryptedDocKeys", onKeys);
      comm.listenTo(comm, "clientConnect", done);
      owner.onDispose(() => {
        comm.stopListening(comm, "encryptedDocKeys", onKeys);
        comm.stopListening(comm, "clientConnect", done);
      });
      cancellation.whenCancelled.catch((e: Error) => {
        if (!owner.isDisposed()) { ctl.close(); }
        reject(e);
      });
      // The key may have been given since the document was opened, before we listened.
      relay.getKeys().then((keys) => {
        const current = keys.keys.find(k => k.scope === DOC_SCOPE && k.current);
        if (current && keys.myKeys.some(k => k.keyId === current.keyId)) { done(); }
      }).catch(() => {});
      return [
        cssModalTitle(t("Waiting for access")),
        cssModalBody(openResult.keys.length > 0 ?
          t("This document is encrypted. You have access to it, but not yet to its key: " +
            "it will open as soon as an owner opens it and gives you access.") :
          t("This document is encrypted, and its owner hasn't set it up yet. It will open as soon as they do.")),
        cssModalButtons(
          bigBasicButton(t("Cancel"), dom.on("click", () => {
            ctl.close();
            reject(new Error(t("No access to the key of this encrypted document")));
          })),
        ),
      ];
    }, { noClickAway: true, noEscapeKey: true });
  });
}

function offerReload(message: string) {
  modal(() => [
    cssModalTitle(t("Reload needed")),
    cssModalBody(message),
    cssModalButtons(bigPrimaryButton(t("Reload"), dom.on("click", () => window.location.reload()))),
  ], { noClickAway: true, noEscapeKey: true });
}

async function getImageSize(file: File): Promise<{ width: number, height: number } | null> {
  if (!file.type.startsWith("image/") || typeof createImageBitmap === "undefined") { return null; }
  try {
    const bitmap = await createImageBitmap(file);
    const size = { width: bitmap.width, height: bitmap.height };
    bitmap.close();
    return size;
  } catch (e) {
    return null;
  }
}

function guessMimeType(fileName: string): string {
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  const types: Record<string, string> = {
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp",
    // Not SVG: opened from a blob URL, it would run scripts with the page's origin.
    pdf: "application/pdf", txt: "text/plain", csv: "text/csv",
  };
  return types[ext] || "application/octet-stream";
}
