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
import {
  copyDocument, decryptDocument, makeFormAnswerHelpers, makeVaultIdFor, ProgressCallback,
} from "app/client/encryption/DocConversion";
import { downloadFromDrive, driveFileIdFromUrl } from "app/client/encryption/driveImport";
import { getKeyVault } from "app/client/encryption/keyVaults";
import { getLocalAssistance } from "app/client/encryption/localAssistant";
import { isLockedHere, lockingHere, showLockOverlay } from "app/client/encryption/lockOverlay";
import { IDocEncryption, KeyGrantResult } from "app/client/encryption/types";
import { WorkerEngine } from "app/client/encryption/WorkerEngine";
import { makeT } from "app/client/lib/localization";
import { checkBrowserUploadSizeLimit } from "app/client/lib/uploads";
import { reportError, reportMessage } from "app/client/models/errors";
import { urlState } from "app/client/models/gristUrlState";
import { bigBasicButton, bigPrimaryButton } from "app/client/ui2018/buttons";
import { cssModalBody, cssModalButtons, cssModalTitle, modal } from "app/client/ui2018/modals";
import { ActiveDocAPI } from "app/common/ActiveDocAPI";
import {
  CommEncryptedDocAction, CommEncryptedDocInbox, CommEncryptedDocKeys, CommEncryptedDocLock,
  CommEncryptedDocSuggestions,
} from "app/common/CommTypes";
import { CellValue } from "app/common/DocActions";
import { OpenLocalDocResult } from "app/common/DocListAPI";
import { EncryptionAccessError } from "app/common/encryption/ColumnPrivacy";
import { decryptFile, encryptFile, makeFileIdent, parseFileIdent } from "app/common/encryption/EncryptedAttachments";
import {
  EncryptedFormKeys, encryptFormSpec, generateFormKeys, makeEncryptedFormShareKey,
} from "app/common/encryption/EncryptedForms";
import {
  base64ToBytes, bytesToBase64, IKeyVault, KeyRecipient, utf8Encode,
} from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, DocKeyRecord, DocLockInfo, ENCRYPTED_PART_BYTES, EncryptedActionRecord, EncryptedDocOpenResult,
  EncryptedInboxEntry, EncryptedPushResult, EncryptedSnapshotInfo, EncryptedSnapshotRecord, EncryptedSuggestion,
  EncryptionKeysResult,
  EncryptionMember, makeColumnScope, makeKeyId, NewKeyRequest, PayloadSource, tableTarget,
} from "app/common/encryption/EncryptionTypes";
import {
  buildFormSpec, getFormScopes, getFormShareOptions, getPublishedForms, readFormAnswers,
} from "app/common/encryption/FormSpecs";
import { Keyring } from "app/common/encryption/Keyring";
import {
  DocRestoredError, IEncryptionRelay, InvalidChange, LocalActiveDoc, LocalDocUserAction, NeedsReloadError,
  SuggestionInfo,
} from "app/common/encryption/LocalActiveDoc";
import { addParsedTables, parseFileLocally } from "app/common/encryption/LocalImport";
import { EncryptionClientConfig } from "app/common/gristUrls";
import { User } from "app/common/User";

import { Semaphore } from "async-mutex";
import { Disposable, dom, Emitter, Observable } from "grainjs";
import isEqual from "lodash/isEqual";
import omit from "lodash/omit";

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

  public pushAction(baseActionNum: number, keyId: string, payload: Base64,
    options?: { consumeInbox?: number[] }): Promise<EncryptedPushResult> {
    return this._call("pushEncryptedAction", baseActionNum, keyId, payload, ...(options ? [options] : []));
  }

  public listInbox(): Promise<EncryptedInboxEntry[]> { return this._call("listEncryptedInbox"); }
  public dropInbox(ids: number[]): Promise<void> { return this._call("dropEncryptedInbox", ids); }
  public publishForm(formId: string, spec: Base64): Promise<void> {
    return this._call("publishEncryptedForm", formId, spec);
  }

  public unpublishForm(formId: string): Promise<void> { return this._call("unpublishEncryptedForm", formId); }

  public async saveSnapshot(actionNum: number, keyId: string, payload: Uint8Array, options?: { compact?: boolean }) {
    await this._call("saveEncryptedSnapshot", actionNum, keyId, await this._send(payload), options || {});
  }

  public fetchSnapshot(snapshot: EncryptedSnapshotRecord): Promise<Uint8Array> {
    return this.receive(snapshot.size, (offset, length) =>
      this._call("fetchEncryptedSnapshot", snapshot.actionNum, offset, length));
  }

  public getKeys(): Promise<EncryptionKeysResult> { return this._call("getEncryptionKeys"); }
  public listMembers(): Promise<EncryptionMember[]> { return this._call("listEncryptionMembers"); }
  public async createKey(request: NewKeyRequest,
    snapshot?: { payload: Uint8Array, compact: boolean }): Promise<EncryptedPushResult> {
    return this._call("createEncryptionKey", snapshot ?
      { ...request, snapshot: await this._send(snapshot.payload), compact: snapshot.compact } : request);
  }

  public listSnapshots(): Promise<EncryptedSnapshotInfo[]> { return this._call("listEncryptedSnapshots"); }
  public getSnapshot(actionNum: number): Promise<EncryptedSnapshotRecord> {
    return this._call("getEncryptedSnapshot", actionNum);
  }

  public async restoreSnapshot(baseActionNum: number, keyId: string,
    payload: Uint8Array): Promise<EncryptedPushResult> {
    return this._call("restoreEncryptedSnapshot", baseActionNum, keyId, await this._send(payload));
  }

  public submitSuggestion(keyId: string, payload: Base64): Promise<number> {
    return this._call("submitEncryptedSuggestion", keyId, payload);
  }

  public listSuggestions(): Promise<EncryptedSuggestion[]> { return this._call("listEncryptedSuggestions"); }
  public resolveSuggestion(id: number): Promise<void> { return this._call("resolveEncryptedSuggestion", id); }

  public lock(reason: DocLockInfo["reason"]): Promise<void> { return this._call("lockEncryptedDoc", reason); }
  public unlock(): Promise<void> { return this._call("unlockEncryptedDoc"); }

  public releaseScope(scope: string, baseActionNum: number, record?: Base64): Promise<EncryptedPushResult> {
    return this._call("releaseEncryptionScope", scope, baseActionNum, ...(record ? [record] : []));
  }

  public shareKeys(wraps: DocKeyRecord[]): Promise<void> { return this._call("shareEncryptionKeys", wraps); }
  public revokeKeys(userIds: number[], scope?: string): Promise<void> {
    return this._call("revokeEncryptionKeys", userIds, scope);
  }

  public async uploadFile(ciphertext: Uint8Array): Promise<{ fileId: string }> {
    return this._call("uploadEncryptedFile", await this._send(ciphertext));
  }

  public async fetchFile(fileId: string): Promise<Uint8Array> {
    const first: { payload: Base64, size: number } =
      await this._call("fetchEncryptedFile", fileId, 0, ENCRYPTED_PART_BYTES);
    if (first.size <= ENCRYPTED_PART_BYTES) { return base64ToBytes(first.payload); }
    return this.receive(first.size, async (offset, length) => offset === 0 ? first.payload :
      (await this._call("fetchEncryptedFile", fileId, offset, length)).payload);
  }

  /** A payload as the server takes it: inline if small enough, or uploaded by parts first. */
  public async send(payload: Uint8Array): Promise<PayloadSource> {
    return this._send(payload);
  }

  /** Calls a method of the server about this document. */
  public call(method: string, ...args: any[]): Promise<any> {
    return this._call(method, ...args);
  }

  /** Gets a payload of the given size by parts. */
  public async receive(size: number, fetchPart: (offset: number, length: number) => Promise<Base64>) {
    const result = new Uint8Array(size);
    for (let offset = 0; offset < size; offset += ENCRYPTED_PART_BYTES) {
      const part = base64ToBytes(await fetchPart(offset, Math.min(ENCRYPTED_PART_BYTES, size - offset)));
      if (offset + part.length > size) { throw new Error("Invalid content received from the server"); }
      result.set(part, offset);
    }
    return result;
  }

  // A payload as the server takes it: inline if small enough, or uploaded by parts first.
  private async _send(payload: Uint8Array): Promise<PayloadSource> {
    if (payload.length <= ENCRYPTED_PART_BYTES) { return bytesToBase64(payload); }
    const uploadId: string = await this._call("beginEncryptedUpload");
    for (let seq = 0, offset = 0; offset < payload.length; seq++, offset += ENCRYPTED_PART_BYTES) {
      await this._call("appendEncryptedUpload", uploadId, seq,
        bytesToBase64(payload.subarray(offset, offset + ENCRYPTED_PART_BYTES)));
    }
    return { uploadId };
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
    options: { isCancelled?: () => boolean, canSuggest?: boolean } = {},
  ): Promise<{ session: EncryptedDocSession, openResponse: OpenLocalDocResult }> {
    const relay = new CommRelay(comm, docId);
    const cancellation = new Cancellation(options.isCancelled);
    const timings = new OpenTimings(docId);
    // The data engine takes longest to start, and needs nothing from the steps before using it:
    // start it right away.
    const startingEngine = WorkerEngine.create();
    startingEngine.catch(() => {});   // (Reported when awaited below.)
    let engine: WorkerEngine | undefined;
    let session: EncryptedDocSession | undefined;
    try {
      let openResult = await relay.open();
      timings.step("server open");
      cancellation.check();
      const vault = await getKeyVault(config, openResult.user.vaultUserId);
      timings.step("load encryption service");
      while (!await vault.hasKeys()) {
        await promptKeySetup(vault, cancellation);
      }
      timings.step("check keys");
      const vaultIdFor = makeVaultIdFor(config);

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

      timings.step("get document key");
      engine = await startingEngine;
      timings.step("wait for engine (Pyodide, started first)", engine.startTimings);
      cancellation.check();
      session = new EncryptedDocSession(comm, docId, relay, keyring, engine, openResult, vaultIdFor, config);
      await session._open(openResult, Boolean(options.canSuggest), step => timings.step(step));
      cancellation.check();
      const openResponse = await session._makeOpenResponse(openResult);
      timings.step("prepare for display");
      session.openTimings = timings.done();
      return { session, openResponse };
    } catch (e) {
      // Don't leave the data engine running, nor the server sending us changes.
      if (session) {
        session.dispose();
      } else {
        startingEngine.then(e => e.terminate()).catch(() => {});
      }
      relay.close().catch(() => {});
      throw e;
    } finally {
      cancellation.dispose();
    }
  }

  public readonly docFD = _nextDocFD--;
  // How long each step of opening the document took (see OpenTimings).
  public openTimings: OpenStepTiming[] = [];
  // Emitted when keys or members change, or which columns are private.
  public readonly keysChanged = this.autoDispose(new Emitter());
  // Emitted when suggestions are added or handled, or when changes are made while suggesting.
  public readonly suggestionsChanged = this.autoDispose(new Emitter());

  private _reviewMembers?: () => void;
  private _localDoc: LocalActiveDoc;
  // Changes from others are held back until the document is shown (see resume()).
  private _paused = true;
  private _heldActions: EncryptedActionRecord[] = [];
  private _timer?: ReturnType<typeof setInterval>;
  // Most recently used last.
  private _attachmentUrls = new Map<number, Promise<string>>();
  private _attachmentFetches = new Semaphore(MAX_PARALLEL_ATTACHMENT_FETCHES);
  private _lastPrivacy = "";
  private _lockOverlay?: ReturnType<typeof showLockOverlay>;
  private _importScheduled = false;
  private _formSyncTimer?: ReturnType<typeof setTimeout>;
  // What respondents of each form were last given (as JSON), by formId.
  private _uploadedSpecs = new Map<string, string>();

  private constructor(
    private _comm: Comm,
    private _docId: string,
    private _relay: CommRelay,
    private _keyring: Keyring,
    private _engine: WorkerEngine,
    private _openResult: EncryptedDocOpenResult,
    private _vaultIdFor: (m: { userId: number, vaultUserId: string | null }) => string | null,
    private _config: EncryptionClientConfig,
  ) {
    super();
    this.onDispose(() => {
      if (this._timer) { clearInterval(this._timer); }
      this._localDoc?.close();
      this._engine.terminate();
      this._comm.stopListening(this._comm, "encryptedDocAction", this._onDocAction);
      this._comm.stopListening(this._comm, "encryptedDocKeys", this._onDocKeys);
      this._comm.stopListening(this._comm, "encryptedDocLock", this._onDocLock);
      this._comm.stopListening(this._comm, "encryptedDocSuggestions", this._onSuggestions);
      this._comm.stopListening(this._comm, "encryptedDocInbox", this._onInbox);
      if (this._formSyncTimer) { clearTimeout(this._formSyncTimer); }
      this._lockOverlay?.close();
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
    this._importAnswersSoon();
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
      case "getAssistance": {
        const assistant = this._config.assistant;
        if (!assistant || !args[0] || !("tableId" in args[0].context)) {
          throw new Error(t("The AI assistant is not available for end-to-end encrypted documents"));
        }
        return getLocalAssistance(assistant, doc, args[0]);
      }
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

  /**
   * For the sharing dialog: members who can't read the document yet, by email, with whether they
   * enabled encryption since (so an owner can accept them, see acceptMember()).
   */
  public async getPendingEncryption(): Promise<Map<string, { canAccept: boolean }>> {
    const { ready, notReady } = await this._splitByReadiness(await this.getPendingMembers());
    return new Map([
      ...notReady.map(m => [m.email, { canAccept: false }] as const),
      ...ready.map(m => [m.email, { canAccept: this.isOwner }] as const),
    ]);
  }

  /** How to open the sharing dialog, where owners accept members (set by the share menu). */
  public setReviewMembers(review: () => void) { this._reviewMembers = review; }

  /** Gives the document's keys to a member waiting for them (see getPendingEncryption()). */
  public async acceptMember(email: string): Promise<void> {
    const member = (await this.getPendingMembers()).find(m => m.email === email);
    if (!member) { return; }
    const { granted } = await this.shareScope(DOC_SCOPE, [member]);
    if (granted.length === 0) { throw new Error(t("They haven't enabled encryption on their account yet.")); }
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
    return this._makePrivate(colRef, userIds);
  }

  /** Makes a private column readable by all members again. */
  public async makeColumnPublic(colRef: number): Promise<void> {
    return this._makePublic(this._keyring.currentScopeOf(colRef));
  }

  /**
   * Makes a whole table private, like a column (see makeColumnPrivate()): all its columns,
   * including those added later. Its structure (name, columns, number of rows) stays visible.
   */
  public async makeTablePrivate(tableRef: number, userIds: number[]): Promise<KeyGrantResult> {
    return this._makePrivate(tableTarget(tableRef), userIds);
  }

  /** Makes a private table readable by all members again. */
  public async makeTablePublic(tableRef: number): Promise<void> {
    return this._makePublic(this._keyring.currentScopeOfTable(tableRef));
  }

  /** The scope of a private table (null if it isn't). */
  public tableScope(tableRef: number): string | null {
    return this._keyring.currentScopeOfTable(tableRef);
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

  /**
   * Imports a file from Google Drive (given its URL, and the authorization code the user got from
   * Google), downloading and parsing it in the browser. Returns the new tables' ids.
   */
  public async importFromGoogleDrive(url: string, code: string): Promise<string[]> {
    const fileId = driveFileIdFromUrl(url);
    if (!fileId) { throw new Error(t("This is not a link to a Google Drive file")); }
    const { accessToken } = await this._relay.call("getGoogleDriveToken", code);
    const { name, data } = await downloadFromDrive(fileId, accessToken);
    const parsed = await parseFileLocally(this._engine, name, data);
    return addParsedTables(parsed, name, this._localDoc.docData,
      (actions, options) => this._localDoc.applyUserActions(actions, options));
  }

  /**
   * Publishes a form section as an encrypted form (see EncryptedForms.ts): gives it keys (kept in
   * the document) if it has none yet, and stores what respondents get, encrypted, on the server.
   */
  public async publishForm(sectionId: number): Promise<void> {
    const options = getFormShareOptions(this._localDoc.docData, sectionId);
    let keys = options.encryptedForm || await generateFormKeys();
    // Answers filling private columns are only for members who can read them: the form's private
    // key gets sealed with their keys (those this member holds: fields of others are left out).
    const scopes = getFormScopes(this._localDoc.docData, this._localDoc.privacy, sectionId)
      .filter(scope => this._keyring.canUseScope(scope));
    if (!isEqual(scopes, keys.scopes || [])) {
      const privateKey = await makeFormAnswerHelpers(this._relay, this._keyring).getPrivateKey(keys);
      if (!privateKey) { throw new Error(t("Only members who can read the columns this form fills can publish it")); }
      const rest = omit(keys, "privateKey", "sealedPrivateKey");
      const keyIds = scopes.map(scope => this._keyring.currentKeyId(scope));
      keys = scopes.length === 0 ? { ...rest, privateKey, scopes: [] } : {
        ...rest, scopes,
        sealedPrivateKey: {
          keyIds, data: bytesToBase64(await this._keyring.encryptWithAll(keyIds, utf8Encode(privateKey))),
        },
      };
    }
    await this._localDoc.applyUserActions([["UpdateRecord", "_grist_Views_section", sectionId, {
      shareOptions: JSON.stringify({ ...options, form: true, publish: true, encryptedForm: keys }),
    }]], { desc: "Publish form" });
    await this._uploadFormSpec(sectionId, keys);
  }

  /** Stops taking answers to a form (answers sent before still get added to the document). */
  public async unpublishForm(sectionId: number): Promise<void> {
    const options = getFormShareOptions(this._localDoc.docData, sectionId);
    if (options.encryptedForm) { await this._relay.unpublishForm(options.encryptedForm.formId); }
    await this._localDoc.applyUserActions([["UpdateRecord", "_grist_Views_section", sectionId, {
      shareOptions: JSON.stringify({ ...options, publish: false }),
    }]], { desc: "Unpublish form" });
  }

  /** The link to a published form (with its link key, after "#"). */
  public getFormUrl(sectionId: number): string | null {
    const keys = getFormShareOptions(this._localDoc.docData, sectionId).encryptedForm;
    if (!keys) { return null; }
    const url = urlState().makeUrl({
      doc: undefined, form: { shareKey: makeEncryptedFormShareKey(this._docId, keys.formId), vsId: sectionId },
    });
    return `${url}#${keys.linkKey}`;
  }

  /** Whether the user can read all of the document (needed to decrypt or copy it). */
  public get canReadAll() { return this._localDoc.canReadAll; }

  /** Whether the user's changes are suggestions (they can't edit the document, but may suggest). */
  public get isSuggesting() { return this._localDoc.isSuggesting; }
  public get pendingSuggestionCount() { return this._localDoc.pendingSuggestionCount; }

  public async submitSuggestion(desc: string): Promise<void> {
    await this._localDoc.submitSuggestion(desc);
    this.suggestionsChanged.emit();
  }

  public async discardSuggestion(): Promise<void> {
    await this._localDoc.discardSuggestion();
    this.suggestionsChanged.emit();
  }

  public async listSuggestions(): Promise<(SuggestionInfo & { userName: string })[]> {
    const suggestions = await this._localDoc.listSuggestions();
    const members = await this.listMembers().catch(() => []);
    return suggestions.map((s) => {
      const member = members.find(m => m.userId === s.userId);
      return { ...s, userName: member?.name || member?.email || "" };
    });
  }

  public async applySuggestion(id: number): Promise<void> {
    await this._localDoc.applySuggestion(id);
  }

  public async dismissSuggestion(id: number): Promise<void> {
    await this._localDoc.dismissSuggestion(id);
  }

  /** The snapshots the server keeps (versions the document can be restored to), newest first. */
  public async listSnapshots(): Promise<(EncryptedSnapshotInfo & { userName: string })[]> {
    const snapshots = await this._relay.listSnapshots();
    const members = await this.listMembers().catch(() => []);
    return snapshots.map((s) => {
      const member = members.find(m => m.userId === s.userId);
      return { ...s, userName: member?.name || member?.email || "" };
    });
  }

  /**
   * Restores the version of the document saved in a snapshot (by an owner who can read all of
   * it). Others see it's in progress meanwhile; then everyone reloads the document.
   */
  public async restoreSnapshot(actionNum: number): Promise<void> {
    const doneLocking = lockingHere(this._docId, () => this._relay.call("renewDocLock"));
    await this._relay.lock("restoring");
    try {
      await this._localDoc.restoreSnapshot(actionNum);
    } finally {
      await this._relay.unlock().catch(() => {});
      doneLocking();
    }
    window.location.reload();
  }

  /**
   * Makes the document a regular one, no longer end-to-end encrypted (by an owner who can read all
   * of it): its private columns get hidden by access rules from members who couldn't read them.
   * Every browser that has it open then reopens it.
   */
  public async decryptDocument(onProgress: ProgressCallback): Promise<void> {
    await decryptDocument(this._relay, this._docId, this._localDoc, this._keyring, onProgress);
  }

  /**
   * Copies the document (all of it, so by a member who can read all of it) into newDocId, a new
   * encrypted document: private columns stay private, and members of the copy get the keys they
   * held in the original.
   */
  public async copyTo(newDocId: string, options: { asTemplate: boolean },
    onProgress: ProgressCallback): Promise<{ waitingMembers: string[] }> {
    const userId = this.userId;
    const vaultUserId = userId ? this._vaultIdFor({ userId, vaultUserId: this._openResult.user.vaultUserId }) : null;
    if (!userId || !vaultUserId) { throw new Error(t("Your account is not known to the encryption service")); }
    return copyDocument(this._comm, newDocId, {
      relay: this._relay, localDoc: this._localDoc, keyring: this._keyring, userId, vaultIdFor: this._vaultIdFor,
    }, options, onProgress);
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
  // Makes a column or table private (see tableTarget()) to the given members and the user.
  private async _makePrivate(target: number, userIds: number[]): Promise<KeyGrantResult> {
    const members = await this.listMembers();
    const chosen = members.filter(m => m.userId === this.userId || userIds.includes(m.userId));
    const { ready, notReady } = await this._splitByReadiness(chosen);
    if (!ready.some(m => m.userId === this.userId)) {
      throw new Error(t("Your account is not known to the encryption service"));
    }
    const recipients: (KeyRecipient & { userId: number })[] = ready.map(m =>
      ({ userId: m.userId, vaultUserId: this._vaultIdFor(m)!, email: m.email, name: m.name }));
    // Values shared so far were readable by all members: keep only the private version (saved
    // along with the key change).
    await this._localDoc.createScopeKey(makeColumnScope(), recipients, target, { compact: true });
    this.keysChanged.emit();
    return { granted: ready.filter(m => m.userId !== this.userId), notReady };
  }

  private async _makePublic(scope: string | null): Promise<void> {
    if (!scope) { return; }
    await this._localDoc.releaseScope(scope);
    this.keysChanged.emit();
  }

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

  private async _open(openResult: EncryptedDocOpenResult, canSuggest: boolean, onOpenStep: (step: string) => void) {
    const user = openResult.user;
    this._localDoc = await LocalActiveDoc.open({
      engine: this._engine,
      relay: this._relay,
      keyring: this._keyring,
      engineUser: makeUser(openResult).toJSON(),
      userName: user.email || "",
      canEdit: openResult.access === "owners" || openResult.access === "editors",
      canSuggest,
      onDocUserAction: action => this._emitDocUserAction(action),
      vaultIdFor: this._vaultIdFor,
      newDocSettings: (openResult.access === "owners") ? {
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
        locale: navigator.language || "en-US",
      } : undefined,
      onInvalidChange: change => this._onInvalidChange(change),
      onOpenStep,
      onRotationFailed: (e) => {
        console.warn("[encryption] Could not replace keys", e);
        reportMessage(t(`Keys couldn't be replaced after a member lost access: it will be tried again on your next change.`), { level: "warning", key: "encryption-rotation-failed" });
      },
      log: (...args) => console.log("[encryption]", ...args),
    }, openResult);
    this._comm.listenTo(this._comm, "encryptedDocAction", this._onDocAction);
    this._comm.listenTo(this._comm, "encryptedDocKeys", this._onDocKeys);
    this._comm.listenTo(this._comm, "encryptedDocLock", this._onDocLock);
    this._comm.listenTo(this._comm, "encryptedDocSuggestions", this._onSuggestions);
    this._comm.listenTo(this._comm, "encryptedDocInbox", this._onInbox);
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

  private _onInbox = (message: CommEncryptedDocInbox) => {
    if (message.data.docId !== this._docId || this.isDisposed() || this._paused) { return; }
    this._importAnswersSoon();
  };

  // Answers to forms are added to the document by members who can edit it, as soon as any of them
  // has it open (and can add them).
  private _importAnswersSoon() {
    if (!this.canEdit || this._importScheduled) { return; }
    this._importScheduled = true;
    setTimeout(() => {
      this._importScheduled = false;
      if (this.isDisposed()) { return; }
      this._track(this._localDoc.importFormAnswers(entries =>
        readFormAnswers(this._localDoc.docData, this._localDoc.privacy, entries,
          makeFormAnswerHelpers(this._relay, this._keyring)),
      ).then(() => {}).catch((e) => {
        // Answers this member can't add (e.g. they'd need keys they don't hold) are left for others.
        if (e instanceof EncryptionAccessError) {
          console.warn("[encryption] Leaving form answers to members with access", e);
        } else {
          throw e;
        }
      }));
    }, 500);
  }

  // Published forms get what respondents see updated after changes made here.
  private _syncFormsSoon() {
    if (!this.canEdit || this._formSyncTimer) { return; }
    this._formSyncTimer = setTimeout(() => {
      this._formSyncTimer = undefined;
      if (this.isDisposed()) { return; }
      this._syncForms().catch(e => console.warn("[encryption] Could not update published forms", e));
    }, 2000);
  }

  private async _syncForms() {
    for (const { sectionId, keys } of getPublishedForms(this._localDoc.docData)) {
      await this._uploadFormSpec(sectionId, keys);
    }
  }

  private async _uploadFormSpec(sectionId: number, keys: EncryptedFormKeys) {
    const spec = await buildFormSpec(this._localDoc.docData, this._localDoc.privacy, sectionId, keys,
      async tableId => (await this._localDoc.fetchTable(tableId)).tableData);
    const json = JSON.stringify(spec);
    if (this._uploadedSpecs.get(keys.formId) === json) { return; }
    await this._relay.publishForm(keys.formId, bytesToBase64(await encryptFormSpec(keys.linkKey, spec)));
    this._uploadedSpecs.set(keys.formId, json);
  }

  private _onSuggestions = (message: CommEncryptedDocSuggestions) => {
    if (message.data.docId !== this._docId || this.isDisposed()) { return; }
    this.suggestionsChanged.emit();
  };

  // Someone locked the document for a while (e.g. to restore an earlier version), or unlocked it.
  private _onDocLock = (message: CommEncryptedDocLock) => {
    if (message.data.docId !== this._docId || this.isDisposed()) { return; }
    if (message.data.decrypted) {
      // It's a regular document now: it must be opened as such.
      window.location.reload();
      return;
    }
    const lock = message.data.lock;
    if (lock && !isLockedHere(this._docId)) {
      if (this._lockOverlay) { this._lockOverlay.update(lock); } else { this._lockOverlay = showLockOverlay(lock); }
    } else if (!lock) {
      this._lockOverlay?.close();
      this._lockOverlay = undefined;
      this._track(this._localDoc.sync());
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
      if (e instanceof DocRestoredError) {
        offerReload(t("An earlier version of this document was restored: it needs reloading."));
      } else if (e instanceof NeedsReloadError) {
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
    if (this._localDoc?.isSuggesting) { setTimeout(() => this.suggestionsChanged.emit(), 0); }
    if (action.fromSelf && this._localDoc && getPublishedForms(this._localDoc.docData).length > 0) {
      this._syncFormsSoon();
    }
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

  // When an owner opens the document: let them know of members who enabled encryption since being
  // added, and wait for the owner to accept them in the sharing dialog. Accepting is explicit, so
  // the owner can check a member's key (e.g. with them) before giving them access.
  private async _offerPendingKeys() {
    if (!this.isOwner) { return; }
    const { ready } = await this._splitByReadiness(await this.getPendingMembers());
    if (ready.length === 0 || this.isDisposed()) { return; }
    reportMessage(t("{{count}} member(s) enabled encryption and are waiting for you to accept them.",
      { count: ready.length }), {
      key: "encryption-pending-keys",
      level: "info",
      // (How to open the sharing dialog is known by the time this is clicked.)
      actions: [{
        label: t("Review"),
        action: () => this._reviewMembers?.(),
      }],
    });
  }
}

export interface OpenStepTiming { step: string, ms: number }

/**
 * Measures the steps of opening an encrypted document: shown in the browser's performance panel
 * (as "encryption: <step>"), and summed up in the console.
 */
class OpenTimings {
  private _start = performance.now();
  private _last = this._start;
  private _steps: OpenStepTiming[] = [];

  constructor(private _docId: string) {}

  public step(name: string, details: OpenStepTiming[] = []) {
    const now = performance.now();
    this._steps.push({ step: name, ms: Math.round(now - this._last) });
    this._steps.push(...details.map(d => ({ step: `  ${d.step}`, ms: d.ms })));
    try {
      performance.measure(`encryption: ${name}`, { start: this._last, end: now });
    } catch (e) {
      // (Older browsers: the console summary is enough.)
    }
    this._last = now;
  }

  public done(): OpenStepTiming[] {
    const total = Math.round(this._last - this._start);
    console.info(`[encryption] Opened ${this._docId} in ${total} ms:\n` +
      this._steps.map(s => `  ${String(s.ms).padStart(6)} ms  ${s.step}`).join("\n"));
    return [...this._steps, { step: "total", ms: total }];
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

/** Thrown when the user gives up setting up their encryption keys (see ensureVaultKeys()). */
export class SetupCancelledError extends Error {
  constructor() { super("Encryption setup cancelled"); }
}

/** Makes sure the user set up their encryption keys, asking them to (until they did or gave up). */
export async function ensureVaultKeys(vault: IKeyVault, purpose: "open" | "encrypt" = "open"): Promise<void> {
  const cancellation = new Cancellation();
  try {
    while (!await vault.hasKeys()) { await promptKeySetup(vault, cancellation, purpose); }
  } finally {
    cancellation.dispose();
  }
}

/**
 * Shows a dialog until the user has set up their encryption keys (or gives up). The encryption
 * service's setup opens from it, and the dialog closes as soon as the setup is done.
 */
function promptKeySetup(vault: IKeyVault, cancellation: Cancellation,
  purpose: "open" | "encrypt" = "open"): Promise<void> {
  return new Promise((resolve, reject) => {
    modal((ctl, owner) => {
      const busy = Observable.create(owner, false);
      cancellation.whenCancelled.catch((e: Error) => {
        if (!owner.isDisposed()) { ctl.close(); }
        reject(e);
      });
      const setUp = async () => {
        busy.set(true);
        try {
          if (await vault.openOnboarding!() || await vault.hasKeys()) {
            ctl.close();
            resolve();
          }
        } finally {
          if (!owner.isDisposed()) { busy.set(false); }
        }
      };
      return [
        cssModalTitle(t("Enable encryption")),
        cssModalBody(purpose === "encrypt" ?
          t("To encrypt a document, first enable encryption on your account.") :
          t("This document is encrypted. You must enable encryption on your account to access it.")),
        cssModalButtons(
          vault.openOnboarding ?
            bigPrimaryButton(t("Enable encryption"), dom.boolAttr("disabled", busy),
              dom.on("click", () => { setUp().catch(reportError); })) :
            // (Without the service's setup at hand: once done elsewhere, check again.)
            bigPrimaryButton(t("Check again"), dom.on("click", () => { ctl.close(); resolve(); })),
          bigBasicButton(t("Cancel"), dom.on("click", () => {
            ctl.close();
            reject(purpose === "encrypt" ? new SetupCancelledError() :
              new Error(t("Encryption keys are required to open this document")));
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
          t(`This document is encrypted. You have access to it, but not yet to its key: it will open as soon as an owner opens it and gives you access.`) :
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
