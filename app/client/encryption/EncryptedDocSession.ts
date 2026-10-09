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
import { getKeyVault } from "app/client/encryption/keyVaults";
import { IDocEncryption } from "app/client/encryption/types";
import { WorkerEngine } from "app/client/encryption/WorkerEngine";
import { makeT } from "app/client/lib/localization";
import { reportError, reportMessage } from "app/client/models/errors";
import { bigBasicButton, bigPrimaryButton } from "app/client/ui2018/buttons";
import { cssModalBody, cssModalButtons, cssModalTitle, modal } from "app/client/ui2018/modals";
import { ActiveDocAPI } from "app/common/ActiveDocAPI";
import { CommEncryptedDocAction, CommEncryptedDocKeys } from "app/common/CommTypes";
import { OpenLocalDocResult } from "app/common/DocListAPI";
import { decryptFile, encryptFile, makeFileIdent, parseFileIdent } from "app/common/encryption/EncryptedAttachments";
import { base64ToBytes, bytesToBase64, IKeyVault, KeyRecipient } from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, DocKeyRecord, EncryptedActionRecord, EncryptedDocOpenResult, EncryptedPushResult,
  EncryptionKeysResult, EncryptionMember, makeColumnScope, makeKeyId, NewKeyRequest,
} from "app/common/encryption/EncryptionTypes";
import { Keyring } from "app/common/encryption/Keyring";
import {
  IEncryptionRelay, InvalidChange, LocalActiveDoc, LocalDocUserAction, NeedsReloadError,
} from "app/common/encryption/LocalActiveDoc";
import { addParsedTables, parseFileLocally } from "app/common/encryption/LocalImport";
import { EncryptionClientConfig } from "app/common/gristUrls";
import { User } from "app/common/User";

import { Disposable, dom, Emitter } from "grainjs";

const t = makeT("EncryptedDocSession");

// Keep formulas depending on the current time up to date, as the server does for regular docs.
const UPDATE_CURRENT_TIME_MS = 60 * 60 * 1000;

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

  public saveSnapshot(actionNum: number, keyId: string, payload: Base64, options?: { compact?: boolean }) {
    return this._call("saveEncryptedSnapshot", actionNum, keyId, payload, options || {});
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
  public uploadFile(payload: Base64): Promise<{ fileId: string }> { return this._call("uploadEncryptedFile", payload); }
  public fetchFile(fileId: string): Promise<Base64> { return this._call("fetchEncryptedFile", fileId); }

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
    const checkCancelled = () => {
      if (options.isCancelled?.()) { throw new Error("Opening cancelled"); }
    };
    let openResult = await relay.open();
    const vault = await getKeyVault(config, openResult.user.vaultUserId);
    while (!await vault.hasKeys()) {
      await promptKeySetup(vault);
      checkCancelled();
    }
    const vaultIdFor = (m: { userId: number, vaultUserId: string | null }) =>
      m.vaultUserId || (config.mockVault ? mockVaultUserId(m.userId) : null);

    const keyring = new Keyring(vault, () => relay.getKeys(), openResult);
    while (!keyring.canUseScope(DOC_SCOPE)) {
      checkCancelled();
      if (openResult.keys.length === 0 && openResult.access === "owners" && openResult.user.id) {
        await createDocumentKey(vault, relay, openResult, vaultIdFor);
        await keyring.refresh();
      } else {
        await waitForKey(comm, docId, openResult);
        openResult = await relay.open();
        keyring.update(openResult);
      }
    }

    const engine = await WorkerEngine.create();
    checkCancelled();
    const session = new EncryptedDocSession(comm, docId, relay, keyring, engine, openResult, vaultIdFor);
    try {
      await session._open(openResult);
      checkCancelled();
    } catch (e) {
      session.dispose();
      throw e;
    }
    return { session, openResponse: await session._makeOpenResponse(openResult) };
  }

  public readonly docFD = _nextDocFD--;
  // Emitted when keys or members change, or which columns are private.
  public readonly keysChanged = this.autoDispose(new Emitter());

  private _localDoc: LocalActiveDoc;
  // Changes from others are held back until the document is shown (see resume()).
  private _paused = true;
  private _heldActions: EncryptedActionRecord[] = [];
  private _timer?: ReturnType<typeof setInterval>;
  private _attachmentUrls = new Map<number, Promise<string>>();

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
      this._timer = setInterval(() => this._track(this._localDoc.updateCurrentTime()), UPDATE_CURRENT_TIME_MS);
    }
    this._offerPendingKeys().catch(e => console.warn("Encryption: could not check members' keys", e));
  }

  /** Serves the ActiveDocAPI method `name` for this document. */
  public async callMethod(name: keyof ActiveDocAPI, ...args: any[]): Promise<any> {
    const doc = this._localDoc;
    switch (name) {
      case "fetchTable": return doc.fetchTable(args[0]);
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
   * who set up their own encryption keys. Only owners can. Returns those who got them.
   */
  public async shareScope(scope: string, members: EncryptionMember[]): Promise<EncryptionMember[]> {
    const candidates = members.filter(m => this._vaultIdFor(m));
    if (candidates.length === 0) { return []; }
    const registered = await this._keyring.vault.getRegisteredUsers(candidates.map(m => this._vaultIdFor(m)!));
    const recipients = candidates.filter(m => registered.has(this._vaultIdFor(m)!))
      .map(m => ({ vaultUserId: this._vaultIdFor(m)!, email: m.email, name: m.name, member: m }));
    if (recipients.length === 0) { return []; }
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
    return [...granted];
  }

  /** Gives the document's keys to members who have access to it but can't read it yet. */
  public async grantPendingKeys(): Promise<EncryptionMember[]> {
    return this.shareScope(DOC_SCOPE, await this.getPendingMembers());
  }

  /**
   * Makes a column private: only the given members (and the current user) will be able to read
   * it, and formulas using it. Its current values are re-encrypted, and the server drops what it
   * had of them in readable form (older changes and snapshots).
   */
  public async makeColumnPrivate(colRef: number, userIds: number[]): Promise<void> {
    const members = await this.listMembers();
    const me = this.userId;
    const recipients = members.filter(m => m.userId === me || userIds.includes(m.userId))
      .map(m => ({ userId: m.userId, vaultUserId: this._vaultIdFor(m)!, email: m.email, name: m.name }))
      .filter(r => r.vaultUserId);
    const scope = makeColumnScope();
    await this._localDoc.createScopeKey(scope, recipients as (KeyRecipient & { userId: number })[], colRef);
    // Values shared so far were readable by all members: keep only the private version.
    await this._localDoc.saveSnapshot({ compact: true });
    this.keysChanged.emit();
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
  public async setScopeAudience(scope: string, userIds: number[]): Promise<void> {
    const members = await this.listMembers();
    const holders = members.filter(m => m.keyIds.some(keyId => this._keyring.getKey(keyId)?.scope === scope));
    const toAdd = members.filter(m => userIds.includes(m.userId) && !holders.includes(m));
    const toRemove = holders.filter(m => !userIds.includes(m.userId) && m.userId !== this.userId);
    if (toAdd.length > 0) { await this.shareScope(scope, toAdd); }
    if (toRemove.length > 0) {
      await this._relay.revokeKeys(toRemove.map(m => m.userId), scope);
      await this._localDoc.refreshKeys();
      await this._localDoc.rotateKeys();
    }
    this.keysChanged.emit();
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
    const scopes = target ? this.privacy.scopesOf(target.tableId, target.colId) : [];
    const scope = scopes[0] || DOC_SCOPE;
    const records: Record<string, any>[] = [];
    for (const file of files) {
      const data = new Uint8Array(await file.arrayBuffer());
      const { ciphertext, ref } = await encryptFile(this._keyring, scope, data);
      const { fileId } = await this._relay.uploadFile(bytesToBase64(ciphertext));
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
        actions => this._localDoc.applyUserActions(actions)));
    }
    return tableIds;
  }

  /** Returns a (local, blob) URL to the decrypted content of an attachment. */
  public getAttachmentUrl(attId: number): Promise<string> {
    let url = this._attachmentUrls.get(attId);
    if (!url) {
      url = this._fetchAttachment(attId).then(({ data, fileName }) =>
        URL.createObjectURL(new Blob([data as BlobPart], { type: guessMimeType(fileName) })));
      url.catch(() => this._attachmentUrls.delete(attId));
      this._attachmentUrls.set(attId, url);
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

  private async _fetchAttachment(attId: number) {
    const record = this._localDoc.docData.getMetaTable("_grist_Attachments").getRecord(attId);
    const ref = record && parseFileIdent(record.fileIdent);
    if (!ref) { throw new Error(t("Attachment not found")); }
    const ciphertext = base64ToBytes(await this._relay.fetchFile(ref.fileId));
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
    if (action.docActions.some(a => a[1] === "_grist_Tables_column")) { this.keysChanged.emit(); }
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
          this.grantPendingKeys()
            .then(granted => reportMessage(t("Gave access to {{count}} member(s).", { count: granted.length }),
              { level: "info" }))
            .catch(reportError);
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

/** Shows a dialog until the user has set up their encryption keys (or gives up). */
function promptKeySetup(vault: IKeyVault): Promise<void> {
  return new Promise((resolve, reject) => {
    modal(ctl => [
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
    ], { noClickAway: true, noEscapeKey: true });
  });
}

/**
 * Shows a dialog explaining that the user has access to the document but no key to read it,
 * until an owner holding the key gives them one.
 */
function waitForKey(comm: Comm, docId: string, openResult: EncryptedDocOpenResult): Promise<void> {
  return new Promise((resolve, reject) => {
    modal((ctl, owner) => {
      const onKeys = (message: CommEncryptedDocKeys) => {
        if (message.data.docId === docId) { ctl.close(); resolve(); }
      };
      comm.listenTo(comm, "encryptedDocKeys", onKeys);
      owner.onDispose(() => comm.stopListening(comm, "encryptedDocKeys", onKeys));
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
