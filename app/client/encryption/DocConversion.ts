/**
 * Browser side of converting documents to and from end-to-end encryption, and of copying
 * encrypted documents (see app/server/lib/encryption/EncryptionConversion.ts for the server side).
 * Each is done by a member who can read the whole document:
 *  - encryptDocument(): a regular document gets a document key, and its content (and its
 *    attachments) get encrypted with it, for its members who enabled encryption;
 *  - decryptDocument(): an encrypted document becomes a regular one. Its private columns become
 *    columns hidden by access rules from the members who couldn't read them;
 *  - copyDocument(): a new encrypted document gets the content of an encrypted one, under keys of
 *    its own (nothing is private in it: only its creator is a member, at first).
 */
import { Comm } from "app/client/components/Comm";
import { CommRelay } from "app/client/encryption/EncryptedDocSession";
import { getKeyVault } from "app/client/encryption/keyVaults";
import { lockingHere } from "app/client/encryption/lockOverlay";
import { TableDataAction } from "app/common/DocActions";
import { makeAccessRuleActions } from "app/common/encryption/AccessRulesFromPrivacy";
import {
  BlobTable, ColumnPrivacy, MetaContext, MetaRows, sealTables,
} from "app/common/encryption/ColumnPrivacy";
import { decryptFile, encryptFile, makeFileIdent, parseFileIdent } from "app/common/encryption/EncryptedAttachments";
import { decryptFormFile } from "app/common/encryption/EncryptedForms";
import { encryptSnapshot, marshalValue, unmarshalValue } from "app/common/encryption/EncryptedPayloads";
import {
  base64ToBytes, bytesToBase64, gunzip, gzip, IKeyVault, utf8Decode,
} from "app/common/encryption/EncryptionCrypto";
import {
  Base64, DOC_SCOPE, DocKeyRecord, ENCRYPTED_PART_BYTES, EncryptionMember, makeColumnScope, makeKeyId,
} from "app/common/encryption/EncryptionTypes";
import { FormAnswerHelpers, readFormAnswers } from "app/common/encryption/FormSpecs";
import { Keyring } from "app/common/encryption/Keyring";
import { LocalActiveDoc } from "app/common/encryption/LocalActiveDoc";
import { SealedCells } from "app/common/encryption/SealedCells";
import { EncryptionClientConfig } from "app/common/gristUrls";
import { safeJsonParse } from "app/common/gutil";

/** What encrypting a document did, beyond encrypting it. */
export interface EncryptionSummary {
  // How many columns access rules hid from some members, now private.
  privateColumns: number;
  // How many access rules were about something else than reading (dropped).
  droppedRules: number;
  // Members who can't read the document yet (they haven't enabled encryption).
  waitingMembers: string[];
}

/** Reports progress, as a fraction between 0 and 1, and what's being done. */
export type ProgressCallback = (fraction: number, step: string) => void;

interface Tables { [tableId: string]: TableDataAction }
type Member = Omit<EncryptionMember, "keyIds">;

/** How encryption identifies members (needed to give them keys), if it can. */
export function makeVaultIdFor(config: EncryptionClientConfig) {
  return (m: { userId: number, vaultUserId: string | null }) =>
    m.vaultUserId || (config.mockVault ? `grist-user-${m.userId}` : null);
}

/**
 * Encrypts a regular document, by one of its owners (who must be able to read all of it, i.e. with
 * no access rules in it). Its members who enabled encryption get its key; others get it later, as
 * for any encrypted document. The document must be reopened once done.
 */
export async function encryptDocument(comm: Comm, docId: string, userId: number, config: EncryptionClientConfig,
  onProgress: ProgressCallback, prepareVault: (vault: IKeyVault) => Promise<void>): Promise<EncryptionSummary> {
  const relay = new CommRelay(comm, docId);
  const doneLocking = lockingHere(docId, () => relay.call("renewDocLock"));
  comm.useDocConnection(docId);
  try {
    onProgress(0, "start");
    const start: {
      size: number, attachments: { rowId: number, size: number }[], members: Member[],
      columnAudiences: { colRef: number, userIds: number[] }[], droppedRules: number,
    } = await relay.call("beginDocEncryption");
    try {
      const vaultIdFor = makeVaultIdFor(config);
      const me = start.members.find(m => m.userId === userId);
      const myVaultId = me && vaultIdFor(me);
      if (!myVaultId) { throw new Error("Your account is not known to the encryption service"); }
      const vault = await getKeyVault(config, me.vaultUserId);
      await prepareVault(vault);

      // The document key, for members who can get one now.
      const known = start.members.filter(m => vaultIdFor(m));
      const registered = await vault.getRegisteredUsers(known.map(m => vaultIdFor(m)!));
      const recipients = known.filter(m => m.userId === userId || registered.has(vaultIdFor(m)!))
        .map(m => ({ userId: m.userId, vaultUserId: vaultIdFor(m)!, email: m.email, name: m.name }));
      const keyWraps = await vault.createDocumentKey(recipients);
      const keyId = makeKeyId(DOC_SCOPE);
      const wraps: DocKeyRecord[] = recipients.filter(r => keyWraps.has(r.vaultUserId)).map(r => ({
        keyId, userId: r.userId, wrappedKey: bytesToBase64(keyWraps.get(r.vaultUserId)!.wrappedKey),
        keyVersion: keyWraps.get(r.vaultUserId)!.keyVersion,
      }));
      if (!wraps.some(w => w.userId === userId)) {
        throw new Error("The encryption service did not create a key for you");
      }
      // Columns that access rules hid from some members become private to the others (those who
      // can get keys now: others get them later, from an owner).
      const columnKeys: { scope: string, keyId: string, colRef: number, wraps: DocKeyRecord[] }[] = [];
      const missed = new Set<number>();
      for (const audience of start.columnAudiences) {
        const scope = makeColumnScope();
        const columnKeyId = makeKeyId(scope);
        const audienceRecipients = recipients.filter(r => r.userId === userId || audience.userIds.includes(r.userId));
        for (const id of audience.userIds) {
          if (!audienceRecipients.some(r => r.userId === id)) { missed.add(id); }
        }
        const columnWraps = await vault.createDocumentKey(audienceRecipients);
        columnKeys.push({ scope, keyId: columnKeyId, colRef: audience.colRef,
          wraps: audienceRecipients.filter(r => columnWraps.has(r.vaultUserId)).map(r => ({
            keyId: columnKeyId, userId: r.userId, wrappedKey: bytesToBase64(columnWraps.get(r.vaultUserId)!.wrappedKey),
            keyVersion: columnWraps.get(r.vaultUserId)!.keyVersion,
          })) });
      }
      const keyring = new Keyring(vault, () => { throw new Error("No keys to fetch yet"); }, {
        keys: [{ keyId, scope: DOC_SCOPE, current: true, rotateOnNextEdit: false, actionNum: 0 },
          ...columnKeys.map(k => ({ keyId: k.keyId, scope: k.scope, current: true, rotateOnNextEdit: false,
            actionNum: 0 }))],
        myKeys: [...wraps, ...columnKeys.flatMap(k => k.wraps)].filter(w => w.userId === userId),
        bindings: columnKeys.map(k => ({ scope: k.scope, colRef: k.colRef, boundAt: 0, releasedAt: null })),
      });

      onProgress(0.05, "content");
      const data = await relay.receive(start.size, (offset, length) =>
        relay.call("fetchConversionData", offset, length));
      const tables: Tables = unmarshalValue(await gunzip(data)).tables;
      const privacy = ColumnPrivacy.fromMetaTables(tables._grist_Tables, tables._grist_Tables_column,
        keyring.bindingsAt(0));
      const attachmentScopes = getAttachmentScopes(tables, privacy);

      // Attachments, encrypted with the document key (or the key of the private column they're in).
      const total = start.attachments.reduce((sum, a) => sum + a.size, 0) || 1;
      let done = 0;
      const idents = new Map<number, string>();
      for (const attachment of start.attachments) {
        onProgress(0.1 + 0.8 * done / total, "attachments");
        const fileData = await fetchByParts(attachment.size, (offset, length) =>
          relay.call("fetchConversionFile", attachment.rowId, offset, length));
        const { ciphertext, ref } = await encryptFile(keyring, attachmentScopes.get(attachment.rowId) || DOC_SCOPE,
          fileData);
        const { fileId } = await relay.uploadFile(ciphertext);
        idents.set(attachment.rowId, makeFileIdent({ fileId, ...ref }));
        done += attachment.size;
      }
      setColumn(tables._grist_Attachments, "fileIdent", (rowId, value) => idents.get(rowId) ?? value);

      onProgress(0.9, "saving");
      // Private values sealed with their columns' keys, as in any snapshot.
      const payload = await sealInitialSnapshot(tables, privacy, keyring, keyId);
      await relay.call("commitDocEncryption", keyId, wraps, await relay.send(payload), columnKeys);
      onProgress(1, "done");
      return {
        privateColumns: columnKeys.length,
        droppedRules: start.droppedRules,
        waitingMembers: start.members.filter(m => missed.has(m.userId) || !recipients.some(r => r.userId === m.userId))
          .map(m => m.name || m.email),
      };
    } catch (e) {
      await relay.call("abortDocConversion").catch(() => {});
      throw e;
    }
  } finally {
    comm.releaseDocConnection(docId);
    doneLocking();
  }
}

/**
 * Makes an encrypted document a regular one, by one of its owners who can read all of it. Columns
 * that were private get access rules hiding them from members who couldn't read them. The
 * document must be reopened once done (every browser that has it open reopens it).
 */
export async function decryptDocument(relay: CommRelay, docId: string, localDoc: LocalActiveDoc,
  keyring: Keyring, onProgress: ProgressCallback): Promise<void> {
  const doneLocking = lockingHere(docId, () => relay.call("renewDocLock"));
  try {
    onProgress(0, "start");
    await relay.call("beginDocDecryption");
    try {
      // Answers to forms still waiting are added first (the inbox goes with the encrypted document).
      await localDoc.importFormAnswers(entries => readFormAnswers(localDoc.docData, localDoc.privacy, entries,
        makeFormAnswerHelpers(relay, keyring)));
      const members = await relay.listMembers();
      const content = await localDoc.exportPlain(makeAccessRuleActions(localDoc.docData, localDoc.privacy, keyring,
        members));
      const tables = content.tables;
      // Forms of encrypted documents don't apply to regular ones (and their keys mustn't go to the server).
      setColumn(tables._grist_Views_section, "shareOptions", (_rowId, value) => {
        const options = safeJsonParse(String(value || ""), null);
        if (!options?.encryptedForm) { return value; }
        delete options.encryptedForm;
        return JSON.stringify({ ...options, publish: false });
      });

      // Attachments, decrypted.
      const attachments = tables._grist_Attachments;
      const fileIdents = attachments[3].fileIdent as string[];
      const sizes = attachments[3].fileSize as number[];
      const total = sizes.reduce((sum, size) => sum + (size || 0), 0) || 1;
      let done = 0;
      const newIdents: string[] = [];
      for (const [i, fileIdent] of fileIdents.entries()) {
        onProgress(0.05 + 0.8 * done / total, "attachments");
        const ref = parseFileIdent(fileIdent);
        if (!ref) { newIdents.push(fileIdent); continue; }
        const data = await decryptFile(keyring, ref, await relay.fetchFile(ref.fileId));
        const ext = (/\.[A-Za-z0-9_-]{1,20}$/.exec(String(attachments[3].fileName[i] || "")) || [""])[0];
        const result: { fileIdent: string } = await relay.call("uploadDecryptedFile", ext.toLowerCase(),
          await relay.send(data));
        newIdents.push(result.fileIdent);
        done += sizes[i] || 0;
      }
      attachments[3].fileIdent = newIdents;

      onProgress(0.9, "saving");
      const payload = await gzip(marshalValue({ tables }));
      await relay.call("commitDocDecryption", content.actionNum, await relay.send(payload));
      onProgress(1, "done");
    } catch (e) {
      await relay.call("abortDocConversion").catch(() => {});
      throw e;
    }
  } finally {
    doneLocking();
  }
}

/**
 * Copies an encrypted document (all of it, readable by the member copying it) into the new
 * encrypted document newDocId, under keys of its own. Columns private in the original are private
 * in the copy too. Members of the copy (as for any copy: those of its workspace) get the keys they
 * held in the original, if they enabled encryption. With `asTemplate`, only its structure is
 * copied, without data or attachments.
 */
export async function copyDocument(comm: Comm, newDocId: string, source: {
  relay: CommRelay, localDoc: LocalActiveDoc, keyring: Keyring, userId: number,
  vaultIdFor: (m: { userId: number, vaultUserId: string | null }) => string | null,
}, options: { asTemplate: boolean }, onProgress: ProgressCallback): Promise<{ waitingMembers: string[] }> {
  onProgress(0, "start");
  const tables = await source.localDoc.exportSnapshotTables();
  if (options.asTemplate) {
    const tableIds = new Set(tables._grist_Tables[3].tableId as string[]);
    for (const tableId of [...tableIds, "_grist_Attachments", "_grist_Cells"]) {
      const table = tables[tableId];
      if (table) { tables[tableId] = ["TableData", tableId, [], mapColumns(table[3], () => [])]; }
    }
  }
  comm.useDocConnection(newDocId);
  const relay = new CommRelay(comm, newDocId);
  try {
    await relay.open();
    const vault = source.keyring.vault;
    // Who can get which keys: members of the copy who held them in the original.
    const originalMembers = await source.relay.listMembers();
    const copyMembers = await relay.listMembers();
    const ready = copyMembers.filter(m => source.vaultIdFor(m));
    const registered = await vault.getRegisteredUsers(ready.map(m => source.vaultIdFor(m)!));
    const holders = (scope: string) => {
      const keyId = source.keyring.currentKey(scope)?.keyId;
      return ready.filter(m => m.userId === source.userId || (registered.has(source.vaultIdFor(m)!) &&
        originalMembers.some(o => o.userId === m.userId && keyId && o.keyIds.includes(keyId))));
    };
    const makeKey = async (scope: string, recipients: EncryptionMember[]) => {
      const keyId = makeKeyId(scope);
      const keyWraps = await vault.createDocumentKey(recipients.map(m => ({
        vaultUserId: source.vaultIdFor(m)!, email: m.email, name: m.name })));
      const wraps = recipients.filter(m => keyWraps.has(source.vaultIdFor(m)!)).map(m => ({
        keyId, userId: m.userId, wrappedKey: bytesToBase64(keyWraps.get(source.vaultIdFor(m)!)!.wrappedKey),
        keyVersion: keyWraps.get(source.vaultIdFor(m)!)!.keyVersion,
      }));
      if (!wraps.some(w => w.userId === source.userId)) {
        throw new Error("The encryption service did not create a key for you");
      }
      return { keyId, wraps };
    };
    const docRecipients = holders(DOC_SCOPE);
    const docKey = await makeKey(DOC_SCOPE, docRecipients);
    const columnKeys: { scope: string, keyId: string, colRef: number, wraps: DocKeyRecord[] }[] = [];
    for (const [colRef, originalScope] of source.keyring.bindingsAt(source.localDoc.head)) {
      const scope = makeColumnScope();
      columnKeys.push({ scope, colRef, ...await makeKey(scope, holders(originalScope)) });
    }
    const keyring = new Keyring(vault, () => relay.getKeys(), {
      keys: [{ keyId: docKey.keyId, scope: DOC_SCOPE, current: true, rotateOnNextEdit: false, actionNum: 0 },
        ...columnKeys.map(k => ({ keyId: k.keyId, scope: k.scope, current: true, rotateOnNextEdit: false,
          actionNum: 0 }))],
      myKeys: [...docKey.wraps, ...columnKeys.flatMap(k => k.wraps)].filter(w => w.userId === source.userId),
      bindings: columnKeys.map(k => ({ scope: k.scope, colRef: k.colRef, boundAt: 0, releasedAt: null })),
    });
    const privacy = ColumnPrivacy.fromMetaTables(tables._grist_Tables, tables._grist_Tables_column,
      keyring.bindingsAt(0));
    const attachmentScopes = getAttachmentScopes(tables, privacy);

    // Attachments, under the new document's keys.
    const attachments = tables._grist_Attachments;
    const sizes = (attachments[3].fileSize || []) as number[];
    const total = sizes.reduce((sum, size) => sum + (size || 0), 0) || 1;
    let done = 0;
    const idents: string[] = [];
    for (const [i, fileIdent] of ((attachments[3].fileIdent || []) as string[]).entries()) {
      onProgress(0.05 + 0.85 * done / total, "attachments");
      const ref = parseFileIdent(fileIdent);
      if (!ref) { idents.push(fileIdent); continue; }
      const data = await decryptFile(source.keyring, ref, await source.relay.fetchFile(ref.fileId));
      const { ciphertext, ref: newRef } = await encryptFile(keyring,
        attachmentScopes.get(attachments[2][i]) || DOC_SCOPE, data);
      const { fileId } = await relay.uploadFile(ciphertext);
      idents.push(makeFileIdent({ fileId, ...newRef }));
      done += sizes[i] || 0;
    }
    if (attachments[3].fileIdent) { attachments[3].fileIdent = idents; }

    onProgress(0.9, "saving");
    const payload = await sealInitialSnapshot(tables, privacy, keyring, docKey.keyId);
    await relay.call("initializeEncryptedDoc",
      { docKey, columnKeys, snapshot: await relay.send(payload) });
    onProgress(1, "done");
    const missing = copyMembers.filter(m => !docRecipients.includes(m));
    return { waitingMembers: missing.map(m => m.name || m.email) };
  } finally {
    await relay.close().catch(() => {});
    comm.releaseDocConnection(newDocId);
  }
}

/**
 * The first snapshot of an encrypted document (see encryptDocument() and copyDocument()):
 * its tables, with private values sealed with their columns' keys, encrypted with the document key.
 */
async function sealInitialSnapshot(tables: Tables, privacy: ColumnPrivacy, keyring: Keyring,
  docKeyId: string): Promise<Uint8Array> {
  const blobs = new BlobTable();
  const ctx: MetaContext = {
    rows: new MetaRows((tableId, rowId, colId) => {
      const table = tables[tableId];
      const index = table ? table[2].indexOf(rowId) : -1;
      return index >= 0 ? table[3][colId]?.[index] : undefined;
    }),
    keyScope: id => keyring.getKey(id)?.scope,
  };
  const sealed = await sealTables(tables, privacy, keyring, 0, blobs, ctx, new SealedCells().makeCarrier(() => "Any"));
  return encryptSnapshot(keyring, docKeyId, {
    v: 1, actionNum: 0, tables: sealed, ...(blobs.blobs.length > 0 ? { blobs: blobs.blobs } : {}),
    keyHistory: await keyring.initHistory(),
  });
}

/** What reading answers to forms needs (see FormSpecs.readFormAnswers()). */
export function makeFormAnswerHelpers(relay: CommRelay, keyring: Keyring): FormAnswerHelpers {
  return {
    getPrivateKey: async (keys) => {
      if (keys.privateKey) { return keys.privateKey; }
      if (!keys.sealedPrivateKey) { return null; }
      if (!keys.sealedPrivateKey.keyIds.every(keyId => keyring.holds(keyId))) { return null; }
      return utf8Decode(await keyring.decryptWithAll(keys.sealedPrivateKey.keyIds,
        base64ToBytes(keys.sealedPrivateKey.data)));
    },
    storeFile: async (file, scope) => {
      const first: { payload: Base64, size: number } =
        await relay.call("fetchEncryptedInboxFile", file.fileId, 0, ENCRYPTED_PART_BYTES);
      const payload = first.size <= ENCRYPTED_PART_BYTES ? base64ToBytes(first.payload) :
        await relay.receive(first.size, async (offset, length) => offset === 0 ? first.payload :
          (await relay.call("fetchEncryptedInboxFile", file.fileId, offset, length)).payload);
      const data = await decryptFormFile(file.key, payload);
      const { ciphertext, ref } = await encryptFile(keyring, scope, data);
      const { fileId } = await relay.uploadFile(ciphertext);
      return makeFileIdent({ fileId, ...ref });
    },
  };
}

/**
 * Which attachments are in private columns (and so get encrypted with their keys): attachment id
 * -> scope. Those also in columns everyone can read stay under the document key.
 */
function getAttachmentScopes(tables: Tables, privacy: ColumnPrivacy): Map<number, string> {
  const result = new Map<number, string>();
  const shared = new Set<number>();
  const columns = tables._grist_Tables_column;
  const tableIds = new Map(tables._grist_Tables[2].map((ref, i) => [ref, String(tables._grist_Tables[3].tableId[i])]));
  columns[2].forEach((_, i) => {
    if (columns[3].type[i] !== "Attachments") { return; }
    const tableId = tableIds.get(columns[3].parentId[i] as number);
    const colId = String(columns[3].colId[i]);
    const values = tableId ? tables[tableId]?.[3][colId] : undefined;
    if (!tableId || !values) { return; }
    const scope = privacy.scopesOf(tableId, colId)[0];
    for (const value of values) {
      if (!Array.isArray(value) || value[0] !== "L") { continue; }
      for (const attId of value.slice(1) as number[]) {
        if (scope) { result.set(attId, scope); } else { shared.add(attId); }
      }
    }
  });
  for (const attId of shared) { result.delete(attId); }
  return result;
}

function setColumn(table: TableDataAction | undefined, colId: string, fn: (rowId: number, value: any) => any) {
  if (!table?.[3][colId]) { return; }
  table[3][colId] = table[3][colId].map((value, i) => fn(table[2][i], value));
}

function mapColumns(columns: Record<string, unknown>, fn: () => any[]) {
  return Object.fromEntries(Object.keys(columns).map(colId => [colId, fn()]));
}

async function fetchByParts(size: number,
  fetchPart: (offset: number, length: number) => Promise<{ payload: Base64 }>): Promise<Uint8Array> {
  const result = new Uint8Array(size);
  for (let offset = 0; offset < size || offset === 0; offset += ENCRYPTED_PART_BYTES) {
    const part = base64ToBytes((await fetchPart(offset, Math.min(ENCRYPTED_PART_BYTES, Math.max(size - offset, 1))))
      .payload);
    if (offset + part.length > size) { throw new Error("Invalid content received from the server"); }
    result.set(part, offset);
    if (size === 0) { break; }
  }
  return result;
}
