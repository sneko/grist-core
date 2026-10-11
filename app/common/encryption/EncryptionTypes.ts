/**
 * Types shared between the browser and the server for encrypted documents (end-to-end encrypted,
 * as in LaSuite Docs and Drive).
 *
 * The server stores and relays only ciphertext. The data engine runs in the browser; each change
 * is computed there, encrypted, and sent to the server, which orders changes (accepting a change
 * only if it was computed on top of the latest one) and forwards them to the other browsers that
 * have the document open. Browsers periodically save an encrypted snapshot of the whole document,
 * so that opening it doesn't require replaying its whole history.
 *
 * Keys. Content is encrypted with keys identified by a keyId, each for a scope:
 *  - "doc": the document key, for the document as a whole. All members hold it.
 *  - "column:<id>": the key of a private column, whose values only some members can read.
 *    Which column a scope protects, and since when, is kept by the server (ScopeBinding), so that
 *    only owners holding the key can make the column public again: the document itself can be
 *    changed by any member holding the document key.
 * A scope's key is replaced ("rotated") after someone who held it lost access to it: its
 * current key is then flagged rotateOnNextEdit, and the next member to edit the document creates
 * a new key for the scope, given to those who still have access. Older keys stay, to read older
 * content. Attachments get a key of their own each, wrapped with the key of the document (or of
 * their private column) at the time they were added; as they never change, they never need a
 * new key.
 *
 * The encryption service wraps each key for each member who may use it; members' wrapped copies
 * are what the server stores in the home database, as Docs and Drive do in their access lists.
 */

/** Stored in the home database, in docs.options.encryption, for documents that are encrypted. */
export interface DocEncryptionOptions {
  version: 1;
}

/**
 * Whether a document (given its home database options) is encrypted. Takes any resource (sites
 * and workspaces never are).
 */
export function isEncryptedDoc(doc: object | null | undefined): boolean {
  type WithOptions = { options?: { encryption?: DocEncryptionOptions | null } | null } | null | undefined;
  return Boolean((doc as WithOptions)?.options?.encryption);
}

export const ENCRYPTED_DOC_SERVER_ERROR = "This document is end-to-end encrypted: " +
  "its content is only available in the browsers of its members";

/** The scope of the document key. Private columns use "column:<id>". */
export const DOC_SCOPE = "doc";

export function isColumnScope(scope: string) {
  return scope.startsWith("column:");
}

/** Describes the engine assets served by the server (see app/server/lib/encryption/engineAssets.ts). */
export interface EngineManifest {
  version: string;
  packages: string[];
}

/** Ciphertext travels as base64 strings, so that it fits in the JSON-based Comm protocol. */
export type Base64 = string;

/**
 * Snapshots and files bigger than this travel by parts of this size (a websocket message can't
 * exceed 100MB).
 */
export const ENCRYPTED_PART_BYTES = 8 * 1024 * 1024;

/**
 * An entry of the document's history, as stored and relayed by the server:
 *  - "change": a change, encrypted with the document key keyId;
 *  - "key": the creation of a new key keyId (e.g. after the previous one of its scope got
 *    retired), with no payload. Entries after it use the new key;
 *  - "restore": the document's content was replaced (with an earlier version of it): it's the
 *    snapshot saved with this entry, encrypted with keyId. No payload.
 */
export interface EncryptedActionRecord {
  actionNum: number;     // Position in the document's history, starting at 1.
  kind: "change" | "key" | "restore";
  keyId: string;
  payload: Base64;       // Encrypted marshalled DocChangeBundle (empty for "key" entries).
  userId: number | null; // Who pushed it (as identified by the server).
  timeMs: number;        // When the server accepted it.
}

/** An encrypted snapshot of the whole document as of actionNum, encrypted with keyId. */
export interface EncryptedSnapshotRecord {
  actionNum: number;
  keyId: string;
  // The encrypted snapshot, if small enough to be returned whole. Otherwise empty: it's fetched
  // by parts (fetchEncryptedSnapshot), up to `size` bytes.
  payload: Base64;
  size: number;
  timeMs: number;
}

/** A snapshot kept by the server (without its payload), e.g. to restore it. */
export interface EncryptedSnapshotInfo {
  actionNum: number;
  keyId: string;
  size: number;
  userId: number | null;    // Who saved it.
  timeMs: number;           // When it was saved.
}

/**
 * Changes suggested by a member (e.g. a viewer, when the document accepts suggestions), until a
 * member who can edit the document applies them or dismisses them. Its payload is an encrypted
 * marshalled SuggestionBundle (see EncryptedPayloads.ts), encrypted with the document key keyId.
 */
export interface EncryptedSuggestion {
  id: number;
  keyId: string;
  payload: Base64;
  userId: number | null;     // Who suggested it (as identified by the server).
  timeMs: number;
}

/**
 * An answer to a form of an encrypted document, encrypted for the form (see EncryptedForms.ts),
 * waiting to be added to the document by a member who can edit it.
 */
export interface EncryptedInboxEntry {
  id: number;
  formId: string;
  payload: Base64;
  timeMs: number;
}

/** A payload as given to the server: inline, or uploaded by parts first (beginEncryptedUpload). */
export type PayloadSource = Base64 | { uploadId: string };

/** A key of the document (without its value, which only members get, wrapped for them). */
export interface DocKeyInfo {
  keyId: string;
  scope: string;
  current: boolean;          // Whether it's the key to use for its scope (vs. one kept for older content).
  rotateOnNextEdit: boolean;
  actionNum: number;         // The entry of the history where it took effect (0 for the first key).
}

/**
 * A private column: values of the column colRef (its row id in _grist_Tables_column) are
 * protected by the scope's keys, for the entries of the history after boundAt (the entry that
 * created the scope's first key) and before releasedAt (when the column was made public again).
 */
export interface ScopeBinding {
  scope: string;
  colRef: number;
  boundAt: number;
  releasedAt: number | null;
}

/**
 * What members recorded of the document's keys and private columns, as opposed to what the server
 * says (which a malicious server could change, e.g. to make a private column public, or to get
 * members to use a key it made). It's kept within the encrypted document (in snapshots, and in
 * the history's key entries, see KeyChangeRecord), which the server can't forge: browsers trust
 * only keys recorded there, take the latest one of each scope as current, and treat a column as
 * private if either the server or this record says so.
 */
export interface KeyHistory {
  keys: KeyHistoryEntry[];
  bindings: ScopeBinding[];
}

export interface KeyHistoryEntry {
  keyId: string;
  scope: string;
  actionNum: number;
  // The keyId, encrypted with the key itself by its creator: members check that the copy the
  // server gives them is of that key (and not of another one with the same id).
  check?: Base64;
}

/**
 * Recorded with each key entry of the history, by the member making the change, encrypted with the
 * document key current before it (see KeyHistory).
 */
export interface KeyChangeRecord {
  v: 1;
  actionNum: number;
  scope: string;
  keyId: string;          // The new key, or the current key of the scope made public.
  check?: Base64;         // For a new key (see KeyHistoryEntry).
  colRef?: number;        // For the first key of a column scope: the column made private.
  release?: boolean;      // For a column made public again.
}

/** A member's copy of a key, wrapped for them by the encryption service. */
export interface DocKeyRecord {
  keyId: string;
  userId: number;
  wrappedKey: Base64;
  keyVersion: number;   // The version of the member's encryption key the wrap was made against.
}

/** A member of the document, with the keys they hold. */
export interface EncryptionMember {
  userId: number;
  email: string;
  name: string;
  access: string;
  // The identifier the encryption service knows the user by (their OIDC subject), when known.
  vaultUserId: string | null;
  keyIds: string[];
}

/** The keys of a document, and the caller's copies of them. */
export interface EncryptionKeysResult {
  keys: DocKeyInfo[];
  myKeys: DocKeyRecord[];
  bindings: ScopeBinding[];
}

/** Returned by openEncryptedDoc. */
export interface EncryptedDocOpenResult extends EncryptionKeysResult {
  // The latest snapshot (if any), and all actions after it.
  snapshot: EncryptedSnapshotRecord | null;
  actions: EncryptedActionRecord[];
  head: number;                 // actionNum of the latest action (0 if none).
  access: string;               // The caller's role: "owners", "editors" or "viewers".
  user: {
    id: number | null;
    email: string | null;
    name: string | null;
    ref: string | null;
    vaultUserId: string | null;
  };
}

/** Returned by pushEncryptedAction and createEncryptionKey. */
export type EncryptedPushResult =
  { accepted: true, actionNum: number, timeMs: number } |
  // Not computed on top of the latest change (or with an outdated key): the caller must catch up
  // and retry.
  { accepted: false, head: number };

/** Passed to createEncryptionKey. */
export interface NewKeyRequest {
  scope: string;
  keyId: string;
  wraps: Omit<DocKeyRecord, "keyId">[];
  // For a new key of an existing scope: the latest change known to the caller (as for
  // pushEncryptedAction). The key change gets recorded right after it.
  baseActionNum: number;
  // For the first key of a column scope: the column it makes private.
  colRef?: number;
  // The encrypted KeyChangeRecord (see KeyHistory), recorded as the history entry's payload.
  record?: Base64;
  // A snapshot of the document as of the key change, saved along with it (encrypted with the
  // document key current after it), so that both happen together or not at all. With
  // `compact`, older snapshots and changes are dropped (by owners, e.g. when making a column
  // private, so that its values aren't available anymore in readable form).
  snapshot?: PayloadSource;
  compact?: boolean;
}

/** Broadcast by the server to browsers that have the document open, for each new entry. */
export interface EncryptedActionMessage {
  docId: string;
  action: EncryptedActionRecord;
}

/**
 * Why a document is locked by a member for a while (others can't change it meanwhile):
 *  - "encrypting", "decrypting": the document is being converted to or from encryption;
 *  - "restoring": an earlier version of the document is being restored.
 */
export interface DocLockInfo {
  reason: "encrypting" | "decrypting" | "restoring";
  userName: string;
}

/**
 * Broadcast to browsers that have an encrypted document open when it gets locked (`lock` set),
 * unlocked (`lock` null), or when it stopped being encrypted (`decrypted` set: it must be opened
 * again, as a regular document).
 */
export interface EncryptedLockMessage {
  docId: string;
  lock: DocLockInfo | null;
  decrypted?: boolean;
}

/** Broadcast when keys change, e.g. so that a member waiting for a key can proceed. */
export interface EncryptedKeysMessage {
  docId: string;
}

/** Files that can be imported into encrypted documents (parsed in the browser, see LocalImport.ts). */
export const LOCAL_IMPORT_EXTENSIONS = [".csv", ".tsv", ".txt", ".dsv", ".xlsx", ".xlsm", ".json"];

/** Generates a random identifier for a new key. */
export function makeKeyId(scope: string): string {
  const random = Array.from(crypto.getRandomValues(new Uint8Array(12)), b => b.toString(16).padStart(2, "0")).join("");
  return `${scope}~${random}`;
}

/** Generates a random identifier for a new private-columns scope. */
export function makeColumnScope(): string {
  const random = Array.from(crypto.getRandomValues(new Uint8Array(9)), b => b.toString(16).padStart(2, "0")).join("");
  return `column:${random}`;
}
