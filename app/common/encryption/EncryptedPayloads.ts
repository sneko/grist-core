/**
 * The plaintext structures of an end-to-end encrypted document, before encryption: the changes
 * ("bundles") and the snapshots. Both are serialized with Grist's marshal format (as used to talk
 * to the data engine), which preserves value types more faithfully than JSON (e.g. NaN, or the
 * distinction between ints and floats).
 */
import { ActionInfo } from "app/common/ActionBundle";
import { DocAction, TableDataAction, UserAction } from "app/common/DocActions";
import { gunzip, gzip } from "app/common/encryption/EncryptionCrypto";
import { KeyChangeRecord, KeyHistory } from "app/common/encryption/EncryptionTypes";
import * as marshal from "app/common/marshal";

import type { SealedBlob } from "app/common/encryption/ColumnPrivacy";
import type { Keyring } from "app/common/encryption/Keyring";

/** One change to the document, as computed by the browser that made it. */
export interface DocChangeBundle {
  v: 1;
  userActions: UserAction[];
  // The doc actions the change consists of, including recomputed formula values.
  stored: DocAction[];
  // The inverse of `stored`, used for undo.
  undo: DocAction[];
  retValues: any[];
  info: ActionInfo;
  // Set for changes that aren't the user's own doing (e.g. updates of NOW()), not to be undone.
  internal?: boolean;
}

/**
 * The whole document, as of a given action. Values of private columns are sealed (see
 * ColumnPrivacy.ts), so the tables are only TableDataActions once unsealed.
 */
export interface DocSnapshotPayload {
  v: 1;
  actionNum: number;
  tables: { [tableId: string]: TableDataAction };
  // Sealed values referred to by columns the snapshot's author couldn't read (CarriedValues).
  blobs?: SealedBlob[];
  // What members recorded of keys and private columns as of actionNum (see KeyHistory).
  keyHistory?: KeyHistory;
}

/** Encrypts a record of a key change (see KeyChangeRecord), with the document key before it. */
export async function encryptKeyRecord(keyring: Keyring, keyId: string, record: KeyChangeRecord): Promise<Uint8Array> {
  return keyring.encrypt(keyId, marshalValue(record));
}

/** Decrypts a record of a key change (throws if it isn't one). */
export async function decryptKeyRecord(keyring: Keyring, keyId: string, payload: Uint8Array): Promise<KeyChangeRecord> {
  const record = unmarshalValue(await keyring.decrypt(keyId, payload));
  if (record?.v !== 1 || typeof record.actionNum !== "number" || typeof record.scope !== "string" ||
    typeof record.keyId !== "string") {
    throw new Error("Malformed key change record");
  }
  return record;
}

/**
 * Changes suggested by a member who can't make them (see EncryptedSuggestion): the user actions
 * to apply, which a member who can edit the document applies (computing them anew) if they agree.
 */
export interface SuggestionBundle {
  v: 1;
  userActions: UserAction[];
  desc: string;       // What the member says of their suggestion.
  time: number;
}

export async function encryptSuggestion(keyring: Keyring, keyId: string, bundle: SuggestionBundle) {
  return keyring.encrypt(keyId, await gzip(marshalValue(bundle)));
}

/** Decrypts a suggestion (made by another member: throws if it isn't shaped as one). */
export async function decryptSuggestion(keyring: Keyring, keyId: string,
  payload: Uint8Array): Promise<SuggestionBundle> {
  const bundle = unmarshalValue(await gunzip(await keyring.decrypt(keyId, payload)));
  if (bundle?.v !== 1 || !Array.isArray(bundle.userActions) ||
    !bundle.userActions.every((a: unknown) => Array.isArray(a) && typeof a[0] === "string") ||
    typeof bundle.desc !== "string" || typeof bundle.time !== "number") {
    throw new Error("Malformed suggestion");
  }
  return bundle;
}

export function marshalValue(value: unknown): Uint8Array {
  const marshaller = new marshal.Marshaller({ stringToBuffer: false, version: 2 });
  marshaller.marshal(value);
  return marshaller.dump();
}

export function unmarshalValue(bytes: Uint8Array): any {
  return marshal.loads(bytes, { bufferToString: true });
}

// Changes and snapshots are compressed before encryption (ciphertext doesn't compress).
export async function encryptBundle(keyring: Keyring, keyId: string, bundle: DocChangeBundle): Promise<Uint8Array> {
  return keyring.encrypt(keyId, await gzip(marshalValue(bundle)));
}

/**
 * Decrypts a change. Changes come from other members, possibly with modified clients: throws if
 * it isn't shaped as a change should be (the change then gets skipped, see LocalActiveDoc).
 */
export async function decryptBundle(keyring: Keyring, keyId: string, payload: Uint8Array): Promise<DocChangeBundle> {
  const bundle = unmarshalValue(await gunzip(await keyring.decrypt(keyId, payload)));
  if (bundle?.v !== 1) { throw new Error("Unsupported encrypted change format"); }
  checkBundle(bundle);
  return bundle;
}

function checkBundle(bundle: any): asserts bundle is DocChangeBundle {
  const isUserActions = (list: unknown) => Array.isArray(list) &&
    list.every(a => Array.isArray(a) && typeof a[0] === "string");
  // Doc actions all start with their name and table.
  const isDocActions = (list: unknown) => Array.isArray(list) &&
    list.every(a => Array.isArray(a) && typeof a[0] === "string" && typeof a[1] === "string");
  const info = bundle.info;
  if (!isUserActions(bundle.userActions) || !isDocActions(bundle.stored) || !isDocActions(bundle.undo) ||
    !Array.isArray(bundle.retValues) || !info || typeof info !== "object" || Array.isArray(info) ||
    typeof info.time !== "number" || typeof info.user !== "string" || typeof info.inst !== "string" ||
    typeof info.otherId !== "number" || typeof info.linkId !== "number" ||
    (info.desc !== undefined && info.desc !== null && typeof info.desc !== "string")) {
    throw new Error("Malformed encrypted change");
  }
}

export async function encryptSnapshot(keyring: Keyring, keyId: string,
  snapshot: DocSnapshotPayload): Promise<Uint8Array> {
  return keyring.encrypt(keyId, await gzip(marshalValue(snapshot)));
}

export async function decryptSnapshot(keyring: Keyring, keyId: string,
  payload: Uint8Array): Promise<DocSnapshotPayload> {
  const snapshot = unmarshalValue(await gunzip(await keyring.decrypt(keyId, payload)));
  if (snapshot?.v !== 1) { throw new Error("Unsupported encrypted snapshot format"); }
  return snapshot;
}
