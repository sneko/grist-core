/**
 * The plaintext structures of an end-to-end encrypted document, before encryption: the changes
 * ("bundles") and the snapshots. Both are serialized with Grist's marshal format (as used to talk
 * to the data engine), which preserves value types more faithfully than JSON (e.g. NaN, or the
 * distinction between ints and floats).
 */
import { ActionInfo } from "app/common/ActionBundle";
import { DocAction, TableDataAction, UserAction } from "app/common/DocActions";
import { SealedBlob } from "app/common/encryption/ColumnPrivacy";
import { gunzip, gzip } from "app/common/encryption/EncryptionCrypto";
import { Keyring } from "app/common/encryption/Keyring";
import * as marshal from "app/common/marshal";

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
}

function marshalValue(value: unknown): Uint8Array {
  const marshaller = new marshal.Marshaller({ stringToBuffer: false, version: 2 });
  marshaller.marshal(value);
  return marshaller.dump();
}

function unmarshalValue(bytes: Uint8Array): any {
  return marshal.loads(bytes, { bufferToString: true });
}

export async function encryptBundle(keyring: Keyring, keyId: string, bundle: DocChangeBundle): Promise<Uint8Array> {
  return keyring.encrypt(keyId, marshalValue(bundle));
}

export async function decryptBundle(keyring: Keyring, keyId: string, payload: Uint8Array): Promise<DocChangeBundle> {
  const bundle = unmarshalValue(await keyring.decrypt(keyId, payload));
  if (bundle?.v !== 1) { throw new Error("Unsupported encrypted change format"); }
  return bundle;
}

export async function encryptSnapshot(keyring: Keyring, keyId: string,
  snapshot: DocSnapshotPayload): Promise<Uint8Array> {
  // Snapshots are compressed (unlike changes, which are small): ciphertext doesn't compress.
  return keyring.encrypt(keyId, await gzip(marshalValue(snapshot)));
}

export async function decryptSnapshot(keyring: Keyring, keyId: string,
  payload: Uint8Array): Promise<DocSnapshotPayload> {
  const snapshot = unmarshalValue(await gunzip(await keyring.decrypt(keyId, payload)));
  if (snapshot?.v !== 1) { throw new Error("Unsupported encrypted snapshot format"); }
  return snapshot;
}
