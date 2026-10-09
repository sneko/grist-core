/**
 * Attachments of encrypted documents. Each file is encrypted with a key of its own (as Drive
 * does), which is wrapped with the current key of the document, or of the private column the
 * file is attached in. The encrypted file is stored by the server; the reference to it, with
 * its wrapped key, is in the attachment's metadata (in fileIdent), which is part of the encrypted
 * document.
 *
 * Files never change, so their keys never need replacing: someone who lost access may still
 * have read a file they had access to, but they can't get its content from the server anymore.
 */
import { base64ToBytes, bytesToBase64 } from "app/common/encryption/EncryptionCrypto";
import { Keyring } from "app/common/encryption/Keyring";

const FILE_IDENT_PREFIX = "encrypted:";

/** Where an encrypted file is, and how to decrypt it. */
export interface EncryptedFileRef {
  fileId: string;      // Identifies the encrypted file on the server.
  keyId: string;       // The key the file's own key is wrapped with.
  nestedKey: string;   // The file's own key, wrapped (base64).
}

export function makeFileIdent(ref: EncryptedFileRef): string {
  return FILE_IDENT_PREFIX + bytesToBase64(new TextEncoder().encode(JSON.stringify(ref)));
}

export function parseFileIdent(fileIdent: string): EncryptedFileRef | null {
  if (!fileIdent.startsWith(FILE_IDENT_PREFIX)) { return null; }
  try {
    const ref = JSON.parse(new TextDecoder().decode(base64ToBytes(fileIdent.slice(FILE_IDENT_PREFIX.length))));
    return (typeof ref?.fileId === "string" && typeof ref.keyId === "string" && typeof ref.nestedKey === "string") ?
      ref : null;
  } catch (e) {
    return null;
  }
}

/**
 * Encrypts a file with a new key of its own, wrapped with the current key of the given scope.
 * Returns the ciphertext to store, and the reference to it (except its fileId, assigned once
 * stored).
 */
export async function encryptFile(keyring: Keyring, scope: string, data: Uint8Array) {
  const keyId = keyring.currentKeyId(scope);
  const { ciphertext, nestedKey } = await keyring.vault.encryptWithNewKey(data, await keyring.getWrap(keyId));
  return { ciphertext, ref: { keyId, nestedKey: bytesToBase64(nestedKey) } };
}

export async function decryptFile(keyring: Keyring, ref: EncryptedFileRef,
  ciphertext: Uint8Array): Promise<Uint8Array> {
  return keyring.vault.decryptWithNestedKey(ciphertext, await keyring.getWrap(ref.keyId), base64ToBytes(ref.nestedKey));
}
