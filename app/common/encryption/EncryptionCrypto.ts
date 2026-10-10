/**
 * Cryptographic plumbing for end-to-end encrypted documents, usable both in browsers and in Node
 * (which provides the same WebCrypto and CompressionStream globals).
 *
 * Document content is encrypted with a per-document key (DEK). That key never reaches Grist:
 * it lives in the user's vault (the LaSuite encryption service), which only hands out copies of
 * it wrapped for each user, and does the encryption and decryption itself. IKeyVault is how
 * Grist talks to it; MockKeyVault stands in for it in tests and development, using a hardcoded key.
 */

/** A copy of the document key, wrapped (encrypted) for one user. */
export interface WrappedKey {
  wrappedKey: Uint8Array;
  // Version of the recipient's encryption key the wrap was made against; the vault needs it to
  // pick the right private key when unwrapping.
  keyVersion: number;
}

/** Someone a document key gets wrapped for. */
export interface KeyRecipient {
  vaultUserId: string;   // How the encryption service identifies the user (their OIDC subject).
  email: string;
  name?: string;
}

export interface IKeyVault {
  /** Whether the current user has encryption keys available on this device. */
  hasKeys(): Promise<boolean>;
  /** Asks the user to set up (or restore) their encryption keys, e.g. in the vault's interface. */
  openOnboarding?(): void;
  /** Which of these users have registered encryption keys (and so can receive a document key). */
  getRegisteredUsers(vaultUserIds: string[]): Promise<Set<string>>;
  /** Mints a new document key, wrapped for each recipient. Returns wraps keyed by vaultUserId. */
  createDocumentKey(recipients: KeyRecipient[]): Promise<Map<string, WrappedKey>>;
  /** Wraps an existing document key (given the caller's own wrap of it) for more recipients. */
  shareDocumentKey(myKey: WrappedKey, recipients: KeyRecipient[]): Promise<Map<string, WrappedKey>>;
  encrypt(data: Uint8Array, myKey: WrappedKey): Promise<Uint8Array>;
  decrypt(data: Uint8Array, myKey: WrappedKey): Promise<Uint8Array>;
  /**
   * Encrypts data with a new key of its own, returned wrapped with the given key (as Drive does
   * for files in an encrypted folder). Used for attachments, which never change.
   */
  encryptWithNewKey(data: Uint8Array, parentKey: WrappedKey):
  Promise<{ ciphertext: Uint8Array, nestedKey: Uint8Array }>;
  /** Decrypts data encrypted by encryptWithNewKey(), given its key and the key it's wrapped with. */
  decryptWithNestedKey(ciphertext: Uint8Array, parentKey: WrappedKey, nestedKey: Uint8Array): Promise<Uint8Array>;
}

/** Encrypts and decrypts one document's content (a vault bound to the user's copy of the key). */
export interface IDocCipher {
  encrypt(data: Uint8Array): Promise<Uint8Array>;
  decrypt(data: Uint8Array): Promise<Uint8Array>;
}

export function makeDocCipher(vault: IKeyVault, myKey: WrappedKey): IDocCipher {
  return {
    encrypt: data => vault.encrypt(data, myKey),
    decrypt: data => vault.decrypt(data, myKey),
  };
}

/**
 * A stand-in for the encryption service, for tests and local development. It exercises all the
 * code paths of a real vault (keys per user, missing keys, encryption of all content), without
 * any of its security: each document key is random, but "wrapped" for users with a hardcoded key
 * (so anyone knowing it can unwrap any key), and labelled with the user it's for.
 */
export class MockKeyVault implements IKeyVault {
  // 256-bit AES key, hex-encoded. Deliberately public: this vault provides no security.
  public static readonly DEFAULT_KEY_HEX = "4772697374453245452d6d6f636b2d6b65792d666f722d74657374732d6f6e6c";

  private _masterKey: Promise<CryptoKey>;
  private _isRegistered: (vaultUserId: string) => boolean;
  private _hasKeys: () => boolean;
  private _keys = new Map<string, Promise<CryptoKey>>();

  constructor(options: {
    keyHex?: string,
    // Users considered registered with the (mock) encryption service; all of them if omitted.
    registeredUsers?: (vaultUserId: string) => boolean,
    hasKeys?: () => boolean,
  } = {}) {
    this._masterKey = importAesKey(hexToBytes(options.keyHex || MockKeyVault.DEFAULT_KEY_HEX));
    this._isRegistered = options.registeredUsers || (() => true);
    this._hasKeys = options.hasKeys || (() => true);
  }

  public async hasKeys() { return this._hasKeys(); }

  public async getRegisteredUsers(vaultUserIds: string[]) {
    return new Set(vaultUserIds.filter(id => this._isRegistered(id)));
  }

  public async createDocumentKey(recipients: KeyRecipient[]) {
    return this._wrapFor(crypto.getRandomValues(new Uint8Array(32)), recipients);
  }

  public async shareDocumentKey(myKey: WrappedKey, recipients: KeyRecipient[]) {
    return this._wrapFor(await this._unwrap(myKey), recipients);
  }

  public async encrypt(data: Uint8Array, myKey: WrappedKey): Promise<Uint8Array> {
    return aesEncrypt(await this._getKey(myKey), data);
  }

  public async decrypt(data: Uint8Array, myKey: WrappedKey): Promise<Uint8Array> {
    return aesDecrypt(await this._getKey(myKey), data);
  }

  public async encryptWithNewKey(data: Uint8Array, parentKey: WrappedKey) {
    const rawKey = crypto.getRandomValues(new Uint8Array(32));
    return {
      ciphertext: await aesEncrypt(await importAesKey(rawKey), data),
      nestedKey: await aesEncrypt(await this._getKey(parentKey), rawKey),
    };
  }

  public async decryptWithNestedKey(ciphertext: Uint8Array, parentKey: WrappedKey, nestedKey: Uint8Array) {
    const rawKey = await aesDecrypt(await this._getKey(parentKey), nestedKey);
    return aesDecrypt(await importAesKey(rawKey), ciphertext);
  }

  private async _wrapFor(rawKey: Uint8Array, recipients: KeyRecipient[]) {
    const wrapped = bytesToBase64(await aesEncrypt(await this._masterKey, rawKey));
    const result = new Map<string, WrappedKey>();
    for (const r of recipients) {
      if (!this._isRegistered(r.vaultUserId)) { continue; }
      result.set(r.vaultUserId, { wrappedKey: utf8Encode(`mock-wrap:${r.vaultUserId}:${wrapped}`), keyVersion: 1 });
    }
    return result;
  }

  private async _unwrap(myKey: WrappedKey): Promise<Uint8Array> {
    const match = /^mock-wrap:.*:([A-Za-z0-9+/=]+)$/.exec(utf8Decode(myKey.wrappedKey));
    if (!match) { throw new Error("MockKeyVault: not a key wrapped by this vault"); }
    return aesDecrypt(await this._masterKey, base64ToBytes(match[1]));
  }

  private _getKey(myKey: WrappedKey): Promise<CryptoKey> {
    const id = utf8Decode(myKey.wrappedKey);
    let key = this._keys.get(id);
    if (!key) {
      key = this._unwrap(myKey).then(importAesKey);
      key.catch(() => this._keys.delete(id));
      this._keys.set(id, key);
    }
    return key;
  }
}

function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", asBufferSource(rawKey), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// AES-GCM, with the 12-byte IV prepended to the ciphertext.
async function aesEncrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, asBufferSource(data)));
  return concatBytes(iv, ciphertext);
}

async function aesDecrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const iv = asBufferSource(data.subarray(0, 12));
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, asBufferSource(data.subarray(12))));
}

// Typed arrays may in principle be backed by a SharedArrayBuffer, which WebCrypto's typings reject.
// Ours never are.
function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as BufferSource;
}

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^([0-9a-fA-F]{2})*$/.test(hex)) { throw new Error("Invalid hex string"); }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    result.set(p, offset);
    offset += p.length;
  }
  return result;
}

export function bytesToBase64(bytes: Uint8Array): string {
  // String.fromCharCode() takes arguments, so convert in chunks to stay under argument limits.
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk) as unknown as number[]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(data))));
}

async function pipeThrough(data: Uint8Array, transform: GenericTransformStream): Promise<Uint8Array> {
  const stream = new Blob([asBufferSource(data)]).stream().pipeThrough(transform);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function gzip(data: Uint8Array): Promise<Uint8Array> {
  return pipeThrough(data, new CompressionStream("gzip"));
}

export function gunzip(data: Uint8Array): Promise<Uint8Array> {
  return pipeThrough(data, new DecompressionStream("gzip"));
}
