/**
 * Access to users' encryption keys, for end-to-end encrypted documents.
 *
 * Keys are held by the LaSuite encryption service, in a vault iframe served from its own origin:
 * Grist never sees them. Its client SDK (client.js, loaded from the vault's origin as other
 * LaSuite products do) does the key wrapping, encryption and decryption on Grist's behalf.
 *
 * For tests and development, GRIST_ENCRYPTION_MOCK_VAULT replaces it with MockKeyVault, which uses
 * a hardcoded key.
 */
import { IKeyVault, KeyRecipient, MockKeyVault, WrappedKey } from "app/common/encryption/EncryptionCrypto";
import { EncryptionClientConfig } from "app/common/gristUrls";

/** The subset of the encryption service's VaultClient that Grist uses. */
interface VaultClient {
  init(): Promise<void>;
  setAuthContext(context: { suiteUserId: string }): void;
  hasKeys(): Promise<{ hasKeys: boolean }>;
  openOnboarding(): void;
  on(event: string, listener: (data: any) => void): void;
  fetchPublicKeys(subs: string[]): Promise<Record<string, { verified: boolean, version: number }>>;
  encryptWithoutKey(data: ArrayBuffer, recipients: Record<string, { email: string, name?: string }>):
  Promise<{ encryptedContent: ArrayBuffer, encryptedKeys: Record<string, ArrayBuffer> }>;
  shareKeys(encryptedSymmetricKey: ArrayBuffer, recipients: Record<string, { email: string, name?: string }>):
  Promise<{ encryptedKeys: Record<string, ArrayBuffer> }>;
  encryptWithKey(data: ArrayBuffer, encryptedSymmetricKey: ArrayBuffer): Promise<{ encryptedData: ArrayBuffer }>;
  decryptWithKey(encryptedData: ArrayBuffer, encryptedSymmetricKey: ArrayBuffer, keyVersion: number,
    encryptedKeyChain?: ArrayBuffer[]): Promise<{ data: ArrayBuffer }>;
  encryptNestedWithoutKey(data: ArrayBuffer, encryptedSymmetricKey: ArrayBuffer, encryptedKeyChain?: ArrayBuffer[]):
  Promise<{ encryptedContent: ArrayBuffer, wrappedKey: ArrayBuffer }>;
}

declare global {
  interface Window {
    EncryptionClient?: { VaultClient: new (options: object) => VaultClient };
  }
}

let _vault: Promise<IKeyVault> | undefined;
let _vaultUserId: string | null | undefined;

/**
 * Returns the vault for the current user (identified to the encryption service by vaultUserId,
 * their OIDC subject).
 */
export function getKeyVault(config: EncryptionClientConfig, vaultUserId: string | null): Promise<IKeyVault> {
  if (_vault && _vaultUserId === vaultUserId) { return _vault; }
  _vaultUserId = vaultUserId;
  const vault: Promise<IKeyVault> = config.mockVault ?
    Promise.resolve(new MockKeyVault({ keyHex: config.mockKey })) :
    ServiceKeyVault.create(config, vaultUserId);
  vault.catch(() => { if (_vault === vault) { _vault = undefined; } });
  _vault = vault;
  return vault;
}

class ServiceKeyVault implements IKeyVault {
  public static async create(config: EncryptionClientConfig, vaultUserId: string | null): Promise<ServiceKeyVault> {
    if (!config.vaultUrl || !config.interfaceUrl) { throw new Error("Encryption service is not configured"); }
    if (!vaultUserId) {
      throw new Error("Your account is not known to the encryption service (no identity provider subject)");
    }
    await loadScript(`${config.vaultUrl.replace(/\/$/, "")}/client.js`);
    const VaultClientClass = window.EncryptionClient?.VaultClient;
    if (!VaultClientClass) { throw new Error("Encryption service client failed to load"); }
    const client = new VaultClientClass({
      vaultUrl: config.vaultUrl,
      interfaceUrl: config.interfaceUrl,
      lang: document.documentElement.lang || navigator.language,
    });
    await client.init();
    client.setAuthContext({ suiteUserId: vaultUserId });
    return new ServiceKeyVault(client);
  }

  private constructor(private _client: VaultClient) {}

  public async hasKeys() {
    return (await this._client.hasKeys()).hasKeys;
  }

  public openOnboarding() {
    this._client.openOnboarding();
  }

  public async getRegisteredUsers(vaultUserIds: string[]) {
    if (vaultUserIds.length === 0) { return new Set<string>(); }
    const users = await this._client.fetchPublicKeys(vaultUserIds);
    return new Set(Object.entries(users).filter(([, u]) => u.verified).map(([id]) => id));
  }

  public async createDocumentKey(recipients: KeyRecipient[]) {
    // The vault mints a key only along with content to encrypt: give it none.
    const { encryptedKeys } = await this._client.encryptWithoutKey(new ArrayBuffer(0), toLabels(recipients));
    return this._withVersions(recipients, encryptedKeys);
  }

  public async shareDocumentKey(myKey: WrappedKey, recipients: KeyRecipient[]) {
    const { encryptedKeys } = await this._client.shareKeys(toArrayBuffer(myKey.wrappedKey), toLabels(recipients));
    return this._withVersions(recipients, encryptedKeys);
  }

  public async encrypt(data: Uint8Array, myKey: WrappedKey) {
    const { encryptedData } = await this._client.encryptWithKey(toArrayBuffer(data), toArrayBuffer(myKey.wrappedKey));
    return new Uint8Array(encryptedData);
  }

  public async decrypt(data: Uint8Array, myKey: WrappedKey) {
    const { data: plaintext } = await this._client.decryptWithKey(toArrayBuffer(data),
      toArrayBuffer(myKey.wrappedKey), myKey.keyVersion);
    return new Uint8Array(plaintext);
  }

  // Like files in an encrypted folder in Drive: a key of its own, wrapped with the parent key.
  public async encryptWithNewKey(data: Uint8Array, parentKey: WrappedKey) {
    const { encryptedContent, wrappedKey } = await this._client.encryptNestedWithoutKey(toArrayBuffer(data),
      toArrayBuffer(parentKey.wrappedKey));
    return { ciphertext: new Uint8Array(encryptedContent), nestedKey: new Uint8Array(wrappedKey) };
  }

  public async decryptWithNestedKey(ciphertext: Uint8Array, parentKey: WrappedKey, nestedKey: Uint8Array) {
    const { data } = await this._client.decryptWithKey(toArrayBuffer(ciphertext), toArrayBuffer(parentKey.wrappedKey),
      parentKey.keyVersion, [toArrayBuffer(nestedKey)]);
    return new Uint8Array(data);
  }

  // A wrap is only usable with the version of the recipient's key it was made against.
  private async _withVersions(recipients: KeyRecipient[], encryptedKeys: Record<string, ArrayBuffer>) {
    const users = await this._client.fetchPublicKeys(recipients.map(r => r.vaultUserId));
    const result = new Map<string, WrappedKey>();
    for (const [vaultUserId, wrappedKey] of Object.entries(encryptedKeys)) {
      result.set(vaultUserId, { wrappedKey: new Uint8Array(wrappedKey), keyVersion: users[vaultUserId]?.version ?? 1 });
    }
    return result;
  }
}

function toLabels(recipients: KeyRecipient[]) {
  return Object.fromEntries(recipients.map(r => [r.vaultUserId, { email: r.email, name: r.name }]));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function loadScript(src: string): Promise<void> {
  if (window.EncryptionClient?.VaultClient) { return Promise.resolve(); }
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Failed to load the encryption service client"));
    document.head.appendChild(script);
  });
}
