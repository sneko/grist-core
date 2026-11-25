/**
 * The "mock" provider: a stand-in with a hardcoded key (MockKeyVault, in app/common so that server
 * tests use it too). It exercises the whole flow but protects nothing: tests and development only,
 * which the server enforces (see app/server/lib/encryption/encryptionProviders.ts).
 */
import { IKeyVault, MockKeyVault } from "app/common/encryption/EncryptionCrypto";
import { MockEncryptionProviderConfig } from "app/common/gristUrls";

export async function createMockKeyVault(config: MockEncryptionProviderConfig): Promise<IKeyVault> {
  console.warn("Encrypted documents use a stand-in for the encryption service, with a known key: " +
    "INSECURE, for tests and development only");
  return new MockKeyVault({ keyHex: config.key });
}
