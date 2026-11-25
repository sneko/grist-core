/**
 * Access to users' encryption keys, for end-to-end encrypted documents, through the provider the
 * server is configured with (GRIST_ENCRYPTION_PROVIDER, see EncryptionProviderConfig in
 * app/common/gristUrls.ts). Each provider gives an IKeyVault (app/common/encryption/EncryptionCrypto.ts),
 * the contract the rest of the encryption code relies on: it mints documents' keys wrapped for each
 * member, shares them with more members, and encrypts and decrypts with them.
 *
 * Adding a provider: its settings in EncryptionProviderConfig, its server side in
 * app/server/lib/encryption/encryptionProviders.ts, and its vault in ./providers, created in makeKeyVault() below.
 */
import { createLaSuiteKeyVault } from "app/client/encryption/providers/lasuite";
import { createMockKeyVault } from "app/client/encryption/providers/mock";
import { gristThemeObs } from "app/client/ui2018/theme";
import { IKeyVault } from "app/common/encryption/EncryptionCrypto";
import { EncryptionClientConfig, EncryptionProviderConfig } from "app/common/gristUrls";
import { Theme } from "app/common/ThemePrefs";

let _vault: Promise<IKeyVault> | undefined;
let _vaultUserId: string | null | undefined;

/**
 * Returns the vault for the current user, identified to the provider by vaultUserId (which the
 * server computes, see encryptionUserIdFor()).
 */
export function getKeyVault(config: EncryptionClientConfig, vaultUserId: string | null): Promise<IKeyVault> {
  if (_vault && _vaultUserId === vaultUserId) { return _vault; }
  _vaultUserId = vaultUserId;
  const vault = makeKeyVault(config.provider, vaultUserId);
  vault.catch(() => { if (_vault === vault) { _vault = undefined; } });
  _vault = vault;
  return vault;
}

function makeKeyVault(provider: EncryptionProviderConfig, vaultUserId: string | null): Promise<IKeyVault> {
  switch (provider.kind) {
    case "lasuite": return createLaSuiteKeyVault(provider, vaultUserId, {
      current: interfaceTheme(gristThemeObs().get()),
      onChange: listener => gristThemeObs().addListener(theme => listener(interfaceTheme(theme))),
    });
    case "mock": return createMockKeyVault(provider);
    default: {
      // (A provider the server knows but this client doesn't: a mismatch between them.)
      const unknown: never = provider;
      return Promise.reject(new Error(`Unknown encryption provider: ${(unknown as { kind: string }).kind}`));
    }
  }
}

// The LaSuite encryption service's interface uses Cunningham themes: match Grist's light or dark appearance.
function interfaceTheme(theme: Theme): string {
  return theme.appearance === "dark" ? "dark" : "default";
}
