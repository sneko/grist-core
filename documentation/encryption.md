# Encrypted documents

Encrypted documents are end-to-end encrypted: the server stores and relays them, but only ever
sees ciphertext. Users' keys are held by a key provider, outside of Grist's server: the first one
is the LaSuite encryption service (the same as LaSuite Docs and Drive use), whose vault runs in an
iframe of its own origin, so Grist itself never holds users' private keys. See "Key providers"
below for what a provider does, and how to add one.

## Configuration

| Variable | Meaning |
|---|---|
| `GRIST_ENCRYPTION_FEATURE_ENABLED` | `true` lets users create encrypted documents ("Add new" › "New encrypted document"). |
| `GRIST_ENCRYPTION_PROVIDER` | The key provider: `lasuite` (the default), `openbao` or `mock` (see "Key providers"). Each has its settings below. `lasuite` and `openbao` require users to sign in with OIDC (`GRIST_OIDC_IDP_ISSUER`..., and no other login system chosen or coming first, such as getgrist.com's): the server refuses to start otherwise. |
| `GRIST_ENCRYPTION_LASUITE_VAULT_URL` | `lasuite`: origin of the encryption service's vault (its `client.js` is loaded from there). Formerly `GRIST_ENCRYPTION_VAULT_URL`, still accepted. |
| `GRIST_ENCRYPTION_LASUITE_INTERFACE_URL` | `lasuite`: origin of the encryption service's interface (onboarding, key backup...). Formerly `GRIST_ENCRYPTION_INTERFACE_URL`, still accepted. |
| `GRIST_ENCRYPTION_OPENBAO_URL` | `openbao`: OpenBao's (or Vault's) origin, e.g. `https://openbao.example.com`. |
| `GRIST_ENCRYPTION_OPENBAO_AUTH_MOUNT` | `openbao`: where its OIDC auth method is mounted, under `auth/` (default `oidc`). |
| `GRIST_ENCRYPTION_OPENBAO_ROLE` | `openbao`: the OIDC role users sign in with (default `grist`). |
| `GRIST_ENCRYPTION_OPENBAO_TRANSIT_MOUNT` | `openbao`: where its transit secrets engine is mounted (default `transit`). |
| `GRIST_ENCRYPTION_OPENBAO_KEY_PREFIX` | `openbao`: users' keys are named `<prefix><OIDC subject>` (default `grist-user-`). Not empty: the policy opens every key it names to all users, so it must only name Grist's. |
| `GRIST_ENCRYPTION_MOCK_KEY` | `mock`: the hardcoded key (64 hex characters; a default is used otherwise). The `mock` provider is a stand-in using it for everyone. **No security at all: for tests and development only**, refused when `NODE_ENV=production` (as in Grist's images). |
| `GRIST_ENCRYPTION_MOCK_VAULT` | Former setting of the `mock` provider: `true` selects it when `GRIST_ENCRYPTION_PROVIDER` is unset. |
| `GRIST_ENCRYPTION_ALLOWED_WIDGETS` | Comma-separated URL prefixes of custom widgets allowed in encrypted documents (e.g. `https://widgets.example.com/`), besides those Grist serves itself. Widgets see the content of the documents they're in. |
| `GRIST_ENCRYPTION_MAX_DOC_SIZE_MB` | The most an encrypted document may take on the server, when the site's plan sets no limit (plans' data and attachments limits apply together, since the server can't tell them apart). |
| `GRIST_ENCRYPTION_ASSISTANT` | An AI service for the formula assistant of encrypted documents, which browsers call directly, as JSON: `{"endpoint": "https://…/v1/chat/completions", "model": "…", "provider": "…", "sovereign": true, "auth": "user-key"}` (an OpenAI-compatible endpoint allowing calls from browsers; `auth` is `user-key` for users to give their own API key, kept in their browser, or `none`). |

The configuration is checked on startup: mistakes stop the server rather than break pages.

With the `lasuite` provider, users are identified to the encryption service by their OIDC subject (`sub`), which Grist links
to the user on their first OIDC sign-in (for all OIDC sign-ins, not only for encrypted documents;
a user already linked to another subject, e.g. from another identity provider, keeps it). As for Docs and Drive, the encryption service and Grist
must share the identity provider (an `encryption` client in the same realm): see
`docker/encryption-dev/` for a local setup, with both the mock and the real service.

A document is encrypted from its creation (`options.encryption = {version: 1}`), or converted
later by an owner (see below).

## Key providers

A provider holds users' keys and does the cryptography with them; Grist stores and relays what it
wraps. The rest of the encryption code (collaboration, private columns, key replacement, forms,
suggestions...) only relies on its contract, so a provider can be replaced without touching it.

**The contract** is `IKeyVault` (`app/common/encryption/EncryptionCrypto.ts`), in the browser:

- `hasKeys()`, and optionally `openOnboarding()` / `openSettings()`: whether the user can use
  encryption on this device, and the provider's own setup and settings (shown by Grist when needed);
- `getRegisteredUsers(ids)`: which members can be given keys (those who set up encryption);
- `createDocumentKey(recipients)` / `shareDocumentKey(myKey, recipients)`: a new document key, or
  the caller's copy of an existing one, wrapped for each recipient (opaque bytes and a key version,
  stored by the server in `doc_encryption_key_wraps`, and handed back to that member only);
- `encrypt(data, myKey)` / `decrypt(data, myKey)`: with the caller's copy of a key;
- `encryptWithNewKey()` / `decryptWithNestedKey()`: attachments, each with a key of its own,
  wrapped with the document's.

The server needs little of a provider (`app/server/lib/encryption/encryptionProviders.ts`): its
settings, read and checked at startup and handed to browsers, and how it identifies a Grist user
(`userIdFor()`, the `vaultUserId` browsers wrap keys for).

**Adding a provider**: its settings in `EncryptionProviderConfig` (`app/common/gristUrls.ts`), its
server side in `encryptionProviders.ts`, its vault in `app/client/encryption/providers/` (created in
`makeKeyVault()`, `app/client/encryption/keyVaults.ts`), each with its tests. The `lasuite`
provider is tested against a stand-in for the service's SDK (`test/client/encryption/lasuiteProvider.ts`);
the end-to-end tests run with the `mock` one.

**The providers:**

- `lasuite`: the LaSuite encryption service ([suitenumerique/encryption](https://github.com/suitenumerique/encryption)).
  Each user has their own key pair in its vault (a browser iframe of its own origin), with its
  recovery phrase, device transfer, recovery team and emergency access; users are known by their
  OIDC subject, so Grist and the service share the identity provider.
- `openbao`: [OpenBao](https://openbao.org) (MPL-2.0), or HashiCorp Vault, whose API it shares,
  with a key for each user in its transit secrets engine (see below).
- `mock`: a stand-in, with one hardcoded key for everyone, for tests and development.

### The `openbao` provider

A simpler alternative to the LaSuite service, with an open source key management server many
organizations already run: users have no keys of their own to set up, back up or move between
devices. Signing in is enough.

- **Each user has a key in OpenBao**, created by themselves when they first sign in (only of the
  plain `aes256-gcm96` kind), named `<prefix><OIDC subject>`. Nobody else can create it, nor
  change it (but OpenBao's operators).
- **Each member's copy of a document key is the key encrypted by OpenBao with that member's key**
  (`transit/encrypt/<prefix><OIDC subject>`): OpenBao's ciphertext, `vault:v<version>:…`, stored
  as usual in `doc_encryption_key_wraps` (its version also as `key_version`, for information:
  OpenBao reads it from the ciphertext). Anyone signed in may wrap a key for anyone who has a key
  (so who signed in once: the others can't be given keys yet, as with the LaSuite service), giving
  nothing but the key to wrap; **a user may only unwrap with their own key**, so a copy is of no
  use to anyone else. The policy (`openBaoPolicy()`, `app/common/encryption/OpenBaoKeyVault.ts`)
  enforces all of it.
- **Keys can be rotated in OpenBao** (`transit/keys/<name>/rotate`): copies made with older
  versions still unwrap (until `min_decryption_version` says otherwise), new ones use the latest
  version. OpenBao's `rewrap` can bring older copies to it without revealing the keys; Grist doesn't
  do it by itself.
- **Signing in**: the first time in a browser (with "Enable encryption"), a tab opens where OpenBao
  runs the OIDC sign-in itself, as a confidential client of the identity provider Grist uses: when
  the user is signed in there, the tab closes at once; otherwise it shows the provider's form. It
  comes back to `/encryption/openbao-callback` on Grist's origin, which hands the result to the
  page, both directly and over a `BroadcastChannel` (identity providers sending
  `Cross-Origin-Opener-Policy: same-origin` sever the tab from the page); the page only takes its
  own sign-in's result (by its `state`), and finishes it with OpenBao (with a secret it kept, so
  that a code leaking from the tab is of no use). A hidden iframe couldn't do it silently: browsers
  withhold the identity provider's cookies there.
- **The token** is kept in the browser (`localStorage`, for the next pages and other tabs, which
  read it again at each use), renewed when it nears its expiry (also while a document stays open
  without calling OpenBao), and forgotten and revoked when the user signs out of Grist from its
  menu. Tokens left in the browser by another user are revoked when the next one opens an
  encrypted document. A token for another user than the one signed in to Grist is refused and
  revoked (the role must map the `sub` claim to `subject`).
- **Wrapping a key for a member OpenBao refuses** skips that member only when their key doesn't
  exist (they never signed in to OpenBao); any other refusal (a revoked token, a policy that
  doesn't match the settings) fails the operation, and a new key is never recorded without the
  user's own copy.
- **Content is encrypted in the page**, with AES-GCM under the document key (see
  `LocalCryptoKeyVault`, `app/common/encryption/EncryptionCrypto.ts`): document keys are in the
  page's memory while documents are open, where the LaSuite service keeps them in its vault's
  iframe.

**What it protects against, and what not.** Grist's server, its administrators, its database,
storage and backups only get ciphertext and wrapped keys, and the server has no token to have
them unwrapped: it can't read documents. These can:

- OpenBao's operators (they can use any user's key);
- **the identity provider's administrators**, who can sign in to OpenBao as anyone, unlike with
  the LaSuite service (where reading also needs the user's own keys); in a self-hosted
  installation, often the same people as Grist's administrators;
- a Grist server modified to serve pages that take the token or the document keys, or a script
  injected in Grist's pages (XSS), since the token and the keys are in the page (the LaSuite
  service keeps keys in an iframe of its own origin against that);
- anyone with the user's browser while the token is valid (a shared computer where the user didn't
  sign out of Grist from its menu, e.g. whose Grist session just expired): keep `token_ttl` short
  (the setup below: an hour, renewed up to 12 hours). Renewing doesn't ask the identity provider
  again: a user disabled there keeps their token until `token_max_ttl` (see "Running it", below).

Anyone signed in to OpenBao may wrap a key of their choosing for anyone (a server with an
account at the identity provider included), but that's of no use to give members a key someone
else knows: browsers only use keys members recorded, and check that their copy is of the key
recorded (see "What members record").

**Limits.**

- Subjects must be unique ignoring case: OpenBao matches users' aliases ignoring it, while keys'
  names keep it (two users `Alice` and `alice` would share an entity, and the second could
  unwrap with the first one's key). Keycloak's subjects (lowercase UUIDs) are.
- Anyone signed in can tell whether a given subject has a key, and since when (it's how Grist
  knows who can be given keys), not list them.
- Any call a user may make can have its answer kept by OpenBao for them (response wrapping), up
  to the size of a request, for as long as they ask, even after their token is revoked: OpenBao
  can only cap that by requiring wrapping. Bound it with the listener's `max_request_size` (Grist
  sends less than 1 KB), and rate limits (see "Running it").

- OpenBao names keys with letters, digits, `_`, and `.` or `-` inside, only: users whose OIDC subject has
  other characters (Keycloak users federated from LDAP, `f:…:…`; Auth0's `auth0|…`; email
  addresses) can't use encrypted documents with it, and are told so.
- The subject must be the same for Grist's and OpenBao's clients of the identity provider: not
  with "pairwise" subjects, different for each client. And it must be the same identity provider:
  OpenBao's `oidc_discovery_url` the issuer of `GRIST_OIDC_IDP_ISSUER` (subjects are only unique
  for an issuer).
- The policy names users' keys after their subject in its paths, where OpenBao reads `*` and `+`
  as wildcards: neither can be in a key's name, so subjects with them are refused, but the
  identity provider must not give them to users either (Keycloak's are UUIDs).
- Every origin users reach Grist at (team sites on subdomains, custom domains) needs its callback
  in the role's `allowed_redirect_uris` and at the identity provider, and CORS for it; tokens are
  kept for each origin. Grist served under a path prefix isn't supported for the callback.

**Setting OpenBao up** (as `test/server/lib/encryption/OpenBaoProvider.ts` and
`docker/encryption-dev/openbao-setup.sh` do), for the default mounts and key names
(`openBaoPolicy()` makes the policy for others):

```bash
bao secrets enable transit
bao auth enable oidc
# A client of the identity provider Grist uses (confidential: OpenBao keeps its secret). Its
# redirect URIs at the identity provider: Grist's callback(s) below.
bao write auth/oidc/config oidc_discovery_url=https://idp.example.com/realms/x \
  oidc_client_id=openbao oidc_client_secret=... default_role=grist
ACCESSOR=$(bao read -field=accessor sys/auth/oidc)
bao policy write grist - <<POLICY
path "transit/keys/grist-user-{{identity.entity.aliases.$ACCESSOR.name}}" { capabilities = ["create", "read", "update"] allowed_parameters = { "type" = ["aes256-gcm96"] } }
path "transit/keys/grist-user-*" { capabilities = ["read"] }
path "transit/encrypt/grist-user-*" { capabilities = ["update"] allowed_parameters = { "plaintext" = [] } }
path "transit/decrypt/grist-user-{{identity.entity.aliases.$ACCESSOR.name}}" { capabilities = ["update"] allowed_parameters = { "ciphertext" = [] } }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
POLICY
# Users are named by their OIDC subject (`sub`), also given to Grist as `subject` (required). They
# get the `grist` policy only, not OpenBao's `default` one (which would let them store data here).
bao write auth/oidc/role/grist role_type=oidc user_claim=sub bound_audiences=openbao \
  allowed_redirect_uris=https://grist.example.com/encryption/openbao-callback \
  claim_mappings=sub=subject oidc_scopes=openid token_policies=grist \
  token_no_default_policy=true token_type=service token_ttl=1h token_max_ttl=12h
# Browsers call OpenBao from Grist's pages.
bao write sys/config/cors enabled=true allowed_origins=https://grist.example.com \
  allowed_headers=X-Vault-Token,Content-Type
```

Then `GRIST_ENCRYPTION_PROVIDER=openbao` and `GRIST_ENCRYPTION_OPENBAO_URL=https://openbao.example.com`,
with Grist signing users in with OIDC at the same identity provider. Removing a user's key (with
`deletion_allowed`), or raising its `min_decryption_version`, makes their copies unusable.

**Running it.**

- **An OpenBao (or a namespace, and an OIDC auth method) of its own**: CORS is set for the whole
  instance, the policy's globs open every key of the transit mount named with the prefix, and
  users choose their role when signing in: any other role of the same auth method without
  `bound_claims` would give them its policies too. Recreating the auth method changes its
  accessor: write the policy again.
- **Who may use it**: anyone with an account at the identity provider can sign in to OpenBao,
  create their key and call it. To keep it to Grist's users, add `bound_claims` to the role (e.g.
  a group: `bound_claims='{"groups":["grist"]}' groups_claim=groups`).
- **Limits on use**: rate limit quotas, e.g. `bao write sys/quotas/rate-limit/grist-transit
  path=transit/ rate=50 interval=1s` and the same for `auth/oidc/`, sized for your users; a small
  `max_request_size` on the listener (e.g. 65536).
- **Losing OpenBao loses the documents**: their keys can't be unwrapped without users' keys. Back
  it up (e.g. Raft snapshots), with its unseal keys, before anything else.
- **Audit**: an audit device, with its defaults (which hash what's sent and returned, so
  document keys), never `log_raw`.
- **Rotation** is the operators' (users can't rotate their own key): `transit/keys/<name>/rotate`,
  or `auto_rotate_period` on users' keys. Older copies keep working: don't raise
  `min_decryption_version` (Grist doesn't rewrap copies).
- **When a user leaves**: disable their entity (`identity/entity/id/<id> disabled=true`), which
  stops their tokens at once; otherwise they keep working until `token_max_ttl` (keep it near
  Grist's session length). Then remove them from documents in Grist, which replaces the keys
  they had.

**What other kinds of providers would need.** Nothing more from the storage: a member's copy of
a document key is opaque to Grist (bytes and a version), so it can be whatever the provider makes
of it, and the rows of `doc_encryption_key_wraps` remain the access list (the server hands a copy
to its member only, and a member removed loses theirs, the document key being replaced on the next
change). For instance:

- services where each member has keys of their own, e.g. SDKs for application developers, wrap the
  document key for each member, as `lasuite` does;
- key access services, which hold an organisation's key and unwrap a document key for whoever the
  application vouches for (the pattern of Google Workspace's client-side encryption, with its key
  access control list services, or of OpenTDF's key access service), would give every member the
  same copy, wrapped with the organisation's key (its version as `key_version`). Since a former
  member may have kept that copy, the service must check that the user is still a member, from a
  statement of their access the server signs, not only who they are. Grist's server still never
  gets the document key, but the service, and whoever runs it, can: it's not end-to-end in the same
  sense, and should be presented as such;
- services that keep the wrapped keys themselves would give each member a reference to their record.

## Architecture

```
 Browser (each member)                                    Server
 ┌──────────────────────────────────────────┐             ┌──────────────────────────────┐
 │ GristDoc UI ── EncryptedDocComm           │             │ EncryptionRelay (Comm methods)│
 │                    │                      │  ciphertext │   - checks document access    │
 │              EncryptedDocSession ─────────┼────────────►│   - numbers changes linearly  │
 │                    │                      │◄────────────┤   - broadcasts to members     │
 │              LocalActiveDoc               │             │ EncryptedDocStorage           │
 │      (seal/unseal, privacy, sync)         │             │   (the doc's .grist file)     │
 │          │                  │            │             │ EncryptionStore (home DB:      │
 │   WorkerEngine          Keyring ── vault  │             │   keys, wrapped keys)         │
 │   (Web Worker: Pyodide, the data engine)  │             └──────────────────────────────┘
 └──────────────────────────────────────────┘
```

- **The data engine runs in the browser.** The same Python engine as on the server, in Pyodide,
  in a Web Worker (`app/client/encryption/engineWorker.ts`), driven through
  `sandbox/grist/direct_sandbox.py`. Its files are served by the server under
  `/encryption-engine/` with immutable, versioned URLs, so browsers cache them. The encryption
  code and the engine are only loaded for encrypted documents (the `loadEncryption` chunk), except
  for a few small modules the rest of the client uses (UI of keys and private columns, exports,
  the custom widgets policy, the guard of the REST API).
- **Starting the engine** is most of opening a document: Grist reloads the page for each document,
  so it starts every time. It starts first, alongside the other steps. The first time, once its
  modules are imported, a memory snapshot of Pyodide is saved in the browser's cache storage
  (about 45 MB, one per engine version); later starts restore it instead (~0.25 s instead of
  ~1.2 s). Files aren't part of a snapshot, so the packages and Grist's code are installed again;
  compiled extensions are dropped for their pure-Python fallbacks (a snapshot can't hold them).
  The console shows how long each step of opening took (`[encryption] Opened …`).
- **Changes** are the doc actions computed by the author's engine, encrypted, and appended to a
  linear log numbered by the server. A push based on an outdated head is refused; the browser
  then applies the changes it missed and computes its change again (`LocalActiveDoc`). Other
  browsers apply changes *exactly* (`apply_doc_actions_exactly`): they don't recompute formulas
  whose values came with the change, so formulas like `NOW()` or `RANDBETWEEN()` are the same
  everywhere. Likewise, when a document is opened, formulas are evaluated (for the engine to learn
  their dependencies), but the loaded values are kept (`calculate_exactly`).
- **Snapshots** of all tables are saved every 50 changes, encrypted, and after key changes. A
  browser opens a document from the latest snapshot and the changes after it. If it misses
  changes the server no longer has, it offers to reload. The server keeps the 5 latest
  snapshots, with the changes since the oldest; only owners can drop older history (as when
  making a column private). Snapshots and attachments bigger than 8MB travel by parts.
- **Storage**: the encrypted log, snapshots and attachments are in the document's own `.grist`
  file (`_gristsys_Encrypted*` tables), so backups and the storage manager handle them as usual
  (as are suggestions waiting, published forms and their answers waiting, all encrypted).
  Keys, wrapped for each member, and which columns are private, are in the home database
  (`doc_encryption_keys`, `doc_encryption_key_wraps`, `doc_encryption_scopes`). Only members
  holding the document key can push changes and snapshots, and documents can't grow beyond the
  size their plan (or `GRIST_ENCRYPTION_MAX_DOC_SIZE_MB`) allows.

## Keys

- **The document key** (scope `doc`) encrypts changes and snapshots. Owners share it with
  members from the document's settings (or when they add members in the sharing dialog).
- **Column keys** (scope `column:…`): a column can be made private to some members (column
  panel › Privacy). Its values, and those of the formulas using it, are sealed with the column's
  key inside the change: other members see 🔒. Formulas using private columns are private too,
  with the keys of all the columns they use, and so are the columns of summary tables grouped by
  them. Which columns are private is kept by the server (`doc_encryption_scopes`), not in the
  document, which any member holding the document key can change: only owners can make a column
  private, and only owners holding its key can make it public again (its values are then shared
  with all members, by any member who can read them, as soon as one can: until then, snapshots
  aren't saved, as members who can't read them would save them locked). New columns never get
  the id of a removed private column, which would make them private too.
- **Owners have access to all private tables and columns**: they're always among those who have
  access (not chosen in "Who has access", and never removed from it). In a document with private
  tables or columns, the server refuses to make members owners until they hold all their keys
  (`_failIfEncryptedDocOwnersLackKeys()`, whatever the way, e.g. the REST API). The sharing dialog
  first has the owner's browser give them these keys (`prepareOwners()`, re-wrapped by the
  encryption service: the server never gets them), then saves the role. Only owners holding all
  these keys can do it, and only for members holding the document key (accepted ones). Keys are
  never given out otherwise without an owner's action. (Owners inherited from a workspace or site
  aren't checked.)
- **Private tables** use column keys too: a table made private (table settings › Data › Privacy)
  has all its columns private with the table's key, including columns added later (its binding
  says the table: `colRef` holds minus the table's row id, see `tableTarget()`). A column of a
  private table can be restricted further, to some of the table's members ("Restrict to some of
  them" in the column's settings): it's then private itself, and needs both keys; members removed
  from the table are removed from such columns too. A private table shows a lock in its widgets'
  titles, in the list of raw data, and next to the pages showing it (list of pages and top bar);
  only columns with more restrictions than their table show one in their header (and none for
  members who can't read the table at all). Members who lose access to values see them locked
  right away; members given access to values they have locked are offered to reload, as such
  values come with the document when opening it. The table's structure stays visible to all
  members (its name, its columns and their settings, its number of rows and their ids), and so do
  which of its cells are empty (see Limitations). New tables never get the id of a removed private
  table. When a document is encrypted, access rules hiding a whole table from some members make
  it a private table; when encryption is removed, a private table becomes a table hidden (rows
  included, and unchangeable) by an access rule from members who couldn't read it.
- **Settings revealing private values** are private too, sealed cell by cell: saved filters of
  private columns, the choices of private Choice columns, comments on private cells, and the
  names and sizes of files attached in private columns.
- **Replacing keys**: when someone loses access to a key (removed from the document, or from a
  private column's audience), the key is flagged `rotate_on_next_edit`. The next change by a
  member holding it creates a new key, given to the remaining holders, and saves a snapshot under
  it. The server only accepts changes under the current document key, and key changes are
  records in the log, so concurrent browsers switch to the new key in order: a change made
  meanwhile with the old key is refused, and its author makes it again on top of the key change,
  with the new key (or fails, without retrying, if they lost access to it). Changes to sharing that
  would leave nobody holding the document key with access to the document are refused (removing
  members from it, its workspace or its site, or moving it): keys can only be given out by members
  holding them, so its content could never be read again.
- **Attachments**: each file is encrypted with a key of its own, wrapped with the document's (or
  private column's) key. Files never change, so their keys are never replaced (except when their
  column is made public: then they get wrapped with the document's key).
- **Key changes come with their snapshot.** Making a column private, or replacing a key, saves
  the document under the new keys along with the key change, in one step (`NewKeyRequest.snapshot`):
  the entry in the history and the snapshot are written in the document's file, in a transaction
  committed only once the home database recorded the key. If writing the file fails after that,
  opening the document undoes key changes the history doesn't have (`dropChangesAfter`). Making a
  column private drops, in the same step, older snapshots and changes, which had its values in
  clear.

## What members record

What the server says about keys and private columns, browsers check against what members recorded,
inside the encrypted document (`KeyHistory`): the snapshots carry it, and each key entry of the
history carries the record of its change (`KeyChangeRecord`), made by the member who made it and
encrypted with the document key current before it (the server can't forge it). Browsers:

- only use keys recorded (`TamperedKeysError` otherwise), and take the latest recorded key of
  each scope as current, whatever the server says (it can't get members to use a key of its own,
  nor an older one a former member holds);
- check that their copy of each key is of the key recorded (a check value, encrypted with the key
  by its creator), so the server can't give them another key under the same id;
- treat a column as private if either the server or the record says so, and only share values
  of a column made public if the record says it was;
- refuse key entries without a valid record (the document can't be used then).

Documents from before such records start one from what the server says, when first opened.

## What the browsers check

The server can't check changes, since it can't read them, and any member holding the document key
can make one, e.g. with a modified client. So browsers check what they receive:

- **Formulas can't read private columns without naming them.** Which formulas read which columns
  is found from the column names in their code. The data engine enforces it: a formula reading a
  column it doesn't name (e.g. with a name built at runtime) gets an error instead
  (`ScopeMonitor` in `sandbox/grist/direct_sandbox.py`), and formulas can't go around the engine
  (no names starting with `_`, no `getattr()`, `vars()`, imports, format strings built at runtime,
  nor the engine's internal objects). This holds in every browser alike, so results stay the same
  everywhere.
- **Changes must seal private values, with the right keys.** A change with private values in
  clear, sealed with other keys, or that can't be decrypted or applied, is skipped by every
  browser (they all reach the same conclusion: it depends only on the history and on what the
  server says about keys and private columns), and the user is told.
- **Sealed values must belong where they are.** They carry their table, column, rows and change
  number: members holding the key check them, so that values can't be moved to other cells or
  replayed. Those that don't match are shown locked, as for members who can't check them.
- **Changes must be shaped as changes**: others are skipped by every browser.
- **The author of a change** shown in the history is the one the server recorded.

## Whole-document operations

These are done by an owner's browser (the server can't read the documents), locking the document
meanwhile (`docLocks.ts`): other members see that it's in progress, and can't change it until it's
done. Locks are kept by the doc worker serving the document, renewed by the browser holding them,
and released if it goes away.

- **Encrypting a regular document** (Settings › Encryption › Encrypt this document), by an owner
  who can read all of it: the members who had it open are disconnected from it and wait; the
  server gives the owner's browser its content and attachments, which it encrypts with a new key,
  for the members who enabled encryption (others get it later, as for any encrypted document).
  Access rules hiding columns from some members become private columns, readable by the members
  who could read them (the server works out who, viewing the document as each member): their
  values and attachments are sealed with keys of their own, in the same step. Rules depending on
  the content (hiding rows or cells) can't be converted: the document can't be encrypted until
  they're removed. Rules limiting edits are dropped (the owner is told). The new content is prepared in
  a file next to the document's (`<doc>.encrypting.tmp`), then the home database records that the
  document is encrypted, then the file replaces the document's. Earlier versions kept by the
  storage (e.g. S3 versions), which have the content in clear, are deleted. Shares (e.g.
  published forms) are removed. See `EncryptionConversion.ts`.
- **Making it regular again** (Settings › Encryption › Remove encryption), by an owner
  who can read all of it: its browser sends the decrypted content, with access rules replacing
  private columns (hiding them, and formulas using them, from members who couldn't read them),
  and the decrypted attachments; the server writes a regular document next to it
  (`<doc>.decrypting.tmp`), then updates the home database (keys forgotten), then replaces the
  file, and deletes earlier (encrypted) versions. Browsers that have it open reopen it.
- If interrupted before the home database is updated, what was prepared is dropped; after, the
  new file is moved in place when the document is next opened (`finishPendingConversion`).
- **Restoring an earlier version** (Document history › Snapshots), by an owner who can read all of
  it: the server keeps the 5 latest snapshots; the owner's browser decrypts the one to restore,
  encrypts it again with the current keys and private columns, and the server records it as a
  "restore" entry of the history, with it as its snapshot. Browsers that have the document open
  reload it.
- **Duplicating** (Share › Duplicate document), by a member who can read all of it: a new
  encrypted document gets the content (or only the structure) under keys of its own, set up in one
  step with its first snapshot (`initializeEncryptedDoc`). Private columns stay private. As for
  regular copies, the copy's members are those of its workspace: they get the keys they held in
  the original (if they enabled encryption).

## Collaborating beyond members who edit

- **Suggestions**: when the document accepts suggestions (Settings › Suggestions), members who
  can't edit it (viewers) make changes in their browser only, then send them as a suggestion
  (encrypted with the document key), with a description. Changes from others wait meanwhile.
  Members who can edit see suggestions waiting (Tools › Suggestions), and apply them (as their own
  change, computed again on the current document) or dismiss them. Suggestions can't involve
  private columns.
- **Forms** (`EncryptedForms.ts`): publishing a form gives it a key pair and a "link key", kept in
  the form's settings in the document. What respondents need (questions, choices, the form's
  public key) is encrypted with the link key, which is in the form's link, after `#` (browsers
  never send it to servers): the server stores it without being able to read it or change it.
  Respondents' browsers encrypt their answers with the form's public key (ECIES: ECDH P-256,
  HKDF, AES-GCM), and the server keeps them in the document's inbox (limited in size, number and
  rate). Browsers of members who can edit the document add them to it as a change that removes
  them from the inbox at the same time (so that they're added once). Forms can fill private
  columns: the form's private key is then sealed with those columns' keys, so that only members
  who can read them can read (and add) the answers; others leave them waiting. Members who can
  edit see, under the title of the form and of widgets of the table it fills (including the raw
  data), how many answers are waiting, and why their browser doesn't add them (columns they can't
  read, or a change refused, e.g. by a calculation they can't do, which is named); browsers
  try again when their keys change. Questions can be
  made private from the form's settings (Field › Privacy) too. When which columns a published form
  fills are private changes (or their keys do), an owner's browser publishes it again, sealing its
  private key anew (see `_syncForms()`). Files attached in
  answers are encrypted by respondents with keys of their own (carried in the encrypted answer),
  kept with the answer, and added as attachments (encrypted with their column's key). Formulas
  aren't in forms (as for regular documents), nor are values of private columns among the
  choices of references (anyone with the form's link would see them). Publishing a form filling a
  private Choice column gives its choices to whoever has the link. Endpoints (public):
  `GET/POST /api/docs/:docId/encrypted-forms/:formId`, `POST …/:formId/files`.

## In the browser instead of the server

- **Imports** of files are parsed in the browser, with the engine's parsers. From Google Drive
  (when Google is configured), the server only turns the user's authorization into an access
  token, with which the browser downloads the file: the server never gets it.
- **Exports** (CSV, TSV, XLSX) are made in the browser.
- **The formula assistant** (`GRIST_ENCRYPTION_ASSISTANT`): the browser describes the document's
  structure (as the server does for regular documents) and calls the AI service directly, after
  the user agreed to it for the session, being told who runs the service and whether it's
  sovereign. Cell values aren't sent. With `"auth": "user-key"`, each user's own API key is used
  (kept in their browser), so that nobody spends the instance's credits; with `"none"`, the
  endpoint must authenticate users otherwise (e.g. a gateway).

## What members without a column key can do

Edits are checked before they're sent (`ColumnPrivacy.checkChange`): a member can't edit a private
column they can't read, nor a value, a column or a table that a private formula uses (it would
need recomputing by someone who can read it), nor private settings (e.g. remove a page with a
saved filter of a private column: undoing it would need the filter). They get a message saying
it must be changed by a member with access. Members who can read a column can set values shown
locked (whose sealed value didn't check out) again.
Which changes would change a formula's results follows the tables it can reach
(`ColumnPrivacy._reach()`): the columns it names of its own table, of tables it names (lookups),
and of tables reached through reference columns it names (`$Team.Budget`, `$group.Salary`). So a
private formula `$Name + str($Pay)` in a table doesn't keep members from changing `Name` columns of
other tables (e.g. adding form answers there). Rows can't be added to its own table and to tables
it looks up, nor removed from any table it reaches; a formula naming a formula column of type Any
(which may hold records of any table) is taken to reach every table.
Formulas they can't compute are "frozen" in their engine, and keep the values computed by others.
They can still save snapshots of the whole document: for the private values they can't read, the
snapshot refers to the sealed values they received (`SealedCells.ts`), which they pass on without
being able to read them; holders of the keys check that each one belongs to its cell.

## Unavailable for encrypted documents

Anything needing the server to read the data is hidden or refused (the client's REST API object
refuses, for these documents, any call sending or fetching their data, whatever the code path):

- REST API data access, webhooks, triggers and automations, the document AI assistant (the
  formula assistant works, see above), access rules with conditions, public sharing, and forks.
  The "Access Rules" page explains instead how access works in an encrypted document (keys for
  reading, roles for changing), lists private tables and columns with the members who can read
  them (leading to their settings), and the kinds of rules that aren't available;
- server-side downloads and exports (`.grist`): CSV, TSV and XLSX exports of widgets are made in
  the browser (XLSX with the data engine's own library);
- imports through the server: files are imported in the browser instead (CSV, TSV, XLSX, JSON),
  with the engine's own parsers, including from Google Drive. Other import plugins aren't
  available.
- external attachment storage, and the data engine settings;
- custom widgets other than those Grist serves itself and those allowed by
  `GRIST_ENCRYPTION_ALLOWED_WIDGETS` (they see the content);
- error reports sent to the server don't include details (they may contain content).

What works differently:

- "On-demand" tables work, but are loaded like others (the data engine is in the browser).
- Notifications of changes can only say that the document changed, and who changed it. Editions
  with notifications implement `notifySubscribersOfEncryptedChange` for that (core has none).

## Limitations

- Formulas reading private columns are found by the names in their code, conservatively (any
  token matching a private column's id): formulas mentioning such a name are private even if they
  don't actually read the column. The engine keeps formulas from reading what they don't name
  (see above); this restricts what formulas can do in encrypted documents (no imports, no
  `getattr()`, no names starting with `_`; `datetime`, `math` and `re` are available, without
  their submodules).
- The engine's protection is a reference monitor plus a restriction of formulas' Python: it is
  tested (including an exploration of what formulas can reach), but Python isn't designed as a
  sandbox. Members holding a column's key can of course share what they read by other means.
- A member without a column's key can't read nor write its values, but can make values they
  can't read locked for everyone (e.g. by replaying sealed values), like any member can damage a
  document. The document's history and snapshots on the server are what to recover from.
- Cells of private columns and tables holding their default value (e.g. empty) are given in
  clear, so that members without the key can still add rows: members can tell which cells are
  empty, but not what the others contain.
- What a member already had of a column or table before it was made private stays in the
  document they have open (and anywhere they copied it): only what they get afterwards is locked.
- A member without a column's key can't make a snapshot right after the column became private
  (values are then only known in clear): members holding the key make it.
- A member without a column's key making a snapshot passes on the sealed values they received:
  a modified client could pass on older ones instead (members holding the key would see older
  values, rather than locked ones). Members holding the key can set them again; the history and
  older snapshots on the server are what to recover from.
- The server is trusted to say who the members are: a server adding an account of its own as a
  member would get keys given to it (e.g. by an owner giving access to members waiting). It can't
  change which keys exist, nor which columns are private (see "What members record" below). It
  could serve an older snapshot (with older records), as any storage could.
  Likewise, the encryption service's `client.js` runs in Grist's pages (and so does the code
  serving forms to respondents, and importing from Google Drive with a token the server makes).
- Converting a document is atomic thanks to its file being replaced once the home database is
  updated: if the doc worker loses its disk between the two, the document can't be opened
  (the window is a few milliseconds).
- Converting a document deletes its earlier versions in the storage; copies of it made earlier
  (e.g. downloads, or backups outside of Grist) aren't.
- Volatile formulas (`NOW()`, `TODAY()`...) aren't refreshed when a document is opened, only when
  something they depend on changes.
- Only the `mock` provider is tested end to end in the browser automatically. The `openbao`
  provider is tested against a real OpenBao, without Grist's pages
  (`test/server/lib/encryption/OpenBaoProvider.ts`); the `lasuite` provider against a stand-in for
  the service's SDK (`test/client/encryption/lasuiteProvider.ts`). Both were run end to end by
  hand; `docker/encryption-dev/` has a setup to try either.

## Tests

- `sandbox/grist/test_direct_sandbox.py`: the engine bridge, the formula lockdown and the scope
  monitor.
- `test/server/lib/encryption/PyodideEngine.ts`: the engine in Pyodide.
- `test/server/lib/encryption/LocalActiveDoc.ts`: collaboration (including the ordering of
  concurrent changes, changes arriving out of order, lost answers), key replacement while members
  edit, private columns and what reveals them (summaries, filters, comments, choices, attachments),
  making columns public again, attachments, imports, snapshots by members without keys, changes
  from modified clients, snapshots saved with key changes, restoring, exporting, suggestions and
  forms, against an in-memory relay.
- `test/server/lib/encryption/EncryptionRelay.ts`: the server side, its access checks, storage,
  transfers by parts, size limits, key changes with their snapshot (and undoing them if they
  didn't make it to the history), restoring, locks, suggestions, forms and their inbox, and
  converting documents to and from encryption (including interrupted conversions).
- `test/nbrowser/EncryptedDocuments.ts`: end to end in the browser (with the `mock` provider).
- `test/client/encryption/lasuiteProvider.ts`: the `lasuite` provider against a stand-in for the
  LaSuite service's SDK (how Grist's calls translate to the service's).
- `test/server/lib/encryption/OpenBaoProvider.ts`: the `openbao` provider against a real OpenBao
  and an identity provider of the test's own: signing in (the browser part, with a stand-in tab
  following the redirects, including one the identity provider severs), each member's copy only
  they can unwrap, keys nobody else can create or tamper with, sharing, rotation, attachments,
  renewed, expired and revoked tokens, signing out, other mounts. Only run with
  `TEST_OPENBAO=docker` (OpenBao started in Docker, on the host's network; `TEST_OPENBAO_IMAGE`
  for another image) or `TEST_OPENBAO_URL` and `TEST_OPENBAO_TOKEN` (a throwaway OpenBao, which
  the test sets up and leaves so), as the CI does; the policy's consistency with this
  documentation and the callback page are checked always.
- `test/client/encryption/openbaoProvider.ts`: the parts of the `openbao` provider that need no
  OpenBao (against made-up answers): which members are skipped when wrapping keys, sign-ins kept
  alongside other tabs, renewed, forgotten and revoked, the sign-in's tab and messages.
