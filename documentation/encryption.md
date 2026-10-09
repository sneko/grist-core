# Encrypted documents

Encrypted documents are end-to-end encrypted: the server stores and relays them, but only ever
sees ciphertext. Their keys are handled by the LaSuite encryption service (the same as Docs and
Drive use), whose vault runs in an iframe of its own origin, so Grist itself never holds users'
private keys.

## Configuration

| Variable | Meaning |
|---|---|
| `GRIST_ENCRYPTION_FEATURE_ENABLED` | `true` lets users create encrypted documents ("Add new" › "New encrypted document"). |
| `GRIST_ENCRYPTION_VAULT_URL` | Origin of the encryption service's vault (its `client.js` is loaded from there). |
| `GRIST_ENCRYPTION_INTERFACE_URL` | Origin of the encryption service's interface (onboarding, key backup...). |
| `GRIST_ENCRYPTION_MOCK_VAULT` | `true` replaces the encryption service by a stand-in using a hardcoded key. **No security at all: for tests and development only**, refused when `NODE_ENV=production` (as in Grist's images). |
| `GRIST_ENCRYPTION_MOCK_KEY` | With the mock vault, the hardcoded key (64 hex characters; a default is used otherwise). |

Users are identified to the encryption service by their OIDC subject (`sub`), which Grist links
to the user on their first OIDC sign-in. As for Docs and Drive, the encryption service and Grist
must share the identity provider (an `encryption` client in the same realm): see
`docker/encryption-dev/` for a local setup, with both the mock and the real service.

A document is encrypted from its creation (`options.encryption = {version: 1}`) and stays so.

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
  code and the engine are only loaded for encrypted documents (the `loadEncryption` chunk).
- **Changes** are the doc actions computed by the author's engine, encrypted, and appended to a
  linear log numbered by the server. A push based on an outdated head is refused; the browser
  then applies the changes it missed and computes its change again (`LocalActiveDoc`). Other
  browsers apply changes *exactly* (`apply_doc_actions_exactly`): they don't recompute formulas
  whose values came with the change, so formulas like `NOW()` or `RANDBETWEEN()` are the same
  everywhere. Likewise, when a document is opened, formulas are evaluated (for the engine to learn
  their dependencies), but the loaded values are kept (`calculate_exactly`).
- **Snapshots** of all tables are saved every 50 changes, encrypted. A browser opens a document
  from the latest snapshot and the changes after it. If it misses changes the server no longer
  has, it offers to reload.
- **Storage**: the encrypted log, snapshots and attachments are in the document's own `.grist`
  file (`_gristsys_Encrypted*` tables), so backups and the storage manager handle them as usual.
  Keys, wrapped for each member, and which columns are private, are in the home database
  (`doc_encryption_keys`, `doc_encryption_key_wraps`, `doc_encryption_scopes`).

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
  with all members).
- **Replacing keys**: when someone loses access to a key (removed from the document, or from a
  private column's audience), the key is flagged `rotate_on_next_edit`. The next change by a
  member holding it creates a new key, given to the remaining holders, and saves a snapshot under
  it. The server only accepts changes under the current document key, and key changes are
  records in the log, so concurrent browsers switch to the new key in order.
- **Attachments**: each file is encrypted with a key of its own, wrapped with the document's (or
  private column's) key. Files never change, so their keys are never replaced.

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
- **The author of a change** shown in the history is the one the server recorded.

## What members without a column key can do

Edits are checked before they're sent (`ColumnPrivacy.checkChange`): a member can't edit a private
column they can't read, nor a value that a private formula uses (it would need recomputing by
someone who can read it). They get a message saying it must be changed by a member with access.
Formulas they can't compute are "frozen" in their engine, and keep the values computed by others.
They can still save snapshots of the whole document: for the private values they can't read, the
snapshot refers to the sealed values they received (`SealedCells.ts`), which they pass on without
being able to read them; holders of the keys check that each one belongs to its cell.

## Unavailable for encrypted documents

Anything needing the server to read the data is hidden or refused:

- REST API data access, webhooks, triggers and automations, the assistant, forms, proposals,
  access rules, public sharing and copies;
- server-side downloads and exports (`.grist`, XLSX): CSV/TSV exports are done in the browser;
- imports through the server: files are imported in the browser instead (CSV, TSV, XLSX, JSON),
  with the engine's own parsers. Imports from Google Drive and other plugins aren't available.
- external attachment storage, and the data engine settings.

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
- A member without a column's key can't make a snapshot right after the column became private
  (values are then only known in clear): members holding the key make it.
- Volatile formulas (`NOW()`, `TODAY()`...) aren't refreshed when a document is opened, only when
  something they depend on changes.
- Only the mock vault is tested end to end automatically. The real encryption service is
  integrated (`keyVaults.ts`); `docker/encryption-dev/` has a setup to try it.

## Tests

- `sandbox/grist/test_direct_sandbox.py`: the engine bridge, the formula lockdown and the scope
  monitor.
- `test/server/lib/encryption/PyodideEngine.ts`: the engine in Pyodide.
- `test/server/lib/encryption/LocalActiveDoc.ts`: collaboration, private columns, key
  replacement, attachments, imports, snapshots by members without keys, and changes from modified
  clients, against an in-memory relay.
- `test/server/lib/encryption/EncryptionRelay.ts`: the server side, its access checks and storage.
- `test/nbrowser/EncryptedDocuments.ts`: end to end in the browser (with the mock vault).
