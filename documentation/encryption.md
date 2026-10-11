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
| `GRIST_ENCRYPTION_ALLOWED_WIDGETS` | Comma-separated URL prefixes of custom widgets allowed in encrypted documents (e.g. `https://widgets.example.com/`), besides those Grist serves itself. Widgets see the content of the documents they're in. |
| `GRIST_ENCRYPTION_MAX_DOC_SIZE_MB` | The most an encrypted document may take on the server, when the site's plan sets no limit (plans' data and attachments limits apply together, since the server can't tell them apart). |
| `GRIST_ENCRYPTION_ASSISTANT` | An AI service for the formula assistant of encrypted documents, which browsers call directly, as JSON: `{"endpoint": "https://…/v1/chat/completions", "model": "…", "provider": "…", "sovereign": true, "auth": "user-key"}` (an OpenAI-compatible endpoint allowing calls from browsers; `auth` is `user-key` for users to give their own API key, kept in their browser, or `none`). |

The configuration is checked on startup: mistakes stop the server rather than break pages.

Users are identified to the encryption service by their OIDC subject (`sub`), which Grist links
to the user on their first OIDC sign-in (for all OIDC sign-ins, not only for encrypted documents;
a user already linked to another subject, e.g. from another identity provider, keeps it). As for Docs and Drive, the encryption service and Grist
must share the identity provider (an `encryption` client in the same realm): see
`docker/encryption-dev/` for a local setup, with both the mock and the real service.

A document is encrypted from its creation (`options.encryption = {version: 1}`), or converted
later by an owner (see below).

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
- **Making it regular again** (Settings › Encryption › Stop encrypting this document), by an owner
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
  who can read them can read (and add) the answers; others leave them waiting. Files attached in
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
Formulas they can't compute are "frozen" in their engine, and keep the values computed by others.
They can still save snapshots of the whole document: for the private values they can't read, the
snapshot refers to the sealed values they received (`SealedCells.ts`), which they pass on without
being able to read them; holders of the keys check that each one belongs to its cell.

## Unavailable for encrypted documents

Anything needing the server to read the data is hidden or refused (the client's REST API object
refuses, for these documents, any call sending or fetching their data, whatever the code path):

- REST API data access, webhooks, triggers and automations, the document AI assistant (the
  formula assistant works, see above), access rules, public sharing, and forks;
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
- Only the mock vault is tested end to end automatically. The real encryption service is
  integrated (`keyVaults.ts`); `docker/encryption-dev/` has a setup to try it.

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
- `test/nbrowser/EncryptedDocuments.ts`: end to end in the browser (with the mock vault).
