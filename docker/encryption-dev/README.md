# Encrypted documents: local dev setup

Two ways to try Grist's encrypted documents (see `documentation/encryption.md`) on your machine:

- **(a) Mock vault**: no encryption service, no identity provider. Fast, but no security at all
  (a hardcoded key). Good for working on Grist's side.
- **(b) Real encryption service**: Grist and the [LaSuite encryption service](https://github.com/suitenumerique/encryption)
  share the Keycloak of this directory, as Docs and Drive share theirs with it.

## Ports

| Port | What | Started by |
|------|------|------------|
| 8484 | Grist (`yarn start`) | grist-core |
| 7310 | Keycloak, realm `grist` (admin console: `admin` / `admin`) | this directory |
| 7200 | Encryption service: vault `http://data.encryption.localhost:7200`, interface `http://encryption.localhost:7200` | encryption repo |
| 7205 | Encryption service's PostgreSQL | encryption repo |
| 7207 / 7208 | Encryption service's Maildev (web / SMTP), where its emails land | encryption repo |

Nothing here clashes with the encryption repo's own stack (7200-7209) nor with Docs/Drive's dev
Keycloak (8083), so they can all run side by side.

## Test users

Realm `grist`, all with password `password`:

| Login | Email | OIDC subject (`sub`) |
|-------|-------|------------------------|
| `alice` | `alice@example.com` | `a11ce000-0000-4000-8000-000000000001` |
| `bob` | `bob@example.com` | `b0b00000-0000-4000-8000-000000000002` |
| `carol` | `carol@example.com` | `ca201000-0000-4000-8000-000000000003` |

Subjects are fixed in `realm-export.json`, so they survive a `docker compose down -v`: Grist and
the encryption service both remember users by their subject.

## (a) Quick test with the mock vault

No Keycloak needed. Grist's test login lets you sign in as anyone (any email, no password):

```bash
GRIST_ENCRYPTION_FEATURE_ENABLED=true \
GRIST_ENCRYPTION_MOCK_VAULT=true \
GRIST_TEST_LOGIN=1 \
yarn start
```

Then sign in as a user by opening (or follow "Sign in", which leads to the same form):

```
http://localhost:8484/test/login?username=alice@example.com&name=Alice&next=http://localhost:8484/
```

A Grist session is one user per browser profile: to have several users at once (e.g. to try a
private column with Alice as owner and Bob as an editor without its key), use one browser profile
or private window per user, each signed in through `/test/login` with its own email. Users are
created on their first sign-in; share the document with the others' emails as usual.

With the mock vault, all users share one hardcoded key (`GRIST_ENCRYPTION_MOCK_KEY` to change
it): it exercises the whole flow (document keys, column keys, rotation) but protects nothing.

If Grist redirects every page to `/boot` (a fresh home database is "not in service" until set up),
add `GRIST_IN_SERVICE=true`, or sign in at `/boot` with the boot key printed in the server logs.

## (b) Test with the real encryption service

Grist identifies users to the encryption service by their OIDC subject (`sub`), which it links
to the user (`users.options.authSubject`) on their first sign-in through OIDC. Users who existed
before signing in through OIDC get it linked on their next sign-in.

### 1. Start Keycloak

```bash
cd docker/encryption-dev
docker compose up -d --wait
curl -s http://localhost:7310/realms/grist/.well-known/openid-configuration | head -c 200
```

The realm has two clients:

- `grist`: confidential (secret `grist-dev-secret`), authorization code flow with PKCE (S256),
  redirect URI `http://localhost:8484/oauth2/callback` (Grist's OIDC callback), logout back to
  `http://localhost:8484/*`.
- `encryption`: the encryption service's interface, configured as in the encryption repo's own
  realm and in Docs' realm: public client, standard flow only, redirect URI
  `http://encryption.localhost:7200/auth/callback`, web origin `http://encryption.localhost:7200`,
  a `sub` mapper on the access token (the service rejects tokens whose `azp` is not `encryption`
  and identifies users by `sub`).

Both clients are in the same realm, so a user has the same `sub` in Grist and in the encryption
service.

To reset everything (users' sessions, realm changes made in the console): `docker compose down -v`,
then `up` again.

### 2. Start the encryption service, pointed at this Keycloak

In a checkout of the encryption repository (Node >= 24.19). Its `npm run dev:product` script is
the one Docs and Drive use: it runs the service on 7200 with `.env.test.product`, which points to
the product's Keycloak (Docs: `http://localhost:8083/realms/impress`) and allows
`http://localhost:3000` as embedding product. Variables already set in the environment take
precedence over that file, so override the Keycloak and the product origin:

```bash
cd ../encryption               # wherever the encryption repo is

# Its database and Maildev only: its own Keycloak (7203) is not needed.
docker compose up -d postgres maildev

npm install
npm run db:schema:compile
npm run db:push

OIDC_ISSUER=http://localhost:7310/realms/grist \
OIDC_JWKS_URL=http://localhost:7310/realms/grist/protocol/openid-connect/certs \
OIDC_CLIENT_ID=encryption \
OIDC_SERVER_CLIENT_ID=encryption \
OIDC_REDIRECT_URI=http://encryption.localhost:7200/auth/callback \
ALLOWED_FRAME_ANCESTORS=http://localhost:8484 \
EMAIL_PRODUCT_URL=http://localhost:8484 \
npm run dev:product
```

`ALLOWED_FRAME_ANCESTORS` is the list of product origins allowed to embed the vault and the
interface (comma separated: add `http://localhost:3000` to use Docs or Drive alongside).
`OIDC_ACCEPT_UNVERIFIED_EMAIL=true` comes from `.env.test.product` (the users here have verified
emails anyway).

`*.localhost` resolves to 127.0.0.1 in modern browsers. If yours doesn't, add
`127.0.0.1 data.encryption.localhost encryption.localhost` to `/etc/hosts`.

### 3. Start Grist with OIDC and the encryption service

```bash
APP_HOME_URL=http://localhost:8484 \
GRIST_OIDC_SP_HOST=http://localhost:8484 \
GRIST_OIDC_IDP_ISSUER=http://localhost:7310/realms/grist \
GRIST_OIDC_IDP_CLIENT_ID=grist \
GRIST_OIDC_IDP_CLIENT_SECRET=grist-dev-secret \
GRIST_ENCRYPTION_FEATURE_ENABLED=true \
GRIST_ENCRYPTION_VAULT_URL=http://data.encryption.localhost:7200 \
GRIST_ENCRYPTION_INTERFACE_URL=http://encryption.localhost:7200 \
yarn start
```

Do not set `GRIST_TEST_LOGIN` nor `GRIST_ENCRYPTION_MOCK_VAULT` here: the test login replaces
the OIDC login, and the mock vault replaces the encryption service. Add `GRIST_IN_SERVICE=true`
if pages redirect to `/boot` (see above).

### 4. Try it with several users

Open `http://localhost:8484` in one browser profile (or private window) per user and sign in
through Keycloak as `alice`, `bob`, `carol`. The Keycloak session, the Grist session and the
vault's keys (stored by the browser for `data.encryption.localhost`) all belong to the browser
profile, so don't switch users within one profile.

1. Each user, on first use of an encrypted document, goes through the encryption service's
   onboarding (key creation and backup) in its modal.
2. Alice creates an encrypted document ("Add new" › "New encrypted document") and shares it with
   `bob@example.com` and `carol@example.com` (owner, editor...). Bob and Carol must have signed in
   to Grist once, and onboarded with the encryption service, for Alice to be able to give them
   the document key.
3. Private columns: in the column panel › Privacy, Alice restricts a column to herself and Bob;
   Carol sees 🔒 instead of its values, and of the formulas using it.

Emails sent by the encryption service (security alerts, emergency access) are in its Maildev:
`http://localhost:7207`.

## How Docs and Drive do it (for reference)

- Their dev Keycloak (`docker/auth/realm.json`, port 8083, realms `impress` and `drive`) got an
  `encryption` client. Docs' is the same as the encryption repo's own (public, standard flow,
  redirect `http://encryption.localhost:7200/auth/callback`, web origin
  `http://encryption.localhost:7200`). Drive's is looser (redirects
  `http://encryption.localhost:7200/*` and `http://localhost:7200/*`, web origins also
  `http://data.encryption.localhost:7200` and `http://localhost:3000`, direct access grants on).
  Neither sets a PKCE method on the client (the interface uses PKCE anyway, and Keycloak accepts
  it without the attribute).
- The encryption service is started with `npm run dev:product` (`.env.test.product`: issuer
  `http://localhost:8083/realms/impress`, `ALLOWED_FRAME_ANCESTORS=http://localhost:3000`,
  `OIDC_ACCEPT_UNVERIFIED_EMAIL=true`).
- The products are given `ENCRYPTION_FEATURE_ENABLED=True`,
  `ENCRYPTION_VAULT_URL=http://data.encryption.localhost:7200` and
  `ENCRYPTION_INTERFACE_URL=http://encryption.localhost:7200`, the equivalents of Grist's
  `GRIST_ENCRYPTION_*` variables.
