#!/usr/bin/env bash
#
# Sets the OpenBao of docker-compose.yaml up for Grist's "openbao" key provider, as
# documentation/encryption.md ("The openbao provider") says: the transit engine, an OIDC sign-in at
# this directory's Keycloak (client `openbao`), the policy giving each user their own key, and CORS
# for Grist's pages. Run after `docker compose --profile openbao up -d --wait`; it can be run again
# (OpenBao's dev mode keeps nothing: again after a restart).
set -euo pipefail

bao() {
  docker exec -i -e BAO_ADDR=http://127.0.0.1:7320 -e BAO_TOKEN=dev-root grist_encryption_dev_openbao bao "$@"
}

bao read sys/mounts/transit > /dev/null 2>&1 || bao secrets enable transit
bao read sys/auth/oidc > /dev/null 2>&1 || bao auth enable oidc
bao write auth/oidc/config oidc_discovery_url=http://localhost:7310/realms/grist \
  oidc_client_id=openbao oidc_client_secret=openbao-dev-secret default_role=grist
ACCESSOR=$(bao read -field=accessor sys/auth/oidc)
# The policy of openBaoPolicy() (app/common/encryption/OpenBaoKeyVault.ts; a test keeps them alike).
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
  allowed_redirect_uris=http://localhost:8484/encryption/openbao-callback \
  claim_mappings=sub=subject oidc_scopes=openid token_policies=grist \
  token_no_default_policy=true token_type=service token_ttl=1h token_max_ttl=12h
bao write sys/config/cors enabled=true allowed_origins=http://localhost:8484 \
  allowed_headers=X-Vault-Token,Content-Type
echo "OpenBao is set up for Grist at http://127.0.0.1:7320"
