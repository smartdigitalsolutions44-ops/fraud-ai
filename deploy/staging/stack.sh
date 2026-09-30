#!/usr/bin/env bash
# STAGING stack orchestration (Stage 12). Synthetic data only.
#
#   deploy/staging/stack.sh up          # everything below, in order (idempotent)
#   deploy/staging/stack.sh unseal      # after a Vault restart
#   deploy/staging/stack.sh check       # privilege checks, key and anchor status
#   deploy/staging/stack.sh down        # stop and DELETE all staging data (volumes)
#
# `up`:
#  1. generate-secrets.sh: DB role passwords, operator keys and registry, anchor credentials;
#  2. build the image (WITH_TORCH=0 builds the verification variant where the CPU PyTorch
#     index is unreachable; CI builds the real image);
#  3. start PostgreSQL, Redis, Vault and RustFS;
#  4. init-vault: initialise and unseal Vault, then create:
#     * the transit keys model/audit/release (Ed25519, non-exportable) and image (ECDSA,
#       via cosign);
#     * one signing policy and token per purpose;
#     * the public keys (to .env) and the image public key (to config/);
#  5. anchor-init: the Object Lock bucket and its writer user;
#  6. db-init as the PostgreSQL administrator (roles only), then migrate as fraud_migrator
#     (plus grants);
#  7. bootstrap the synthetic world as fraud_service, models signed through Vault;
#  8. start the service (fraud_service), the TLS proxy and the scheduled anchor job;
#  9. check: every role's privileges, key status, anchor status.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
compose() { docker compose -f docker-compose.staging.yml "$@"; }
export VAULT_ADDR="http://127.0.0.1:8200"
# Until init-vault has written the real public keys to .env, give compose placeholders
# (only Vault/PostgreSQL/Redis/RustFS start before then; no fraud-ai service trusts them).
if [ ! -s "$here/.env" ]; then
  export MODEL_SIGNING_PUBLIC_KEYS=pending AUDIT_ANCHOR_PUBLIC_KEYS=pending \
         RELEASE_SIGNING_PUBLIC_KEYS=pending
fi
init_file="$here/secrets/vault-init.json"

vault_exec() { compose exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e "VAULT_TOKEN=${VAULT_TOKEN:-}" vault "$@"; }

wait_vault() {
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$VAULT_ADDR/v1/sys/health" || true)"
    [[ "$code" =~ ^(200|429|472|473|501|503)$ ]] && return 0
    sleep 1
  done
  echo "Vault did not come up" >&2; exit 1
}

unseal() {
  wait_vault
  key="$(python3 -c "import json;print(json.load(open('$init_file'))['unseal_keys_b64'][0])")"
  vault_exec vault operator unseal "$key" >/dev/null
  echo "vault unsealed"
}

secret_file() {  # write a service-readable secret file (0400 uid 10001 as root, else 0444)
  printf '%s' "$2" > "$here/secrets/$1"
  if [ "$(id -u)" = "0" ]; then chown 10001:10001 "$here/secrets/$1"; chmod 400 "$here/secrets/$1"
  else chmod 444 "$here/secrets/$1"; fi
}

init_vault() {
  compose up -d vault
  wait_vault
  if [ ! -s "$init_file" ]; then
    (umask 077; vault_exec vault operator init -key-shares=1 -key-threshold=1 -format=json \
      > "$init_file")
    echo "vault initialised (staging custody: one unseal key in $init_file)"
  fi
  unseal
  VAULT_TOKEN="$(python3 -c "import json;print(json.load(open('$init_file'))['root_token'])")"
  export VAULT_TOKEN
  vault_exec vault secrets list -format=json | grep -q '"transit/"' \
    || vault_exec vault secrets enable transit >/dev/null
  for purpose in model audit release; do
    vault_exec vault read "transit/keys/fraud-ai-$purpose" >/dev/null 2>&1 \
      || vault_exec vault write -f "transit/keys/fraud-ai-$purpose" type=ed25519 exportable=false >/dev/null
  done
  compose cp ./vault/policies.sh vault:/tmp/policies.sh >/dev/null 2>&1 \
    || docker cp ./vault/policies.sh "$(compose ps -q vault)":/tmp/policies.sh
  vault_exec sh /tmp/policies.sh >/dev/null
  for purpose in model audit release image; do
    [ -s "$here/secrets/vault_token_$purpose" ] && continue
    token="$(vault_exec vault token create -orphan -period=720h -no-default-policy \
      -policy="fraud-ai-sign-$purpose" -display-name="fraud-ai-$purpose-signer" -field=token)"
    secret_file "vault_token_$purpose" "$token"
  done
  if [ ! -s "$here/secrets/vault_token_key_admin" ]; then
    (umask 077; vault_exec vault token create -orphan -period=24h -no-default-policy \
      -policy=fraud-ai-key-admin -policy=fraud-ai-sign-image -display-name=fraud-ai-key-admin \
      -field=token > "$here/secrets/vault_token_key_admin")
  fi
  # The image key (ECDSA P-256) is created by cosign itself, inside Vault.
  mkdir -p "$here/config"
  if ! vault_exec vault read transit/keys/fraud-ai-image >/dev/null 2>&1; then
    (cd "$here/secrets" && VAULT_TOKEN="$(cat vault_token_key_admin)" \
      cosign generate-key-pair --kms hashivault://fraud-ai-image >/dev/null && rm -f cosign.pub)
  fi
  VAULT_TOKEN="$(cat "$here/secrets/vault_token_key_admin")" \
    cosign public-key --key hashivault://fraud-ai-image > "$here/config/image-signing.pub"
  # Public keys of the statement-signing keys, in the settings' base64url form.
  {
    for purpose in model audit release; do
      raw="$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/transit/keys/fraud-ai-$purpose")"
      public="$(python3 -c "import json,sys,base64
d=json.loads(sys.argv[1])['data']; v=str(d['latest_version'])
print(base64.urlsafe_b64encode(base64.b64decode(d['keys'][v]['public_key'])).decode().rstrip('='))" "$raw")"
      case $purpose in
        model) echo "MODEL_SIGNING_PUBLIC_KEYS=$public" ;;
        audit) echo "AUDIT_ANCHOR_PUBLIC_KEYS=$public" ;;
        release) echo "RELEASE_SIGNING_PUBLIC_KEYS=$public" ;;
      esac
    done
  } > "$here/.env"
  unset MODEL_SIGNING_PUBLIC_KEYS AUDIT_ANCHOR_PUBLIC_KEYS RELEASE_SIGNING_PUBLIC_KEYS
  echo "trusted public keys written to deploy/staging/.env; image key: config/image-signing.pub"
}

build() {
  local args=(--build-arg "WITH_TORCH=${WITH_TORCH:-1}" -t fraud-ai:staging)
  # Behind a TLS-intercepting proxy: the CA as a BuildKit secret (never in a layer).
  [ -n "${CA_BUNDLE:-}" ] && args+=(--secret "id=ca_bundle,src=$CA_BUNDLE")
  DOCKER_BUILDKIT=1 docker build "${args[@]}" "$here/../.."
}

check() {
  local rc=0
  compose run --rm -T migrate db check-privileges --expect fraud_migrator || rc=1
  compose run --rm -T ops db check-privileges --expect fraud_service || rc=1
  compose run --rm -T readonly db check-privileges --expect fraud_readonly || rc=1
  compose run --rm -T -e VAULT_TOKEN_FILE=/run/secrets/vault_token_audit ops keys status || true
  compose run --rm -T readonly audit anchor-status || rc=1
  compose run --rm -T readonly audit verify-anchor || rc=1
  return $rc
}

drill() {
  # Audit restore/tamper drill (see scripts/audit_tamper_drill.py).
  compose run --rm -T -e VAULT_TOKEN_FILE=/run/secrets/vault_token_audit ops audit anchor-now --always
  compose run --rm -T backup
  local dump
  dump="$(ls -t "$here"/backups/fraud_ai-*.dump | head -1)"
  compose exec -T postgres psql -q -U postgres -d postgres \
    -c "DROP DATABASE IF EXISTS fraud_ai_drill_clone" -c "CREATE DATABASE fraud_ai_drill_clone"
  compose exec -T postgres pg_restore -U postgres --no-owner -d fraud_ai_drill_clone < "$dump"
  echo "restored $(basename "$dump") into fraud_ai_drill_clone"
  local rc=0
  compose run --rm -T drill | tee "$here/out/tamper-drill.json" || rc=$?
  compose run --rm -T readonly audit verify-anchor  # the live database is untouched
  compose exec -T postgres psql -q -U postgres -d postgres -c "DROP DATABASE fraud_ai_drill_clone"
  return $rc
}

up() {
  [ -s "$here/secrets/service_database_url" ] || "$here/generate-secrets.sh"
  mkdir -p "$here/models" "$here/out" "$here/backups"
  chmod 0777 "$here/models" "$here/out" "$here/backups"  # written by uid 10001
  [ -n "${SKIP_BUILD:-}" ] || build
  compose up -d postgres redis rustfs
  init_vault
  compose up -d --wait postgres redis
  compose run --rm -T anchor-init
  compose run --rm -T db-init
  compose run --rm -T migrate
  if ! compose run --rm -T readonly models list 2>/dev/null | grep -q gradient-boosting; then
    compose run --rm -T -e VAULT_TOKEN_FILE=/run/secrets/vault_token_model --entrypoint python \
      ops /scripts/bootstrap_world.py --models /models --kinds "${KINDS:-gradient-boosting,logistic}" \
      --users "${USERS:-80}" --activity-days "${ACTIVITY_DAYS:-120}" --live-days "${LIVE_DAYS:-7}" \
      --sign-with-provider
  fi
  compose up -d fraud-ai proxy
  compose --profile ops up -d anchor
  echo "staging is up: https://staging.fraud-ai.test (127.0.0.1:8443)"
}

case "${1:-up}" in
  up) up ;;
  init-vault) init_vault ;;
  build) build ;;
  unseal) compose up -d vault; unseal ;;
  check) check ;;
  drill) drill ;;
  down)
    compose --profile jobs --profile ops --profile llm down -v --remove-orphans
    # The Vault volume is gone: its unseal key, tokens and the trusted public keys with it.
    rm -f "$init_file" "$here"/secrets/vault_token_* "$here/.env" "$here/config/image-signing.pub"
    ;;
  *) echo "usage: $0 up|build|init-vault|unseal|check|drill|down" >&2; exit 2 ;;
esac
