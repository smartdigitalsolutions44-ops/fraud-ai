#!/usr/bin/env bash
# Generate random STAGING secrets (never reuse them anywhere else). Everything written here is
# git-ignored. Re-running keeps existing secrets (delete deploy/staging/secrets/ to rotate;
# existing data then needs the old pseudonymisation key: see DISASTER_RECOVERY.md).
#
# Compose file secrets are plain bind mounts: they keep their host owner and mode, and the
# service runs as uid 10001. Run this with sudo so the service's files become 0400 owned by
# 10001 (preferred). Without root they fall back to 0444 inside a 0700 directory: the
# directory protects them on the host, and the service logs a permissions warning.
#
# Stage 12 adds:
#   * one password per least-privilege PostgreSQL role (fraud_migrator, fraud_service,
#     fraud_readonly, fraud_backup) plus the administrator's, and a DATABASE_URL per job;
#   * the object-store (anchor) root and writer credentials;
#   * STAGING operator keys (alice, bob: policy_approver; carol: policy_activator;
#     rita: reviewer; sec: security_admin) and the operator registry. In a real deployment
#     every operator generates their own key (`fraud-ai operators keygen`); here they are
#     generated together only because staging is single-machine test data.
# The trust-chain signing keys are NOT generated here: they are created inside Vault
# (deploy/staging/stack.sh init-vault) and never exist as files.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="$here/secrets"
umask 077
mkdir -p "$dir"
chmod 700 "$dir"
rand() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }
keep() { [ -s "$dir/$1" ] || printf '%s' "$2" > "$dir/$1"; }

for name in postgres_password migrator_password service_password readonly_password \
            backup_password redis_password anchor_root_secret anchor_writer_secret \
            anchor_reader_secret; do
  keep "$name" "$(rand 24)"
done
keep pseudonymisation_key "$(rand 32)"
keep signing_master_key "$(rand 32)"
keep payment_webhook_secret "$(rand 32)"
pw() { cat "$dir/$1"; }
url() { printf 'postgresql+psycopg://%s:%s@postgres:5432/fraud_ai' "$1" "$(pw "$2")"; }
printf '%s' "$(url postgres postgres_password)" > "$dir/admin_database_url"
printf '%s' "$(url fraud_migrator migrator_password)" > "$dir/migrator_database_url"
printf '%s' "$(url fraud_service service_password)" > "$dir/service_database_url"
printf '%s' "$(url fraud_readonly readonly_password)" > "$dir/readonly_database_url"
printf '%s' "$(url fraud_backup backup_password)" > "$dir/backup_database_url"
printf 'redis://:%s@redis:6379/0' "$(pw redis_password)" > "$dir/redis_url"
printf 'postgresql://fraud_backup:%s@postgres:5432/fraud_ai' "$(pw backup_password)" \
  > "$dir/backup_libpq_url"

service_files=(service_database_url migrator_database_url readonly_database_url
               backup_database_url admin_database_url redis_url pseudonymisation_key
               signing_master_key payment_webhook_secret migrator_password service_password
               readonly_password backup_password anchor_writer_secret backup_libpq_url
               anchor_root_secret anchor_reader_secret)
if [ "$(id -u)" = "0" ] && chown 10001:10001 "${service_files[@]/#/$dir/}" 2>/dev/null; then
  chmod 400 "${service_files[@]/#/$dir/}"
  echo "staging secrets in $dir (service files 0400, owned by uid 10001)"
else
  chmod 444 "${service_files[@]/#/$dir/}"
  echo "staging secrets in $dir (0700 directory; files 0444 - run with sudo for 0400/uid 10001)"
fi

# ---- staging operators (per-person Ed25519 keys) and the operator registry
ops="$here/operators"
mkdir -p "$ops"
chmod 700 "$ops"
declare -A roles=([alice]=policy_approver [bob]=policy_approver [carol]=policy_activator
                  [rita]=reviewer [sec]=security_admin)
entries=()
for op in alice bob carol rita sec; do
  [ -f "$ops/$op.pem" ] || { openssl genpkey -algorithm ed25519 -out "$ops/$op.pem"; chmod 600 "$ops/$op.pem"; }
  public="$(openssl pkey -in "$ops/$op.pem" -pubout -outform DER | tail -c 32 \
    | base64 | tr '+/' '-_' | tr -d '=\n')"
  entries+=("{\"id\": \"$op\", \"roles\": [\"${roles[$op]}\"], \"public_keys\": [\"$public\"]}")
done
registry="$here/config/operators.json"
mkdir -p "$here/config"
chmod 755 "$here/config"  # public configuration only (public keys, roles)
(IFS=,; printf '{"version": 1, "operators": [%s]}\n' "${entries[*]}") > "$registry"
chmod 644 "$registry"
if [ "$(id -u)" = "0" ]; then chown 10001:10001 "$ops" "$ops"/*.pem; fi
echo "operator keys in $ops (0600); registry $registry"
