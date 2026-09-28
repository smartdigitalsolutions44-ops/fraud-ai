#!/usr/bin/env bash
# Generate random STAGING secrets (never reuse them anywhere else). Git-ignored.
# Re-running rotates everything (existing data then needs the old pseudonymisation key;
# see DISASTER_RECOVERY.md before rotating it).
#
# Compose file secrets are plain bind mounts: they keep their host owner and mode, and the
# service runs as uid 10001. Run this with sudo so the files become 0400 owned by 10001
# (preferred). Without root the files fall back to 0444 inside a 0700 directory: the
# directory protects them on the host, and the service logs a permissions warning.
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)/secrets"
umask 077
mkdir -p "$dir"
chmod 700 "$dir"
rand() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }
pg="$(rand 24)"; redis="$(rand 24)"
printf '%s' "$pg" > "$dir/postgres_password"
printf '%s' "$redis" > "$dir/redis_password"
printf 'postgresql+psycopg://fraud_ai:%s@postgres:5432/fraud_ai' "$pg" > "$dir/database_url"
printf 'redis://:%s@redis:6379/0' "$redis" > "$dir/redis_url"
rand 32 > "$dir/pseudonymisation_key"
rand 32 > "$dir/signing_master_key"
rand 32 > "$dir/payment_webhook_secret"
service_files=(database_url redis_url pseudonymisation_key signing_master_key payment_webhook_secret)
if chown 10001:10001 "${service_files[@]/#/$dir/}" 2>/dev/null; then
  chmod 400 "${service_files[@]/#/$dir/}"
  echo "wrote staging secrets to $dir (service files 0400, owned by uid 10001)"
else
  chmod 444 "${service_files[@]/#/$dir/}"
  echo "wrote staging secrets to $dir (0700 directory; files 0444 - run with sudo for 0400/uid 10001)"
fi
