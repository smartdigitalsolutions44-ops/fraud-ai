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

# Stage 11: a STAGING-ONLY Ed25519 model-signing key (PKCS#8 PEM, 0600). The private key
# stays in deploy/staging/signing/ (git-ignored, never mounted into the service); compose
# only gets the public key, through deploy/staging/.env.
signing="$(cd "$(dirname "$0")" && pwd)/signing"
mkdir -p "$signing"
chmod 700 "$signing"
if [ ! -f "$signing/model.pem" ]; then
  openssl genpkey -algorithm ed25519 -out "$signing/model.pem"
  chmod 600 "$signing/model.pem"
fi
public="$(openssl pkey -in "$signing/model.pem" -pubout -outform DER | tail -c 32 \
  | base64 | tr '+/' '-_' | tr -d '=\n')"
printf 'MODEL_SIGNING_PUBLIC_KEYS=%s\n' "$public" > "$(dirname "$signing")/.env"
if [ "$(id -u)" = "0" ]; then chown 10001:10001 "$signing" "$signing/model.pem"; fi
echo "model signing key: $signing/model.pem (public key in deploy/staging/.env)"

