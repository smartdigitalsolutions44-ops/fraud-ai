#!/usr/bin/env bash
# Stage 10 container image checks. Usage: scripts/container_checks.sh <image>
# Verifies: non-root user, no git metadata / .env / databases / model or LLM artefacts /
# key files in the image, secrets absent from the environment and layer history, the
# health check is declared, and the CLI starts with a read-only root filesystem.
set -euo pipefail
image="${1:?image}"
fail() { echo "FAIL: $*" >&2; exit 1; }

user="$(docker image inspect --format '{{.Config.User}}' "$image")"
[[ "$user" == "10001:10001" ]] || fail "image user is '$user', expected 10001:10001"
uid="$(docker run --rm --entrypoint id "$image" -u)"
[[ "$uid" != "0" ]] || fail "container runs as root"

health="$(docker image inspect --format '{{json .Config.Healthcheck}}' "$image")"
[[ "$health" == *"/v1/health"* ]] || fail "no /v1/health HEALTHCHECK"

found="$(docker run --rm --entrypoint sh "$image" -c \
  'find / -xdev \( -name .git -o -name ".env" -o -name ".env.*" -o -name "*.db" -o -name "*.sqlite*" \
     -o -name "*.gguf" -o -name "*.joblib" -o -name "*.pt" -o -name ".pseudonymisation_key" \) \
     -not -path "/proc/*" -not -path "/sys/*" \
     -not -path "/usr/local/lib/python3.11/site-packages/*/tests/*" \
     -not -path "/usr/local/lib/python3.11/site-packages/torch/bin/*.pt" 2>/dev/null' || true)"
# (torch/bin/*.pt: a test fixture that ships inside the PyTorch wheel, not a model artefact.)
[[ -z "$found" ]] || fail "unexpected files in the image:\n$found"
# Public CA bundles (*.pem) are expected; private-key material is not, wherever it is.
keys="$(docker run --rm --entrypoint sh "$image" -c \
  'grep -rlE --exclude="*.py" --exclude="*.pyc" "BEGIN ([A-Z]+ )?PRIVATE KEY" /app /etc /usr/local /tmp /root /home 2>/dev/null \
     | grep -v "/site-packages/.*/tests\?/"' || true)"
[[ -z "$keys" ]] || fail "private-key material in the image:\n$keys"

envdump="$(docker image inspect --format '{{json .Config.Env}}' "$image")"
for word in PSEUDONYMISATION_KEY SERVICE_SIGNING_MASTER_KEY PAYMENT_AUTH_WEBHOOK_SECRET \
            STRIPE_API_KEY REDIS_URL DATABASE_URL HTTPS_PROXY; do
  [[ "$envdump" != *"$word="* ]] || fail "$word is baked into the image environment"
done
if docker history --no-trunc "$image" | grep -Eiq 'sk_(test|live)_|whsec_|PASSWORD=|BEGIN (RSA|EC|OPENSSH) PRIVATE'; then
  fail "a secret-looking value appears in the layer history"
fi

docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  "$image" --version >/dev/null || fail "the CLI does not start with a read-only root filesystem"
docker run --rm --read-only --tmpfs /tmp --entrypoint sh "$image" -c 'touch /app/x' 2>/dev/null \
  && fail "the root filesystem is writable under --read-only" || true

size="$(docker image inspect --format '{{.Size}}' "$image")"
echo "OK: $image user=$user size=$((size / 1024 / 1024))MB"
