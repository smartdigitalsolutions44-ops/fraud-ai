#!/usr/bin/env bash
# Stage 11 end-to-end smoke test of a built image against PostgreSQL (CI container job).
#
#   scripts/container_smoke.sh <image> <database-url> [out-dir]
#
# 1. migrate; bootstrap a SYNTHETIC world (gradient boosting + GRU + logistic regression)
# 2. with MODEL_SIGNATURES_REQUIRED=true, UNSIGNED models must refuse start-up
# 3. sign every model with a throwaway Ed25519 key (generated here, never kept)
# 4. the service must start read-only, non-root, with all capabilities dropped; the GRU must
#    load (PyTorch present) and /v1/ready must report every check ok
# Results go to <out-dir>/container-smoke.json (no secrets in it).
set -euo pipefail
image="${1:?image}"
db="${2:?database url}"
out="${3:-container-smoke}"
# KINDS=gradient-boosting,logistic for the torch-less verification image (no GRU check).
kinds="${KINDS:-gradient-boosting,gru,logistic}"
python_bin="${PYTHON_BIN:-python}"  # python3 on distroless (research image)
declare -A names=([gradient-boosting]=gradient-boosting-1.0.0 [gru]=gru-1.0.0
                  [logistic]=logistic-regression-1.0.0)
mkdir -p "$out"
work="$(mktemp -d)"
cleanup() {
  docker rm -f fraud-ai-smoke >/dev/null 2>&1 || true
  # The container wrote the models and the throwaway key as uid 10001: delete them from a
  # root container (the host user may not own them), then the directory itself.
  docker run --rm -u 0 --entrypoint "$python_bin" -v "$work:/w" "$image" -c \
    'import shutil; [shutil.rmtree(p, ignore_errors=True) for p in ("/w/models", "/w/keys")]' \
    >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/models" "$work/keys"
chmod 0777 "$work/models" "$work/keys"  # the image runs as uid 10001
key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
common=(--rm --network host -e "DATABASE_URL=$db" -e "PSEUDONYMISATION_KEY=$key"
        -e MODEL_DIRECTORY=/models -v "$work/models:/models")
fail() { echo "SMOKE FAILED: $*" >&2; exit 1; }

docker run "${common[@]}" "$image" db migrate
docker run "${common[@]}" -v "$PWD/scripts:/scripts:ro" --entrypoint "$python_bin" "$image" \
  /scripts/bootstrap_world.py --models /models --kinds "$kinds"

public="$(docker run --rm -v "$work/keys:/keys" "$image" keys generate --purpose model \
  --out /keys/model.pem | awk '/^public key/ {print $3}')"
[[ -n "$public" ]] || fail "no public key generated"
trusted=(-e MODEL_SIGNATURES_REQUIRED=true -e "MODEL_SIGNING_PUBLIC_KEYS=$public")

# Unsigned models: start-up must be refused.
if timeout 120 docker run "${common[@]}" "${trusted[@]}" --read-only --tmpfs /tmp \
     -e SERVICE_PORT=8097 "$image" service run >"$work/unsigned.log" 2>&1; then
  fail "the service started with unsigned models"
fi
grep -q "model signature check failed" "$work/unsigned.log" || fail "unexpected refusal: $(tail -5 "$work/unsigned.log")"

IFS=, read -ra kind_list <<<"$kinds"
for kind in "${kind_list[@]}"; do
  docker run "${common[@]}" "${trusted[@]}" -v "$work/keys:/keys:ro" "$image" \
    models sign "${names[$kind]}" --key /keys/model.pem
  docker run "${common[@]}" "${trusted[@]}" "$image" models verify-signature "${names[$kind]}"
done

docker run -d --name fraud-ai-smoke --network host --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true -e "DATABASE_URL=$db" -e "PSEUDONYMISATION_KEY=$key" \
  -e MODEL_DIRECTORY=/models -v "$work/models:/models:ro" "${trusted[@]}" \
  -e SERVICE_HOST=127.0.0.1 -e SERVICE_PORT=8098 "$image" >/dev/null
ready=""
for _ in $(seq 1 90); do
  ready="$(curl -fsS http://127.0.0.1:8098/v1/ready 2>/dev/null || true)"
  [[ "$ready" == *'"status":"ready"'* ]] && break
  sleep 2
done
docker logs fraud-ai-smoke >"$work/service.log" 2>&1 || true
[[ "$ready" == *'"status":"ready"'* ]] || fail "not ready: $ready $(tail -20 "$work/service.log")"
if [[ ",$kinds," == *",gru,"* ]]; then
  grep -q 'gru-1.0.0' "$work/service.log" || fail "the GRU was not loaded"
fi
user="$(docker exec fraud-ai-smoke "$python_bin" -c 'import os; print(os.getuid())')"
[[ "$user" == "10001" ]] || fail "running as uid $user"
warmed="$(grep -o 'model cache warmed: .*' "$work/service.log" | head -1 | cut -c1-300)"
python3 - "$out/container-smoke.json" "$image" "$ready" "$warmed" "$user" <<'EOF'
import json, subprocess, sys
path, image, ready, warmed, user = sys.argv[1:]
size = int(subprocess.run(["docker", "image", "inspect", "--format", "{{.Size}}", image],
                          capture_output=True, text=True, check=True).stdout.strip())
json.dump({"image": image, "image_bytes": size, "ready": json.loads(ready),
           "model_cache": warmed, "uid": int(user),
           "unsigned_models_refused": True, "signed_models_loaded": True},
          open(path, "w"), indent=2)
print(open(path).read())
EOF
echo "SMOKE OK"
