#!/usr/bin/env bash
# Stage 12: sign a built image, attach SLSA provenance and a CycloneDX SBOM, and write the
# evidence file that the signed release manifest records (fraud-ai release manifest
# --image-evidence ...).
#
#   scripts/image_sign.sh <local-image> <registry/repo> <cosign-key> <cosign-public-key> <out-dir>
#
# <cosign-key> is a KMS URI (hashivault://fraud-ai-image, awskms://..., gcpkms://...) or a
# cosign key file. It is a DEDICATED image key, never the model, audit, release or API key.
# Everything is addressed by DIGEST (never a tag). No Rekor upload (--tlog-upload=false):
# the registry is private, and trust rests on the key (see TRUST_CHAIN.md).
# Needs: docker, cosign, openssl, python3; Trivy runs from the aquasec/trivy image.
set -euo pipefail
image="${1:?local image}"; repo="${2:?registry/repo}"; key="${3:?cosign key}"
pub="${4:?cosign public key}"; out="${5:?out dir}"
mkdir -p "$out"
commit="${GIT_COMMIT:-$(git rev-parse HEAD)}"
ref_name="${GIT_REF:-refs/heads/$(git rev-parse --abbrev-ref HEAD)}"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
insecure=()
case "$repo" in localhost*|127.0.0.1*) insecure=(--allow-insecure-registry --allow-http-registry) ;; esac

docker tag "$image" "$repo:$commit"
docker push -q "$repo:$commit" >/dev/null
ref="$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$repo:$commit" \
  | grep "^$repo@" | head -1)"
digest="${ref#*@}"
[[ "$digest" == sha256:* ]] || { echo "no registry digest for $repo" >&2; exit 1; }
echo "image $ref"

# Image SBOM (CycloneDX) from Trivy, scanning exactly this image.
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(cd "$out" && pwd):/out" \
  aquasec/trivy:0.58.1 image --quiet --format cyclonedx --output /out/image-sbom.cdx.json "$image"

base_digest="$(docker image inspect python:3.11-slim --format '{{index .RepoDigests 0}}' 2>/dev/null \
  | sed 's/.*@//' || true)"
python3 "$(dirname "$0")/provenance.py" --image-digest "$digest" --commit "$commit" \
  --ref "$ref_name" \
  --sbom "$out/image-sbom.cdx.json" --started "$started" --out "$out/provenance.json" \
  ${WITH_TORCH:+--build-arg "WITH_TORCH=$WITH_TORCH"} \
  ${base_digest:+--base-image-digest "$base_digest"}

cosign sign --yes --tlog-upload=false "${insecure[@]}" --key "$key" "$ref"
cosign attest --yes --tlog-upload=false "${insecure[@]}" --key "$key" \
  --type slsaprovenance1 --predicate "$out/provenance.json" "$ref"
cosign attest --yes --tlog-upload=false "${insecure[@]}" --key "$key" \
  --type cyclonedx --predicate "$out/image-sbom.cdx.json" "$ref"

sig_ref="$(cosign triangulate "${insecure[@]}" "$ref")"
att_ref="$(cosign triangulate --type attestation "${insecure[@]}" "$ref")"
fingerprint="sha256:$(openssl pkey -pubin -in "$pub" -outform DER | sha256sum | cut -d' ' -f1)"
key_ref="$key"
[[ "$key" == *://* ]] || key_ref="file:$(basename "$key")"
# Read the attestations back (verifying them) and record the digest of what was SIGNED.
for kind in slsaprovenance1 cyclonedx; do
  cosign verify-attestation --key "$pub" --insecure-ignore-tlog "${insecure[@]}" \
    --type "$kind" "$ref" > "$out/attestation-$kind.jsonl" 2>/dev/null
done
python3 - "$out" "$repo" "$digest" "$sig_ref" "$att_ref" "$fingerprint" "$key_ref" <<'EOF'
import base64, hashlib, json, sys
out, repo, digest, sig_ref, att_ref, fingerprint, key_ref = sys.argv[1:]
def canon(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()
def signed(kind, source):
    want = canon(json.load(open(f"{out}/{source}")))
    for line in open(f"{out}/attestation-{kind}.jsonl"):
        if line.startswith("{"):
            statement = json.loads(base64.b64decode(json.loads(line)["payload"]))
            subjects = {s["digest"]["sha256"] for s in statement["subject"]}
            if digest.removeprefix("sha256:") in subjects and canon(statement["predicate"]) == want:
                return want
    sys.exit(f"the signed {kind} attestation does not match {source}")
evidence = {
    "image": repo, "digest": digest, "signature_ref": sig_ref,
    "signing_key_fingerprint": fingerprint, "signing_key_ref": key_ref,
    "provenance_ref": att_ref, "provenance_sha256": signed("slsaprovenance1", "provenance.json"),
    "provenance_predicate_type": "https://slsa.dev/provenance/v1",
    "sbom_ref": att_ref, "sbom_sha256": signed("cyclonedx", "image-sbom.cdx.json"),
}
json.dump(evidence, open(f"{out}/image-evidence.json", "w"), indent=2, sort_keys=True)
print(json.dumps(evidence, indent=2, sort_keys=True))
EOF
echo "evidence: $out/image-evidence.json"
