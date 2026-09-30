"""Generate a SLSA v1 provenance predicate for a container build (Stage 12).

The predicate (https://slsa.dev/provenance/v1) is what ``cosign attest --type
slsaprovenance1`` wraps into a signed in-toto statement whose subject is the image digest.
It records:

* ``buildDefinition``: build type, the repository, ref and Dockerfile, the build
  arguments, and the resolved dependencies (the git commit and the base-image digest);
* ``runDetails``:
  * ``builder.id``: the GitHub Actions runner, or ``local:<hostname>`` outside CI;
  * ``metadata``: invocation id (the workflow run URL in CI), start and finish times;
  * ``byproducts``: the SBOM file and its SHA-256.

Only facts the build actually has are recorded, and nothing is invented. Outside GitHub
Actions the builder is marked ``local`` (no isolation guarantee, SLSA build level 1 at
most).

    python scripts/provenance.py --image-digest sha256:… --commit $(git rev-parse HEAD) \\
        --sbom image-sbom.cdx.json --out provenance.json [--base-image-digest sha256:…]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from datetime import UTC, datetime
from pathlib import Path

BUILD_TYPE = "https://github.com/smartdigitalsolutions44-ops/fraud-ai/docker-build/v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def predicate(args: argparse.Namespace) -> dict[str, object]:
    env = os.environ
    in_ci = env.get("GITHUB_ACTIONS") == "true"
    repo = env.get("GITHUB_REPOSITORY", "smartdigitalsolutions44-ops/fraud-ai")
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    ref = env.get("GITHUB_REF", args.ref or "")
    run_url = (
        f"{server}/{repo}/actions/runs/{env['GITHUB_RUN_ID']}/attempts/"
        f"{env.get('GITHUB_RUN_ATTEMPT', '1')}"
        if in_ci and env.get("GITHUB_RUN_ID")
        else f"local:{platform.node()}:{args.started}"
    )
    dependencies: list[dict[str, object]] = [
        {"uri": f"git+{server}/{repo}@{ref}", "digest": {"gitCommit": args.commit}}
    ]
    if args.base_image_digest:
        dependencies.append(
            {
                "uri": f"pkg:docker/{args.base_image}",
                "digest": {"sha256": args.base_image_digest.removeprefix("sha256:")},
            }
        )
    byproducts = []
    if args.sbom:
        byproducts.append(
            {"name": Path(args.sbom).name, "digest": {"sha256": _sha256(Path(args.sbom))}}
        )
    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "repository": f"{server}/{repo}",
                "ref": ref,
                "dockerfile": args.dockerfile,
                "buildArgs": dict(a.split("=", 1) for a in args.build_arg),
                "workflow": env.get("GITHUB_WORKFLOW_REF", "") if in_ci else "",
            },
            "internalParameters": {"imageDigest": args.image_digest},
            "resolvedDependencies": dependencies,
        },
        "runDetails": {
            "builder": {
                "id": f"{server}/actions/runner/github-hosted"
                if in_ci
                else f"local:{platform.node()}"
            },
            # Field names and RFC 3339 "Z" times exactly as cosign's SLSA v1 types
            # serialise them, so the signed predicate is byte-for-byte this document.
            "metadata": {
                "invocationID": run_url,
                "startedOn": args.started,
                "finishedOn": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "byproducts": byproducts,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--ref", default=None)
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument("--build-arg", action="append", default=[])
    parser.add_argument("--base-image", default="python:3.11-slim")
    parser.add_argument("--base-image-digest", default=None)
    parser.add_argument("--sbom", default=None)
    parser.add_argument("--started", default=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(json.dumps(predicate(args), indent=2, sort_keys=True) + "\n")
    print(f"provenance for {args.image_digest[:19]}… written to {args.out}")


if __name__ == "__main__":
    main()
