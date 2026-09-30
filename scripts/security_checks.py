#!/usr/bin/env python
"""Stage 10 security tooling, one entry point for local runs and CI.

    python scripts/security_checks.py closure            # pinned dependency closure
    python scripts/security_checks.py pip-audit          # known vulnerabilities (PyPI advisory DB)
    python scripts/security_checks.py bandit             # static analysis (config: pyproject.toml)
    python scripts/security_checks.py secrets            # detect-secrets vs .secrets.baseline
    python scripts/security_checks.py sbom --output sbom/fraud-ai.cdx.json

The dependency closure is computed from the *installed* ``fraud-ai`` distribution and its
declared requirements (extras ``postgres``, ``stripe`` and ``anchors``), so the audit and the SBOM
cover exactly what the service ships with, not every package that happens to be on the
machine. Ignored advisories live in ``security/pip-audit-ignore.txt`` with a reason each;
nothing is ignored silently.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from importlib import metadata
from pathlib import Path
from typing import Any

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
IGNORE_FILE = ROOT / "security" / "pip-audit-ignore.txt"
BASELINE = ROOT / ".secrets.baseline"
EXTRAS = ("postgres", "stripe", "anchors")


def closure(root: str = "fraud-ai", extras: tuple[str, ...] = EXTRAS) -> dict[str, str]:
    """name -> installed version for ``root`` and everything it (transitively) needs."""
    env = default_environment()
    seen: dict[str, str] = {}
    stack: list[tuple[str, tuple[str, ...]]] = [(root, extras)]
    while stack:
        name, wanted = stack.pop()
        key = canonicalize_name(name)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        first = key not in seen
        seen[key] = dist.version
        for raw in dist.requires or []:
            req = Requirement(raw)
            ok = req.marker is None or any(
                req.marker.evaluate({**env, "extra": e}) for e in (*wanted, "")
            )
            if not ok:
                continue
            child = canonicalize_name(req.name)
            if (child not in seen or req.extras) and (first or req.extras):
                stack.append((req.name, tuple(sorted(req.extras))))
    seen.pop(canonicalize_name(root), None)
    return dict(sorted(seen.items()))


def _pinned_file() -> Path:
    path = Path(tempfile.mkdtemp(prefix="fraud-ai-closure-")) / "requirements.txt"
    path.write_text("".join(f"{n}=={v}\n" for n, v in closure().items()))
    return path


def _ignores() -> dict[str, str]:
    out: dict[str, str] = {}
    if IGNORE_FILE.exists():
        for line in IGNORE_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            advisory, _, reason = line.partition(" ")
            if not reason.strip():
                raise SystemExit(f"{IGNORE_FILE}: {advisory} has no reason")
            out[advisory] = reason.strip()
    return out


def pip_audit() -> int:
    pinned = _pinned_file()
    proc = subprocess.run(  # noqa: S603 - fixed tool, argument list
        [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            str(pinned),
            "--no-deps",
            "--disable-pip",
            "--format",
            "json",
            "--progress-spinner",
            "off",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        print(proc.stderr or proc.stdout)
        return 2
    ignores = _ignores()
    findings: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    ignored: list[tuple[str, str]] = []
    for dep in report.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            ids = [vuln["id"], *vuln.get("aliases", [])]
            key = (dep["name"], dep["version"], vuln["id"])
            if key in seen:
                continue
            seen.add(key)
            hit = next((i for i in ids if i in ignores), None)
            fixes = ",".join(vuln.get("fix_versions", [])) or "none"
            if hit:
                ignored.append((f"{dep['name']} {dep['version']} {vuln['id']}", ignores[hit]))
            else:
                findings.append((dep["name"], dep["version"], vuln["id"], fixes))
    print(f"audited {len(report.get('dependencies', []))} pinned dependencies")
    for name, version, vid, fixes in findings:
        print(f"VULNERABLE {name} {version}: {vid} (fixed in: {fixes})")
    for what, why in ignored:
        print(f"ignored    {what}: {why}")
    print(f"{len(findings)} unignored finding(s), {len(ignored)} ignored with a reason")
    return 1 if findings else 0


def bandit() -> int:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            "fraud_ai",
            "-c",
            "pyproject.toml",
            "-f",
            "json",
            "-q",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(proc.stdout or "{}")
    results = report.get("results", [])
    for r in results:
        print(
            f"{r['issue_severity']:<6} {r['issue_confidence']:<6} {r['test_id']} "
            f"{r['filename']}:{r['line_number']} {r['issue_text']}"
        )
    totals = report.get("metrics", {}).get("_totals", {})
    print(
        f"{len(results)} finding(s); nosec-suppressed: {totals.get('nosec', 0)}; "
        f"lines scanned: {totals.get('loc', 0)}"
    )
    serious = [r for r in results if r["issue_severity"] in ("MEDIUM", "HIGH")]
    return 1 if serious else 0


def _tracked_files() -> list[str]:
    out = subprocess.run(  # noqa: S603 - fixed tool
        [shutil.which("git") or "git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [f for f in out.splitlines() if f and not f.startswith(".secrets.baseline")]


def secrets(update: bool = False) -> int:
    files = _tracked_files()
    proc = subprocess.run(  # noqa: S603 - fixed tool, argument list
        [sys.executable, "-m", "detect_secrets", "scan", *files],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    current = json.loads(proc.stdout)
    if update:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"baseline written: {sum(len(v) for v in current['results'].values())} entries")
        return 0
    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() else {"results": {}}
    known = {(f, r["hashed_secret"]) for f, rows in baseline["results"].items() for r in rows}
    new = [
        (f, r["type"], r["line_number"])
        for f, rows in current["results"].items()
        for r in rows
        if (f, r["hashed_secret"]) not in known
    ]
    for f, kind, line in new:
        print(f"NEW POSSIBLE SECRET {f}:{line} ({kind})")
    print(f"{len(new)} new finding(s) vs the reviewed baseline ({len(known)} reviewed)")
    return 1 if new else 0


def sbom(output: Path) -> int:
    pinned = _pinned_file()
    output.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(  # noqa: S603 - fixed tool, argument list
        [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "requirements",
            str(pinned),
            "--of",
            "JSON",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stderr)
        return proc.returncode
    doc: dict[str, Any] = json.loads(output.read_text())
    # Deterministic output (no timestamp/serial churn) so the file diffs cleanly.
    doc.pop("serialNumber", None)
    doc.get("metadata", {}).pop("timestamp", None)
    doc.setdefault("metadata", {})["component"] = {
        "type": "application",
        "name": "fraud-ai",
        "version": metadata.version("fraud-ai"),
        "bom-ref": "fraud-ai",
    }
    output.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"SBOM with {len(doc.get('components', []))} components written to {output}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("closure")
    sub.add_parser("pip-audit")
    sub.add_parser("bandit")
    s = sub.add_parser("secrets")
    s.add_argument("--update-baseline", action="store_true")
    b = sub.add_parser("sbom")
    b.add_argument("--output", type=Path, default=ROOT / "sbom" / "fraud-ai.cdx.json")
    args = parser.parse_args()
    if args.cmd == "closure":
        for name, version in closure().items():
            print(f"{name}=={version}")
        return
    code = {
        "pip-audit": pip_audit,
        "bandit": bandit,
        "secrets": lambda: secrets(args.update_baseline),
        "sbom": lambda: sbom(args.output),
    }[args.cmd]()
    sys.exit(code)


if __name__ == "__main__":
    main()
