"""The 5-10 minute demo walkthrough (Stage 12): ``fraud-ai demo run``.

Drives the RUNNING demo service (``fraud-ai demo start``) over HTTP with signed v2
requests, and the real CLI for the offline checks. The steps are those in DEMO.md:

1. the service is up and ready;
2. normal events score (normal purchase, legitimate VPN user, house mover, large basket);
3. suspicious events score (high-velocity fraud, account takeover, stealth takeover);
4. a review item appears and an authenticated reviewer resolves it;
5. step-up flow: payment authentication succeeds for one, fails for another;
6. model disagreement: the shadow model and shadow policy versus the active ones;
7. an LLM explanation of an event (analyst assistance only; never used for decisions);
8. audit verification: hash chain, external anchor, anchor verification;
9. signed model and signed release verification.

Every decision printed is the service's live answer; the catalogue's measured expectation
is shown next to it. Nothing is staged or faked.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess  # nosec B404 - the fraud-ai CLI itself, fixed argument lists
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fraud_ai.service.signatures import sign, sign_v2

# A synthetic processor token reference for the fake provider: not a card, not a secret.
DEMO_TOKEN_REFERENCE = "tok_demo_synthetic_0001"  # nosec B105 - a synthetic id


class DemoClient:
    def __init__(self, base: str, credential: str, secret: str) -> None:
        import httpx

        self.http = httpx.Client(base_url=base, timeout=120)
        self.credential, self.secret = credential, secret
        self._used: dict[tuple[str, str, bytes], set[int]] = {}

    def _ts(self, key: tuple[str, str, bytes]) -> int:
        now = int(time.time())
        used = self._used.setdefault(key, set())
        ts = next(t for t in range(now, now - 250, -1) if t not in used)
        used.add(ts)
        return ts

    def request(self, method: str, path: str, payload: Any = None, **extra: str) -> Any:
        body = b"" if payload is None else json.dumps(payload).encode()
        ts = self._ts((method, path, body))
        bare, _, query = path.partition("?")
        headers = {
            "Authorization": f"Bearer {self.credential}",
            "Content-Type": "application/json",
            "X-Fraud-Timestamp": str(ts),
            "X-Fraud-Signature": sign_v2(self.secret, method, bare, ts, body, query=query),
            **extra,
        }
        return self.http.request(method, path, content=body or None, headers=headers)


def _cli(
    env: dict[str, str], *args: str, echo: Callable[[str], None]
) -> subprocess.CompletedProcess[str]:
    echo(f"    $ fraud-ai {shlex.join(args)}")
    result = subprocess.run(  # nosec B603 # noqa: S603 - our own CLI, argument list
        [sys.executable, "-m", "fraud_ai", *args],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=False,
    )
    for line in (result.stdout + result.stderr).strip().splitlines()[-8:]:
        if not line.startswith("{"):
            echo(f"      {line}")
    return result


def run(root: Path, base_url: str, *, echo: Callable[[str], None] = print) -> dict[str, Any]:
    from fraud_ai.demo.world import load_env
    from fraud_ai.trust.keys import load_private_key
    from fraud_ai.trust.operators import create_assertion

    env = load_env(root)
    creds = json.loads((root / "demo-credentials.json").read_text())
    catalogue = json.loads((root / "catalogue.json").read_text())
    cases = {c["label"]: c for c in catalogue["cases"]}
    client = DemoClient(base_url, creds["credential"], creds["signing_secret"])
    results: dict[str, Any] = {"steps": {}}

    def score(label: str) -> dict[str, Any] | None:
        case = cases.get(label)
        if case is None:
            echo(f"  - {label}: not produced by this seed (listed as missing, not faked)")
            return None
        for event in case["prelude"]:
            client.request("POST", "/v1/score", event)
        r = client.request("POST", "/v1/score", case["event"])
        body = r.json()
        decision = body.get("decision") or body.get("status")
        mark = "=" if decision == case["expected_decision"] else "!="
        reasons = ", ".join(body.get("reason_codes", [])[:3]) or "-"
        echo(f"  - {case['title']:<28} -> {decision:<24} ({mark} expected "
             f"{case['expected_decision']}); reasons: {reasons}")  # fmt: skip
        results["steps"].setdefault("decisions", {})[label] = decision
        return dict(body)

    echo("1. The service is up")
    health = client.http.get("/v1/health").status_code
    ready = client.http.get("/v1/ready").json()
    checks = ", ".join(f"{k}={v}" for k, v in ready.get("checks", {}).items())
    echo(f"  health {health}; ready: {ready.get('status')} (checks: {checks})")
    results["steps"]["ready"] = ready.get("status")

    echo("2. Legitimate customers (signed v2 requests, synthetic events)")
    for label in ("normal_purchase", "legitimate_vpn", "house_mover", "large_legitimate"):
        score(label)
    echo("3. Suspicious activity")
    for label in ("high_velocity_fraud", "account_takeover", "stealth_takeover"):
        score(label)

    echo("4. A manual review appears and an authenticated analyst resolves it")
    review_body = score("manual_review")
    if review_body is not None:
        items = client.request("GET", "/v1/reviews?status=open&limit=50").json()["items"]
        item = next(
            (i for i in items if i["assessment_id"] == review_body.get("assessment_id")), None
        )
        if item:
            echo(f"    review {item['review_id'][:8]}… priority {item['priority']} reasons "
                 f"{', '.join(item['reason_codes'][:3])}")  # fmt: skip
            refused = client.request("POST", f"/v1/reviews/{item['review_id']}/resolve",
                                     {"resolution": "legitimate", "note": "demo"})  # fmt: skip
            echo(f"    without the reviewer's own assertion: {refused.status_code} "
                 f"{refused.json()['error']['code']}")  # fmt: skip
            token = create_assertion(
                load_private_key(root / "keys" / "operator-rita.pem"), "rita",
                action="review.resolve", target=item["review_id"],
                binding={"resolution": "legitimate"}, audience="fraud-ai-admin",
            )  # fmt: skip
            ok = client.request("POST", f"/v1/reviews/{item['review_id']}/resolve",
                                {"resolution": "legitimate", "note": "customer confirmed (demo)"},
                                **{"X-Fraud-Operator-Assertion": token})  # fmt: skip
            echo(f"    as reviewer rita (signed, single-use assertion): {ok.status_code}; the "
                 "original decision is never rewritten")  # fmt: skip
            results["steps"]["review"] = ok.status_code

    echo("5. Step-up authentication")
    for label, status in (("step_up_success", "authenticated"), ("step_up_failure", "failed")):
        body = score(label)
        if body is None or body.get("decision") != "STEP_UP_AUTHENTICATION":
            continue
        aid = body["assessment_id"]
        start = client.request("POST", f"/v1/step-up/{aid}/payment",
                               {"token_reference": DEMO_TOKEN_REFERENCE, "amount_minor": 4250,
                                "currency": "GBP"})  # fmt: skip
        if start.status_code != 200:
            echo(f"    step-up start {start.status_code}: {start.text[:120]}")
            continue
        attempt = start.json().get("attempt_number", 1)
        reference = "fake_" + hashlib.sha256(f"{aid}:{attempt}".encode()).hexdigest()[:24]
        payload = json.dumps(
            {"provider_reference": reference, "status": status}, sort_keys=True
        ).encode()
        ts = int(time.time())
        cb = client.http.post(
            "/v1/callbacks/payment/fake",
            content=payload,
            headers={"x-provider-id": "fake", "x-provider-timestamp": str(ts),
                     "x-provider-signature": sign(env["PAYMENT_AUTH_WEBHOOK_SECRET"], ts, payload),
                     "Content-Type": "application/json"},
        )  # fmt: skip
        view = client.request("GET", f"/v1/assessments/{aid}").json()
        follow = client.request("GET", f"/v1/assessments/{view['latest_assessment_id']}").json()
        echo(f"    provider says {status}: callback {cb.status_code} -> follow-up decision "
             f"{follow.get('decision')} (the original stays {view.get('decision')})")  # fmt: skip
        if status == "failed":
            echo("    a failed attempt allows another, up to STEP_UP_MAX_ATTEMPTS; after that the "
                 "case goes to MANUAL_REVIEW, never to ALLOW")  # fmt: skip
        results["steps"][label] = follow.get("decision")

    echo("6. Model disagreement (shadow model and shadow policy never decide)")
    from fraud_ai.database.engine import create_db_engine, make_session_factory
    from fraud_ai.realtime.monitoring import shadow_report

    engine = create_db_engine(env["DATABASE_URL"])
    with make_session_factory(engine)() as s:
        report = shadow_report(s)
    engine.dispose()
    for name, m in (report.get("models") or {}).items():
        echo(f"    shadow model {name}: agrees on {m.get('agree')}/{m.get('compared')} events; "
             f"flags alone {m.get('fraud_only_shadow', 0)} fraud, "
             f"{m.get('false_positives_only_shadow', 0)} false positives")  # fmt: skip
    for name, p in (report.get("policies") or {}).items():
        echo(f"    shadow policy {name}: agrees on {p.get('agree')}/{p.get('compared')}")
    results["steps"]["shadow"] = bool(report.get("models"))

    echo("7. LLM explanation (analyst assistance; scoring never needs it)")
    target = review_body or next(iter(results["steps"].get("decisions", {})), None)
    if isinstance(target, dict) and target.get("assessment_id"):
        inv = client.request("POST", f"/v1/assessments/{target['assessment_id']}/investigate", {})
        if inv.status_code == 200:
            data = inv.json()
            text_ = " ".join(str(data.get("explanation") or "").split())
            echo(f"    runtime {data.get('runtime')} ({data.get('model')}): {text_[:220]}")
            echo(f"    {data.get('note')}")
            if data.get("runtime") == "reference":
                echo("    (the REFERENCE template, not a language model: set LOCAL_LLM_RUNTIME "
                     "for a real local model)")  # fmt: skip
        else:
            echo(f"    investigation unavailable: {inv.status_code}")
        results["steps"]["llm"] = inv.status_code

    echo("8. Audit: hash chain, external anchor, anchor verification")
    _cli(env, "audit", "verify", echo=echo)
    _cli(env, "audit", "anchor-now", "--always", echo=echo)
    anchored = _cli(env, "audit", "verify-anchor", echo=echo)
    results["steps"]["anchors"] = anchored.returncode == 0

    echo("9. Signed model and signed release")
    signed = _cli(env, "models", "verify-signature", "gradient-boosting-1.0.0", echo=echo)
    manifest = root / "release-demo.json"
    manifest.unlink(missing_ok=True)
    _cli({**env, "OPERATOR_ID": "sec"}, "release", "manifest", "--out", str(manifest),
         "--operator-key", str(root / "keys" / "operator-sec.pem"), echo=echo)  # fmt: skip
    verified = _cli(env, "release", "verify", str(manifest), echo=echo)
    results["steps"]["model_signature"] = signed.returncode == 0
    results["steps"]["release"] = verified.returncode == 0
    echo("Done. All data above is SYNTHETIC.")
    return results
