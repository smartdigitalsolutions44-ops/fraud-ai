#!/usr/bin/env python
"""Stage 10 end-to-end check against a running (staging) service. SYNTHETIC/TEST data only.

signed merchant request → scoring → policy → step-up → provider callback → follow-up
assessment → review → investigation (plus a WebAuthn step-up with a TEST-ONLY software
authenticator).

    python scripts/staging_e2e.py --base-url https://staging.example.test \
        --credential fak_....secret --signing-secret <hex> --webhook-secret <secret> \
        --events live.jsonl --rp-id staging.example.test --origin https://staging.example.test

Every request is signed (``X-Fraud-Timestamp`` / ``X-Fraud-Signature``). The payment
step-up uses the DEVELOPMENT FAKE provider, so this only runs where staging explicitly
allows it (``PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING=true``); the fake is not 3-D Secure.
Exit status 0 only if every step behaved as expected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fraud_ai.service.signatures import sign
from fraud_ai.stepup.payment import FakePaymentAuthProvider


class E2EError(AssertionError):
    pass


class SignedClient:
    def __init__(self, base: str, credential: str, signing_secret: str, *, verify: Any = True):
        self.base = base.rstrip("/")
        self.credential = credential
        self.secret = signing_secret
        self.verify = verify
        self._used: dict[bytes, set[int]] = {}
        self._lock = threading.Lock()

    def _ts(self, body: bytes) -> int:
        now = int(time.time())
        with self._lock:
            used = self._used.setdefault(body, set())
            ts = next(t for t in range(now, now - 250, -1) if t not in used)
            used.add(ts)
            return ts

    def request(
        self, method: str, path: str, payload: Any = None, *, retries: int = 5
    ) -> httpx.Response:
        """Signed request; a 429 is retried after its ``Retry-After`` (bounded), each attempt
        freshly signed (the service rejects a re-used timestamp/signature as a replay)."""
        body = b"" if payload is None else json.dumps(payload).encode()
        for attempt in range(retries + 1):
            ts = self._ts(body)
            headers = {
                "Authorization": f"Bearer {self.credential}",
                "Content-Type": "application/json",
                "X-Fraud-Timestamp": str(ts),
                "X-Fraud-Signature": sign(self.secret, ts, body),
            }
            response = httpx.request(
                method,
                self.base + path,
                content=body or None,
                headers=headers,
                timeout=120,
                verify=self.verify,
            )
            if response.status_code != 429 or attempt == retries:
                return response
            time.sleep(min(float(response.headers.get("Retry-After", "1")), 30.0))
        raise AssertionError("unreachable")


def _expect(cond: bool, message: str) -> None:
    if not cond:
        raise E2EError(message)


def run(
    client: SignedClient,
    events: list[dict[str, Any]],
    *,
    webhook_secret: str,
    rp_id: str,
    origin: str,
    session_lookup: Any = None,
) -> dict[str, Any]:
    """``session_lookup(assessment_id) -> (user_id, session_id)`` enables the WebAuthn leg
    (it needs the assessed event's user and session, which the merchant already knows)."""
    report: dict[str, Any] = {"steps": []}

    def step(name: str, **info: Any) -> None:
        report["steps"].append({"step": name, **info})

    policy = client.request("GET", "/v1/policy")
    _expect(policy.status_code == 200, f"policy: {policy.text}")
    step("policy", version=policy.json()["policy_version"])

    wanted = {"STEP_UP_AUTHENTICATION": [], "MANUAL_REVIEW": []}
    for event in events:
        r = client.request("POST", "/v1/score", event)
        _expect(r.status_code in (200, 202), f"score: {r.status_code} {r.text[:200]}")
        body = r.json()
        decision = body.get("decision")
        if body.get("status") == "decided" and decision in wanted:
            wanted[decision].append(body)
        if len(wanted["STEP_UP_AUTHENTICATION"]) >= 2 and wanted["MANUAL_REVIEW"]:
            break
    _expect(len(wanted["STEP_UP_AUTHENTICATION"]) >= 2, "no two STEP_UP decisions in the stream")
    _expect(bool(wanted["MANUAL_REVIEW"]), "no MANUAL_REVIEW decision in the stream")
    for body in wanted["STEP_UP_AUTHENTICATION"] + wanted["MANUAL_REVIEW"]:
        forbidden = {"ml_probability", "calibrated_score", "model_scores", "features"} & set(body)
        _expect(not forbidden, f"internals leaked: {forbidden}")
    step(
        "scoring",
        step_ups=len(wanted["STEP_UP_AUTHENTICATION"]),
        reviews=len(wanted["MANUAL_REVIEW"]),
    )

    # Payment step-up through the provider, completed by its signed callback.
    first = wanted["STEP_UP_AUTHENTICATION"][0]["assessment_id"]
    start = client.request(
        "POST",
        f"/v1/step-up/{first}/payment",
        {"token_reference": "tok_e2e_synthetic_0001", "amount_minor": 4250, "currency": "GBP"},
    )
    _expect(start.status_code == 200 and start.json()["status"] == "pending", start.text)
    fake = FakePaymentAuthProvider(webhook_secret)
    reference = "fake_" + hashlib.sha256(f"{first}:1".encode()).hexdigest()[:24]
    headers, payload = fake.simulate_callback(reference)
    cb = httpx.post(
        client.base + "/v1/callbacks/payment/fake",
        content=payload,
        headers={**headers, "Content-Type": "application/json"},
        timeout=60,
        verify=client.verify,
    )
    _expect(cb.status_code == 200 and cb.json()["result"] == "SUCCESS", f"callback: {cb.text}")
    replay = httpx.post(
        client.base + "/v1/callbacks/payment/fake",
        content=payload,
        headers={**headers, "Content-Type": "application/json"},
        timeout=60,
        verify=client.verify,
    )
    _expect(replay.status_code == 401, "a replayed callback was accepted")
    view = client.request("GET", f"/v1/assessments/{first}").json()
    followup = client.request("GET", f"/v1/assessments/{view['latest_assessment_id']}").json()
    _expect(view["decision"] == "STEP_UP_AUTHENTICATION", "the original assessment changed")
    _expect(followup["decision"] == "ALLOW_WITH_MONITORING", f"follow-up: {followup}")
    _expect(followup["supersedes_assessment_id"] == first, "follow-up does not supersede")
    step("payment_step_up", followup=followup["decision"])

    # WebAuthn step-up with a TEST-ONLY software authenticator.
    if session_lookup is not None:
        from tests.service_helpers import SoftAuthenticator

        second = wanted["STEP_UP_AUTHENTICATION"][1]["assessment_id"]
        user_id, session_id = session_lookup(second)
        auth = SoftAuthenticator(rp_id=rp_id, origin=origin)
        ch = client.request(
            "POST", "/v1/webauthn/registrations/challenge", {"user_id": user_id}
        ).json()
        reg = client.request(
            "POST",
            "/v1/webauthn/registrations",
            {"challenge_id": ch["challenge_id"], "credential": auth.register(ch["public_key"])},
        )
        _expect(reg.status_code == 201, f"registration: {reg.text}")
        ch = client.request(
            "POST", f"/v1/step-up/{second}/webauthn/challenge", {"session_id": session_id}
        ).json()
        done = client.request(
            "POST",
            "/v1/step-up/webauthn/verify",
            {
                "challenge_id": ch["challenge_id"],
                "session_id": session_id,
                "credential": auth.assertion(ch["public_key"]),
            },
        )
        _expect(done.status_code == 200 and done.json()["result"] == "SUCCESS", done.text)
        step("webauthn_step_up", followup=done.json()["followup"]["decision"])

    # Review: find the MANUAL_REVIEW item and resolve it.
    review_assessment = wanted["MANUAL_REVIEW"][0]["assessment_id"]
    items = client.request("GET", "/v1/reviews?status=open&limit=200").json()["items"]
    item = next(i for i in items if i["assessment_id"] == review_assessment)
    resolved = client.request(
        "POST",
        f"/v1/reviews/{item['review_id']}/resolve",
        {"resolution": "legitimate", "note": "e2e synthetic check"},
    )
    _expect(resolved.status_code == 200, f"resolve: {resolved.text}")
    _expect(resolved.json()["assessment"]["decision"] == "MANUAL_REVIEW", "decision rewritten")
    step("review", resolution="legitimate")

    # Investigation (optional LLM; the reference template counts as a runtime here).
    inv = client.request("POST", f"/v1/assessments/{review_assessment}/investigate", {})
    _expect(inv.status_code in (200, 503), f"investigate: {inv.status_code} {inv.text[:200]}")
    step(
        "investigation",
        status=inv.status_code,
        runtime=inv.json().get("runtime") if inv.status_code == 200 else "unavailable",
    )

    metrics = client.request("GET", "/v1/metrics")
    _expect(metrics.status_code == 200, "metrics")
    step("metrics", bytes=len(metrics.content))
    report["ok"] = True
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--credential", required=True)
    parser.add_argument("--signing-secret", required=True)
    parser.add_argument("--webhook-secret", required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--rp-id", default="localhost")
    parser.add_argument("--origin", default="http://localhost:8080")
    parser.add_argument("--ca-bundle", default=None, help="TLS CA for a staging certificate")
    args = parser.parse_args()
    events = [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
    client = SignedClient(
        args.base_url, args.credential, args.signing_secret, verify=args.ca_bundle or True
    )
    try:
        report = run(
            client, events, webhook_secret=args.webhook_secret, rp_id=args.rp_id, origin=args.origin
        )
    except E2EError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(1)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
