"""Stage 12 operator authentication: signed single-use assertions, roles, two-person approval
with authenticated identities, the reviewer boundary on the API, and admin audit."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from click.testing import CliRunner
from sqlalchemy import select, text

from fraud_ai import audit
from fraud_ai.cli.main import cli
from fraud_ai.config.settings import Settings, get_settings
from fraud_ai.database.engine import session_scope
from fraud_ai.database.models import OperatorAssertion, PolicyApproval, ReviewOutcome
from fraud_ai.risk.approvals import (
    EvidenceCheck,
    approval_binding,
    approve,
    ensure_approved,
    status,
)
from fraud_ai.risk.promotion import promote
from fraud_ai.risk.registry import PolicyError, get_policy_record
from fraud_ai.trust import keys as tk
from fraud_ai.trust.operators import (
    ACTIONS,
    OperatorAuthError,
    OperatorRegistry,
    authenticate,
    create_assertion,
    verify_assertion,
)
from tests.operator_helpers import Operators, make_operators
from tests.realtime_world import P2, World, open_world
from tests.service_helpers import Harness, make_harness

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
AUD = "fraud-ai-admin"


@pytest.fixture
def ops(tmp_path: Path) -> Operators:
    return make_operators(tmp_path / "ops")


@pytest.fixture
def registry(ops: Operators) -> OperatorRegistry:
    return OperatorRegistry.load(ops.registry)


def _verify(token: str, registry: OperatorRegistry, **kw: Any) -> Any:
    args: dict[str, Any] = {
        "audience": AUD,
        "action": "policy.approve",
        "target": P2,
        "binding": {"definition_sha256": "d" * 64},
        "now": NOW,
    }
    args.update(kw)
    return verify_assertion(token, registry, **args)


def _token(ops: Operators, who: str = "alice", **kw: Any) -> str:
    args: dict[str, Any] = {
        "action": "policy.approve",
        "target": P2,
        "binding": {"definition_sha256": "d" * 64},
        "audience": AUD,
        "now": NOW,
    }
    args.update(kw)
    return create_assertion(ops.keys[who], who, **args)


def _code(fn: Any) -> str:
    with pytest.raises(OperatorAuthError) as err:
        fn()
    return err.value.code


# ------------------------------------------------------------------ registry
def test_registry_validation(ops: Operators, tmp_path: Path) -> None:
    good = json.loads(ops.registry.read_text())
    reg = OperatorRegistry.parse(json.dumps(good))
    assert set(reg.operators) == {"alice", "bob", "carol", "rita", "sec"}
    assert reg.operators["carol"].may("policy.activate") and not reg.operators["carol"].may(
        "policy.approve"
    )
    bad_cases: list[Any] = [
        "not json",
        {"version": 2, "operators": good["operators"]},
        {"version": 1, "operators": []},
        {"version": 1, "operators": [{**good["operators"][0], "roles": ["root"]}]},
        {"version": 1, "operators": [{**good["operators"][0], "id": "Bad Id!"}]},
        {"version": 1, "operators": [good["operators"][0], good["operators"][0]]},
        # one key registered for two operators
        {
            "version": 1,
            "operators": [
                good["operators"][0],
                {**good["operators"][1], "public_keys": good["operators"][0]["public_keys"]},
            ],
        },
        {"version": 1, "operators": [{**good["operators"][0], "extra": "field"}]},
    ]
    for case in bad_cases:
        text_ = case if isinstance(case, str) else json.dumps(case)
        assert _code(lambda t=text_: OperatorRegistry.parse(t)) == "REGISTRY_INVALID"
    assert _code(lambda: OperatorRegistry.load(tmp_path / "missing.json")) == "REGISTRY_MISSING"


def test_operator_keys_must_not_double_as_trust_keys(ops: Operators) -> None:
    from fraud_ai.trust.operators import registry_from_settings

    alice = tk.encode_public(ops.keys["alice"].public)
    settings = Settings(
        database_url="sqlite:///x.db",
        operator_registry_file=ops.registry,
        audit_anchor_public_keys=alice,
    )
    with pytest.raises(OperatorAuthError, match="trusted for both"):
        registry_from_settings(settings)


# ------------------------------------------------------------------ assertions
def test_valid_assertion_and_every_mismatch(ops: Operators, registry: OperatorRegistry) -> None:
    token = _token(ops)
    ok = _verify(token, registry)
    assert ok.operator_id == "alice" and ok.key_id == ops.keys["alice"].key_id
    assert ok.actor == "operator:alice" and "policy_approver" in ok.roles
    assert _code(lambda: _verify(token, registry, action="policy.activate")) == "WRONG_ACTION"
    assert _code(lambda: _verify(token, registry, target="risk-policy-9")) == "WRONG_TARGET"
    assert _code(lambda: _verify(token, registry, binding={"definition_sha256": "e" * 64})) == (
        "WRONG_BINDING"
    )
    assert _code(lambda: _verify(token, registry, audience="other-deployment")) == (
        "WRONG_AUDIENCE"
    )
    later = NOW + timedelta(minutes=10)
    assert _code(lambda: _verify(token, registry, now=later)) == "EXPIRED_ASSERTION"
    long_lived = _token(ops, lifetime_seconds=3600)
    assert _code(lambda: _verify(long_lived, registry)) == "LIFETIME_TOO_LONG"
    future = _token(ops, now=NOW + timedelta(minutes=5))
    assert _code(lambda: _verify(future, registry)) in {"NOT_YET_VALID", "INVALID_ASSERTION"}


def test_roles_come_from_the_registry_not_the_token(
    ops: Operators, registry: OperatorRegistry
) -> None:
    # carol is an activator: an approval assertion signed by her is refused (FORBIDDEN),
    # whatever it claims.
    token = _token(ops, "carol")
    assert _code(lambda: _verify(token, registry)) == "FORBIDDEN"
    for action, role in ACTIONS.items():
        assert role, action


def test_forgeries_are_refused(ops: Operators, registry: OperatorRegistry) -> None:
    claims = jwt.decode(_token(ops), options={"verify_signature": False})
    # alg=none (unsigned) token
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    assert _code(lambda: _verify(f"{header}.{body}.", registry)) == "BAD_ALGORITHM"
    # HMAC token keyed with a public key (algorithm confusion)
    hs = jwt.encode(claims, "x" * 32, algorithm="HS256",
                    headers={"kid": ops.keys["alice"].key_id})  # fmt: skip
    assert _code(lambda: _verify(hs, registry)) == "BAD_ALGORITHM"
    # signed by an unregistered key
    stranger = tk.generate()
    unknown = create_assertion(
        stranger, "alice", action="policy.approve", target=P2,
        binding={"definition_sha256": "d" * 64}, audience=AUD, now=NOW,
    )  # fmt: skip
    assert _code(lambda: _verify(unknown, registry)) == "UNKNOWN_KEY"
    # alice's key, bob's name: impersonation
    as_bob = create_assertion(
        ops.keys["alice"], "bob", action="policy.approve", target=P2,
        binding={"definition_sha256": "d" * 64}, audience=AUD, now=NOW,
    )  # fmt: skip
    assert _code(lambda: _verify(as_bob, registry)) == "IDENTITY_MISMATCH"
    # a registered kid, but signed with another key
    forged = jwt.encode(claims, stranger.private, algorithm="EdDSA",
                        headers={"kid": ops.keys["alice"].key_id})  # fmt: skip
    assert _code(lambda: _verify(forged, registry)) == "INVALID_ASSERTION"
    # tampered payload
    head, payload, sig = _token(ops).split(".")
    changed = json.loads(base64.urlsafe_b64decode(payload + "=="))
    changed["tgt"] = "risk-policy-9.9.9"
    evil = base64.urlsafe_b64encode(json.dumps(changed).encode()).rstrip(b"=").decode()
    assert _code(lambda: _verify(f"{head}.{evil}.{sig}", registry, target="risk-policy-9.9.9")) == (
        "INVALID_ASSERTION"
    )
    assert _code(lambda: _verify("garbage", registry)) == "MALFORMED_ASSERTION"


def test_disabled_operator(ops: Operators, tmp_path: Path) -> None:
    data = json.loads(ops.registry.read_text())
    data["operators"][0]["disabled"] = True  # alice
    reg = OperatorRegistry.parse(json.dumps(data))
    assert _code(lambda: _verify(_token(ops), reg)) == "OPERATOR_DISABLED"


# ------------------------------------------------------------------ with a database
@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


def _settings(w: World, ops: Operators, **kw: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": w.url,
        "operator_auth_required": True,
        "operator_registry_file": ops.registry,
    }
    values.update(kw)
    return Settings(**values)


def _candidate(w: World) -> str:
    with session_scope(w.factory) as s:
        promote(s, P2, "shadow", actor="cli:a", note="shadowed")
        promote(s, P2, "evaluation", actor="cli:a", note="simulated",
                evidence={"simulation": {"events": 1}})  # fmt: skip
        promote(s, P2, "candidate", actor="cli:a", note="ok", approved=True)
        return get_policy_record(s, P2).definition_sha256


def _approve(w: World, ops: Operators, who: str, note: str, definition: str) -> PolicyApproval:
    settings = _settings(w, ops)
    binding = approval_binding(definition, note)
    token = _token(ops, who, binding=binding, now=datetime.now(UTC))
    with session_scope(w.factory) as s:
        identity = authenticate(s, settings, token, action="policy.approve", target=P2,
                                binding=binding)  # fmt: skip
        row = approve(s, P2, operator=None, note=note, ttl_hours=72, identity=identity,
                      evidence=token)  # fmt: skip
        s.expunge(row)
        return row


def test_authenticated_two_person_approval(w: World, ops: Operators) -> None:
    definition = _candidate(w)
    evidence = EvidenceCheck.from_settings(_settings(w, ops))
    assert evidence is not None
    first = _approve(w, ops, "alice", "simulation reviewed", definition)
    assert first.operator == "alice" and first.assertion and first.assertion_jti
    with pytest.raises(PolicyError, match="already approved"):
        _approve(w, ops, "alice", "again", definition)
    _approve(w, ops, "bob", "second pair of eyes", definition)
    with w.factory() as s:
        state = ensure_approved(s, P2, required=2, evidence=evidence)
        assert state.valid_operators == ("alice", "bob")
        assert s.scalar(select(OperatorAssertion).where(OperatorAssertion.operator_id == "bob"))
        actions = [e.action for e in audit.list_events(s, limit=50)]
        assert actions.count("operator.authenticated") == 2  # the refused retry rolled back
    # The evidence is re-verified against the CURRENT registry: bob loses the role.
    data = json.loads(ops.registry.read_text())
    for entry in data["operators"]:
        if entry["id"] == "bob":
            entry["roles"] = ["reviewer"]
    ops.registry.write_text(json.dumps(data))
    demoted = EvidenceCheck.from_settings(_settings(w, ops))
    with w.factory() as s:
        state = status(s, P2, required=2, evidence=demoted)
        assert state.valid_operators == ("alice",) and "FORBIDDEN" in state.unverified[0]


def test_replayed_and_expired_assertions(w: World, ops: Operators) -> None:
    definition = _candidate(w)
    settings = _settings(w, ops)
    binding = approval_binding(definition, "reviewed")
    token = _token(ops, binding=binding, now=datetime.now(UTC))
    with session_scope(w.factory) as s:
        authenticate(s, settings, token, action="policy.approve", target=P2, binding=binding)
    with session_scope(w.factory) as s, pytest.raises(OperatorAuthError) as err:
        authenticate(s, settings, token, action="policy.approve", target=P2, binding=binding)
    assert err.value.code == "REPLAYED_ASSERTION"
    old = _token(ops, binding=binding, now=datetime.now(UTC) - timedelta(hours=1))
    with session_scope(w.factory) as s, pytest.raises(OperatorAuthError) as err:
        authenticate(s, settings, old, action="policy.approve", target=P2, binding=binding)
    assert err.value.code == "EXPIRED_ASSERTION"


def test_rows_inserted_behind_the_tooling_do_not_count(w: World, ops: Operators) -> None:
    definition = _candidate(w)
    evidence = EvidenceCheck.from_settings(_settings(w, ops))
    _approve(w, ops, "alice", "reviewed", definition)
    with session_scope(w.factory) as s:
        # A DBA-style insert: no assertion at all.
        s.add(PolicyApproval(policy_version=P2, policy_sha256=definition, operator="bob",
                             note="trust me", approved_at=datetime.now(UTC)))  # fmt: skip
        # Alice's real assertion copied onto a fake "mallory" approval.
        real = s.scalar(select(PolicyApproval).where(PolicyApproval.operator == "alice"))
        assert real is not None
        s.add(PolicyApproval(policy_version=P2, policy_sha256=definition, operator="mallory",
                             note=real.note, approved_at=real.approved_at,
                             assertion=real.assertion, assertion_jti="copied-jti"))  # fmt: skip
    with w.factory() as s:
        state = status(s, P2, required=2, evidence=evidence)
        assert state.valid_operators == ("alice",)
        reasons = " ".join(state.unverified)
        assert "unauthenticated" in reasons and "another operator" in reasons
        with pytest.raises(PolicyError, match="not verifiable"):
            ensure_approved(s, P2, required=2, evidence=evidence)
        # Without operator authentication (development) the Stage 11 rows would count.
        assert len(status(s, P2, required=2).valid_operators) == 3


def test_edited_approval_note_breaks_the_evidence(w: World, ops: Operators) -> None:
    definition = _candidate(w)
    evidence = EvidenceCheck.from_settings(_settings(w, ops))
    _approve(w, ops, "alice", "reviewed", definition)
    with w.engine.begin() as conn:
        conn.execute(text("DROP TRIGGER policy_approvals_no_update"))
        conn.execute(text("UPDATE policy_approvals SET note = 'rubber stamp'"))
    with w.factory() as s:
        assert "WRONG_BINDING" in status(s, P2, required=1, evidence=evidence).unverified[0]


# ------------------------------------------------------------------ CLI
def _cli(env: dict[str, str], *args: str) -> Any:
    get_settings.cache_clear()
    try:
        return CliRunner().invoke(cli, list(args), env=env)
    finally:
        get_settings.cache_clear()


def test_cli_operator_flow(w: World, ops: Operators, tmp_path: Path) -> None:
    _candidate(w)
    env = {
        "DATABASE_URL": w.url,
        "OPERATOR_AUTH_REQUIRED": "true",
        "OPERATOR_REGISTRY_FILE": str(ops.registry),
    }
    check = _cli(env, "operators", "registry-check")
    assert check.exit_code == 0 and "alice" in check.output and "security_admin" in check.output
    who = _cli({**env, "OPERATOR_ID": "rita"}, "operators", "whoami",
               "--operator-key", str(ops.files["rita"]))  # fmt: skip
    assert who.exit_code == 0 and "rita" in who.output and "reviewer" in who.output
    no_auth = _cli(env, "policy", "approve", P2, "--note", "n")
    assert no_auth.exit_code != 0 and "OPERATOR_AUTH_REQUIRED" in no_auth.output
    # An assertion made "on the operator's laptop" with `operators assert`.
    with w.factory() as s:
        definition = get_policy_record(s, P2).definition_sha256
    made = _cli(env, "operators", "assert", "--key", str(ops.files["alice"]), "--id", "alice",
                "--action", "policy.approve", "--target", P2,
                "--bind", f"definition_sha256={definition}", "--note", "laptop review")  # fmt: skip
    assert made.exit_code == 0, made.output
    token = made.output.strip()
    wrong_note = _cli(env, "policy", "approve", P2, "--note", "different note",
                      "--operator-assertion", token)  # fmt: skip
    assert wrong_note.exit_code != 0 and "WRONG_BINDING" in wrong_note.output
    ok = _cli(env, "policy", "approve", P2, "--note", "laptop review",
              "--operator-assertion", token)  # fmt: skip
    assert ok.exit_code == 0 and "approved by alice" in ok.output, ok.output
    replay = _cli(env, "policy", "approve", P2, "--note", "laptop review",
                  "--operator-assertion", token)  # fmt: skip
    assert replay.exit_code != 0 and "REPLAYED_ASSERTION" in replay.output
    status_out = _cli(env, "policy", "approvals", P2)
    assert "valid     alice" in status_out.output
    # Admin actions are audited, including the refusals (codes only, never tokens).
    listing = _cli(env, "audit", "list", "--limit", "100")
    assert "operator.authenticated" in listing.output
    assert "operator.authentication_failed" in listing.output
    assert token not in listing.output and token.split(".")[2] not in listing.output
    # service-key management needs security_admin
    denied = _cli({**env, "OPERATOR_ID": "alice"}, "service-key", "create", "--name", "x",
                  "--scope", "score:write", "--operator-key", str(ops.files["alice"]))  # fmt: skip
    assert denied.exit_code != 0 and "FORBIDDEN" in denied.output
    made_key = _cli({**env, "OPERATOR_ID": "sec"}, "service-key", "create", "--name", "x",
                    "--scope", "score:write", "--operator-key", str(ops.files["sec"]))  # fmt: skip
    assert made_key.exit_code == 0, made_key.output
    assert "operator:sec" in _cli(env, "audit", "list", "--action", "service_key.created").output


# ------------------------------------------------------------------ API: the reviewer
@pytest.fixture
def h(w: World, ops: Operators) -> Iterator[Harness]:
    harness = make_harness(
        w.url, engine=w.engine, operator_auth_required=True, operator_registry_file=ops.registry
    )
    try:
        yield harness
    finally:
        harness.container.close()


def test_review_resolution_needs_an_authenticated_reviewer(
    w: World, h: Harness, ops: Operators
) -> None:
    cred = h.key()
    body, _ = h.drive(cred, w.events, "MANUAL_REVIEW")
    item = next(
        i
        for i in h.get("/v1/reviews", cred).json()["items"]
        if i["assessment_id"] == body["assessment_id"]
    )
    path = f"/v1/reviews/{item['review_id']}/resolve"
    payload = {"resolution": "legitimate", "note": "customer confirmed"}

    def assertion(who: str, resolution: str = "legitimate") -> dict[str, str]:
        token = create_assertion(ops.keys[who], who, action="review.resolve",
                                 target=item["review_id"], binding={"resolution": resolution},
                                 audience=AUD, now=h.clock())  # fmt: skip
        return {"X-Fraud-Operator-Assertion": token}

    none = h.post(path, cred, payload)
    assert none.status_code == 401 and none.json()["error"]["code"] == "OPERATOR_AUTH_REQUIRED"
    wrong_role = h.post(path, cred, payload, headers=assertion("alice"))
    assert wrong_role.status_code == 403
    assert "FORBIDDEN" in wrong_role.json()["error"]["message"]
    wrong_binding = h.post(path, cred, payload, headers=assertion("rita", "fraud"))
    assert wrong_binding.status_code == 401
    good = assertion("rita")
    ok = h.post(path, cred, payload, headers=good)
    assert ok.status_code == 200, ok.text
    with w.factory() as s:
        outcome = s.scalar(select(ReviewOutcome).order_by(ReviewOutcome.created_at.desc()))
        assert outcome is not None and outcome.reviewer == "operator:rita"
        resolved = audit.list_events(s, action="review.resolved", limit=1)[0]
        assert resolved.actor == "operator:rita" and resolved.details["authenticated"]
        failures = audit.list_events(s, action="operator.authentication_failed", limit=10)
        assert {e.details["code"] for e in failures} >= {"FORBIDDEN", "WRONG_BINDING"}
