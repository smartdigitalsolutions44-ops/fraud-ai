"""Controlled shadow → evaluation → candidate → active promotion (Stage 10).

Nothing is promoted automatically. Each step is an explicit CLI action, and each step is
recorded as an append-only ``policy_lifecycle_events`` row plus an audit event.

Stages and what each requires:

* ``shadow``: the policy is a shadow policy of the *current* deployment, i.e. it is being
  observed on live traffic.
* ``evaluation``: stage ``shadow`` plus offline evidence (a test-split simulation summary
  and the live shadow agreement at the time).
* ``candidate``: stage ``evaluation`` plus an explicit approval and a note.
* ``rejected``: allowed from any stage; ends the promotion (a new version is needed).
* active: ``deployment activate``. With ``POLICY_REQUIRE_PROMOTION`` (the default in
  staging and production) only a ``candidate`` can be activated.

The evidence is SYNTHETIC wherever the data is; promotion records a decision, it does not
prove a policy is better.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai import audit
from fraud_ai.database.models import PolicyLifecycleEvent
from fraud_ai.privacy import freetext
from fraud_ai.risk.registry import PolicyError, active_deployment, load_policy

STAGES = ("shadow", "evaluation", "candidate", "rejected")
_REQUIRED_PREVIOUS = {"shadow": None, "evaluation": "shadow", "candidate": "evaluation"}


def current_stage(session: Session, version: str) -> str | None:
    row = session.scalar(
        select(PolicyLifecycleEvent)
        .where(PolicyLifecycleEvent.policy_version == version)
        .order_by(PolicyLifecycleEvent.created_at.desc(), PolicyLifecycleEvent.lifecycle_id)
        .limit(1)
    )
    return row.stage if row else None


def history(session: Session, version: str) -> list[PolicyLifecycleEvent]:
    return list(
        session.scalars(
            select(PolicyLifecycleEvent)
            .where(PolicyLifecycleEvent.policy_version == version)
            .order_by(PolicyLifecycleEvent.created_at)
        )
    )


def check_transition(session: Session, version: str, stage: str) -> Any:
    """The stage-order rules alone (cheap; run before collecting any evidence). Returns the
    active deployment."""
    if stage not in STAGES:
        raise PolicyError(f"stage must be one of {STAGES}")
    load_policy(session, version)  # exists and its hash verifies
    stage_now = current_stage(session, version)
    if stage_now == "rejected":
        raise PolicyError(f"{version} was rejected; create a new policy version")
    deployment = active_deployment(session)
    if deployment is not None and deployment.policy.policy_version == version:
        raise PolicyError(f"{version} is already active")
    if stage != "rejected":
        required = _REQUIRED_PREVIOUS[stage]
        if stage_now == stage:
            raise PolicyError(f"{version} is already at stage {stage}")
        if required is not None and stage_now != required:
            raise PolicyError(
                f"{version} must be at stage {required!r} before {stage!r} "
                f"(currently {stage_now or 'not promoted'}); stages cannot be skipped"
            )
    return deployment


def promote(
    session: Session,
    version: str,
    stage: str,
    *,
    actor: str,
    note: str | None = None,
    evidence: dict[str, Any] | None = None,
    approved: bool = False,
) -> PolicyLifecycleEvent:
    try:
        note = freetext.check("policy.promotion_note", note)
    except freetext.FreeTextError as exc:
        raise PolicyError(str(exc)) from None
    stage_now = current_stage(session, version)
    deployment = check_transition(session, version, stage)
    if stage == "shadow" and (
        deployment is None or version not in {p.policy_version for p in deployment.shadow_policies}
    ):
        raise PolicyError(
            f"{version} is not a shadow policy of the current deployment; activate the "
            "current policy with --shadow-policy first"
        )
    if stage == "evaluation" and not (evidence or {}).get("simulation"):
        raise PolicyError("evaluation needs a simulation summary as evidence")
    if stage == "candidate":
        if not approved:
            raise PolicyError("candidate promotion needs an explicit approval (--approve)")
        if not note:
            raise PolicyError("candidate promotion needs a note explaining the decision")
    row = PolicyLifecycleEvent(
        policy_version=version,
        stage=stage,
        actor=actor[:200],
        evidence=evidence or {},
        note=note[:500] if note else None,
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        "policy.promoted",
        actor=actor,
        target_type="policy",
        target_id=version,
        details={"stage": stage, "previous_stage": stage_now, "note": note or ""},
    )
    return row


def ensure_activatable(session: Session, version: str) -> None:
    """The promotion gate used by activation when promotion is required."""
    stage = current_stage(session, version)
    if stage != "candidate":
        raise PolicyError(
            f"{version} is not a promoted candidate (stage: {stage or 'none'}); promote it "
            "through shadow → evaluation → candidate first (POLICY_REQUIRE_PROMOTION)"
        )
