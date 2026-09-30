"""Policy storage and deployment: immutable policies, append-only activations.

* :func:`create_policy` stores a new version. A version that exists is never replaced.
* :func:`load_policy` re-hashes the stored definition and refuses a mismatch, so an
  edited policy row is detected and never used.
* :func:`activate` validates everything a policy references before appending a
  deployment:
  * every model is registered, its artefact digest matches, and the artefact loads and
    verifies;
  * every calibration exists for that model with the same parameters;
  * the rule set is known and its fingerprint matches;
  * shadow models and shadow policies are valid.

  Nothing is activated implicitly.
* :func:`active_deployment` returns the latest deployment (the highest ``sequence``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import (
    ModelCalibration,
    ModelVersion,
    PolicyDeployment,
    RiskPolicyRecord,
)
from fraud_ai.models.factory import is_anomaly_model, is_sequence_kind, kind_for_name
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.scoring import load_registered_model
from fraud_ai.privacy import freetext
from fraud_ai.risk.policy import ModelSlot, RiskPolicyDefinition
from fraud_ai.rules.ruleset import get_rule_set


class PolicyError(FraudAIError):
    pass


class PolicyIntegrityError(PolicyError):
    """A stored policy no longer matches its recorded hash."""


@dataclass(frozen=True)
class ActiveDeployment:
    deployment: PolicyDeployment
    policy: RiskPolicyDefinition
    shadow_policies: tuple[RiskPolicyDefinition, ...]

    @property
    def deployment_id(self) -> Any:
        return self.deployment.deployment_id

    @property
    def shadow_models(self) -> tuple[str, ...]:
        return tuple(self.deployment.shadow_models)


def create_policy(
    session: Session,
    definition: RiskPolicyDefinition,
    *,
    derivation: dict[str, Any] | None = None,
    description: str | None = None,
) -> RiskPolicyRecord:
    existing = session.scalar(
        select(RiskPolicyRecord).where(RiskPolicyRecord.policy_version == definition.policy_version)
    )
    if existing is not None:
        raise PolicyError(
            f"{definition.policy_version} already exists; policies are immutable - create a "
            "new version"
        )
    validate_references(session, definition, load_artifacts=False)
    row = RiskPolicyRecord(
        policy_version=definition.policy_version,
        definition=definition.model_dump(mode="json"),
        definition_sha256=definition.sha256(),
        derivation=derivation or {},
        synthetic_derived=definition.synthetic_derived,
        description=description or definition.description or None,
    )
    session.add(row)
    session.flush()
    return row


def get_policy_record(session: Session, version: str) -> RiskPolicyRecord:
    row = session.scalar(select(RiskPolicyRecord).where(RiskPolicyRecord.policy_version == version))
    if row is None:
        raise PolicyError(f"unknown policy {version!r}")
    return row


def load_policy(session: Session, version: str) -> RiskPolicyDefinition:
    return verified_definition(get_policy_record(session, version))


def verified_definition(row: RiskPolicyRecord) -> RiskPolicyDefinition:
    try:
        definition = RiskPolicyDefinition.model_validate(row.definition)
    except ValueError as exc:
        raise PolicyIntegrityError(f"{row.policy_version} is not a valid policy: {exc}") from None
    if definition.sha256() != row.definition_sha256 or (
        definition.policy_version != row.policy_version
    ):
        raise PolicyIntegrityError(
            f"{row.policy_version} does not match its recorded SHA-256: it was modified "
            "after creation and will not be used"
        )
    return definition


def list_policies(session: Session) -> list[RiskPolicyRecord]:
    return list(session.scalars(select(RiskPolicyRecord).order_by(RiskPolicyRecord.created_at)))


def _record(session: Session, slot: ModelSlot) -> ModelVersion:
    try:
        record = resolve_model(session, slot.ref)
    except FraudAIError as exc:
        raise PolicyError(str(exc)) from None
    if record.artifact_sha256 != slot.artifact_sha256:
        raise PolicyError(
            f"{slot.ref}: the registered artefact digest differs from the one the policy pins"
        )
    return record


def validate_references(
    session: Session, definition: RiskPolicyDefinition, *, load_artifacts: bool = True
) -> None:
    for role, slot in definition.slots().items():
        record = _record(session, slot)
        anomaly = is_anomaly_model(record.model_name)
        if (role == "anomaly") != anomaly:
            raise PolicyError(
                f"{slot.ref} cannot be the {role} model: anomaly scores are only allowed as "
                "the anomaly signal, and the anomaly slot needs an anomaly model"
            )
        if role == "sequence" and not is_sequence_kind(kind_for_name(record.model_name)):
            raise PolicyError(f"{slot.ref} is not a sequence model")
        if slot.calibration is not None:
            calibration = session.get(ModelCalibration, _uuid(slot.calibration.calibration_id))
            if (
                calibration is None
                or calibration.model_version_id != record.model_version_id
                or calibration.method != slot.calibration.method
                or calibration.parameters != slot.calibration.parameters
            ):
                raise PolicyError(
                    f"{slot.ref}: calibration {slot.calibration.calibration_id} is missing, "
                    "belongs to another model, or has different parameters"
                )
        if load_artifacts:
            try:
                load_registered_model(record)
            except (FraudAIError, OSError) as exc:
                raise PolicyError(f"{slot.ref}: artefact failed verification: {exc}") from None
    try:
        rules = get_rule_set(definition.rules_version)
    except KeyError as exc:
        raise PolicyError(str(exc)) from None
    if rules.fingerprint() != definition.rules_fingerprint:
        raise PolicyError(
            f"rule set {definition.rules_version} has changed since the policy was created"
        )


def _uuid(value: str) -> Any:
    import uuid

    try:
        return uuid.UUID(value)
    except ValueError:
        raise PolicyError(f"invalid calibration id {value!r}") from None


def _config_hash(version: str, shadow_models: list[str], shadow_policies: list[str]) -> str:
    payload = {
        "policy": version,
        "shadow_models": shadow_models,
        "shadow_policies": shadow_policies,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def activate(
    session: Session,
    version: str,
    *,
    shadow_models: list[str] | None = None,
    shadow_policies: list[str] | None = None,
    note: str | None = None,
    activated_by: str | None = None,
    require_promotion: bool = False,
    approvals_required: int = 0,
    now: datetime | None = None,
    approval_evidence: Any = None,
) -> PolicyDeployment:
    """Validate and append a deployment. It takes effect for events scored afterwards.

    Refused (Stage 10 safeguards included) when:

    * a referenced model is missing, or its artefact fails verification;
    * a model was trained on a different feature catalogue, or the models of the active
      set disagree on the feature version (the service computes one vector per event);
    * a calibration is missing, belongs to another model, or has other parameters;
    * the rule set changed since the policy was created;
    * ``require_promotion`` is set and the policy is not a promoted ``candidate``;
    * (Stage 11) ``approvals_required`` distinct, unexpired operator approvals of this
      exact definition are missing (the two-person rule, :mod:`fraud_ai.risk.approvals`).
    """
    try:
        note = freetext.check("deployment.note", note)
    except freetext.FreeTextError as exc:
        raise PolicyError(str(exc)) from None
    definition = load_policy(session, version)
    if require_promotion or approvals_required:
        from fraud_ai.risk.promotion import ensure_activatable

        ensure_activatable(session, version)
    if approvals_required:
        from fraud_ai.risk.approvals import ensure_approved

        ensure_approved(
            session, version, required=approvals_required, now=now, evidence=approval_evidence
        )
    validate_references(session, definition)
    _check_feature_versions(session, definition, shadow_models or [])
    shadows = sorted(set(shadow_models or []))
    active_refs = {slot.ref for slot in definition.slots().values()}
    for ref in shadows:
        if ref in active_refs:
            raise PolicyError(f"{ref} is already in the active model set; it cannot be a shadow")
        try:
            record = resolve_model(session, ref)
        except FraudAIError as exc:
            raise PolicyError(str(exc)) from None
        if is_anomaly_model(record.model_name):
            raise PolicyError(f"{ref} is an anomaly model; shadow models must be classifiers")
        try:
            load_registered_model(record)
        except (FraudAIError, OSError) as exc:
            raise PolicyError(f"{ref}: artefact failed verification: {exc}") from None
    shadow_versions = sorted(set(shadow_policies or []))
    if version in shadow_versions:
        raise PolicyError("the active policy cannot also be a shadow policy")
    for shadow in shadow_versions:
        validate_references(session, load_policy(session, shadow))
    sequence = int(session.scalar(select(func.max(PolicyDeployment.sequence))) or 0) + 1
    row = PolicyDeployment(
        sequence=sequence,
        policy_version=version,
        shadow_models=shadows,
        shadow_policies=shadow_versions,
        config_sha256=_config_hash(version, shadows, shadow_versions),
        note=note,
        activated_by=activated_by[:200] if activated_by else None,
    )
    session.add(row)
    session.flush()
    return row


def _check_feature_versions(
    session: Session, definition: RiskPolicyDefinition, shadow_models: list[str]
) -> None:
    primary = _record(session, definition.primary)
    refs = [slot.ref for slot in definition.slots().values()] + list(shadow_models)
    for ref in refs:
        try:
            record = resolve_model(session, ref)
        except FraudAIError as exc:
            raise PolicyError(str(exc)) from None
        if record.feature_version != primary.feature_version:
            raise PolicyError(
                f"{ref} uses feature version {record.feature_version}, but the primary "
                f"model uses {primary.feature_version}; the active set must share one"
            )


def active_deployment(session: Session) -> ActiveDeployment | None:
    row = session.scalar(select(PolicyDeployment).order_by(PolicyDeployment.sequence.desc()))
    if row is None:
        return None
    if row.config_sha256 != _config_hash(
        row.policy_version, list(row.shadow_models), list(row.shadow_policies)
    ):
        raise PolicyIntegrityError(f"deployment {row.sequence} was modified after activation")
    policy = load_policy(session, row.policy_version)
    shadows = tuple(load_policy(session, v) for v in row.shadow_policies)
    return ActiveDeployment(row, policy, shadows)


def deployment_history(session: Session) -> list[PolicyDeployment]:
    return list(
        session.scalars(select(PolicyDeployment).order_by(PolicyDeployment.sequence.desc()))
    )
