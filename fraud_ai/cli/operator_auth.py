"""Operator authentication for administrative CLI commands (Stage 12).

Every protected command takes one of:

* ``--operator-assertion TOKEN``, or ``FRAUD_AI_OPERATOR_ASSERTION``: an assertion created
  on the operator's own machine with ``fraud-ai operators assert``. The private key never
  reaches the admin host;
* ``--operator-key FILE`` together with ``OPERATOR_ID``: a convenience. The CLI signs a
  fresh single-use assertion with the local key and verifies it like any other.

With ``OPERATOR_AUTH_REQUIRED`` (default in staging/production), a protected command without
a valid assertion stops. Without it (development), the command runs unauthenticated. Its
audit actor is then the CLI user, or Stage 11's configured ``OPERATOR_ID``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import click

from fraud_ai.trust.operators import (
    OperatorAuthError,
    VerifiedAssertion,
    authenticate,
    create_assertion,
    record_failure,
)


def operator_options(func: Callable[..., Any]) -> Callable[..., Any]:
    func = click.option(
        "--operator-key",
        "operator_key",
        type=click.Path(path_type=Path, dir_okay=False),
        default=None,
        help="Your operator Ed25519 key (0600); signs a one-off assertion (needs OPERATOR_ID).",
    )(func)
    func = click.option(
        "--operator-assertion",
        "operator_assertion",
        envvar="FRAUD_AI_OPERATOR_ASSERTION",
        default=None,
        help="A signed operator assertion from `fraud-ai operators assert` (single use).",
    )(func)
    return func


def token_for(
    settings: Any,
    *,
    action: str,
    target: str,
    binding: dict[str, str],
    assertion: str | None,
    key_file: Path | None,
) -> str | None:
    if assertion is not None and key_file is not None:
        raise click.ClickException("give either --operator-assertion or --operator-key, not both")
    if assertion is not None:
        return assertion.strip()
    if key_file is None:
        return None
    from fraud_ai.trust.keys import TrustError, load_private_key

    if not settings.operator_id:
        raise click.ClickException("--operator-key needs OPERATOR_ID (your operator id)")
    try:
        pair = load_private_key(key_file)
    except TrustError as exc:
        raise click.ClickException(str(exc)) from None
    return create_assertion(
        pair,
        settings.operator_id,
        action=action,
        target=target,
        binding=binding,
        audience=settings.operator_audience,
        lifetime_seconds=min(120, settings.operator_assertion_max_seconds),
    )


def authenticate_cli(
    app: Any,
    session: Any,
    *,
    action: str,
    target: str,
    binding: dict[str, str],
    assertion: str | None,
    key_file: Path | None,
) -> tuple[VerifiedAssertion | None, str | None]:
    """Verify and consume the operator's assertion inside ``session`` (the action's own
    transaction). Returns ``(identity, token)``, or ``(None, None)`` when authentication is
    optional and none was given."""
    settings = app.settings
    token = token_for(
        settings,
        action=action,
        target=target,
        binding=binding,
        assertion=assertion,
        key_file=key_file,
    )
    if token is None:
        if settings.operator_auth_is_required:
            raise click.ClickException(
                f"{action} needs an authenticated operator (OPERATOR_AUTH_REQUIRED): pass "
                "--operator-key or --operator-assertion"
            )
        return None, None
    try:
        return (
            authenticate(session, settings, token, action=action, target=target, binding=binding),
            token,
        )
    except OperatorAuthError as exc:
        from fraud_ai.database import make_session_factory

        session.rollback()
        record_failure(
            make_session_factory(app.engine), action=action, target=target, error=exc, via="cli"
        )
        raise click.ClickException(f"operator authentication failed ({exc.code}): {exc}") from None


def actor(identity: VerifiedAssertion | None) -> str:
    from fraud_ai import audit as audit_log

    return identity.actor if identity is not None else audit_log.cli_actor()
