"""Stage 12 administrative commands: key-provider status and rotation, and operator
identities (keys, assertions, registry checks). Registered on the main CLI."""

from __future__ import annotations

import json
from pathlib import Path

import click

from fraud_ai.cli.main import AppContext, cli, keys_group, pass_app, privacy
from fraud_ai.cli.operator_auth import authenticate_cli, operator_options
from fraud_ai.database import make_session_factory, session_scope

_SETTING = {
    "model": "MODEL_SIGNING_PUBLIC_KEYS",
    "audit": "AUDIT_ANCHOR_PUBLIC_KEYS",
    "release": "RELEASE_SIGNING_PUBLIC_KEYS",
}


# --------------------------------------------------------------------------- keys
@keys_group.command("status")
@pass_app
def keys_status(app: AppContext) -> None:
    """Where each signing key lives (provider), its key id, and whether that key is in the
    purpose's trusted set. Contacts the KMS; fails closed if it is unreachable."""
    from fraud_ai.trust.keys import TrustError, parse_public_keys
    from fraud_ai.trust.kms import provider_from_settings

    s = app.settings
    click.echo(
        f"provider      {s.key_provider} (KMS required: {'yes' if s.kms_is_required else 'no'})"
    )
    problems = 0
    try:
        provider = provider_from_settings(s)
    except TrustError as exc:
        raise click.ClickException(str(exc)) from None
    for purpose, setting in _SETTING.items():
        trusted = parse_public_keys(getattr(s, setting.lower()))
        try:
            signer = provider.signer(purpose)
        except TrustError as exc:
            click.echo(f"{purpose:<8}      {provider.describe(purpose)}  UNAVAILABLE: {exc}")
            problems += 1
            continue
        state = "trusted" if signer.key_id in trusted else f"NOT in {setting}"
        if signer.key_id not in trusted:
            problems += 1
        click.echo(f"{purpose:<8}      {provider.describe(purpose)}  {signer.key_id}  {state}")
    if s.image_signing_public_key_file is not None:
        from fraud_ai.trust.images import key_fingerprint

        try:
            fp = key_fingerprint(Path(s.image_signing_public_key_file).read_bytes())
            click.echo(f"image         cosign public key {s.image_signing_public_key_file}  {fp}")
        except (OSError, TrustError) as exc:
            click.echo(f"image         UNREADABLE: {exc}")
            problems += 1
    if problems:
        raise SystemExit(1)


@keys_group.command("rotate")
@click.option("--purpose", type=click.Choice(sorted(_SETTING)), required=True)
@operator_options
@pass_app
def keys_rotate(
    app: AppContext, purpose: str, operator_assertion: str | None, operator_key: Path | None
) -> None:
    """Rotate a KMS signing key (KEY_PROVIDER=vault): Vault creates a new key version.

    A ``security_admin`` action. The new public key must then be ADDED to the purpose's
    trusted set before anything can be signed with it (signing refuses untrusted keys);
    keep the old key in the set while its signatures must still verify."""
    app.require_migrated()
    from fraud_ai import audit as audit_log
    from fraud_ai.cli.operator_auth import actor
    from fraud_ai.trust.keys import TrustError, encode_public
    from fraud_ai.trust.kms import VaultTransitProvider, provider_from_settings

    try:
        provider = provider_from_settings(app.settings)
    except TrustError as exc:
        raise click.ClickException(str(exc)) from None
    if not isinstance(provider, VaultTransitProvider):
        raise click.ClickException(
            "rotation is a KMS operation (KEY_PROVIDER=vault); for local files, generate a new "
            "key with `fraud-ai keys generate` and update the trusted set"
        )
    name = provider.key_names[purpose]
    with session_scope(make_session_factory(app.engine)) as session:
        identity, _ = authenticate_cli(
            app,
            session,
            action="signing_key.rotate",
            target=purpose,
            binding={"key": name},
            assertion=operator_assertion,
            key_file=operator_key,
        )
        try:
            old = provider.signer(purpose)
            provider.client.rotate_key(name)
            new = provider.signer(purpose)
        except TrustError as exc:
            raise click.ClickException(str(exc)) from None
        audit_log.record(
            session,
            "signing_key.rotated",
            actor=actor(identity),
            target_type="signing_key",
            target_id=purpose,
            details={"kms_key": name, "old_key_id": old.key_id, "new_key_id": new.key_id},
        )
    click.echo(f"{purpose}: {old.key_id} -> {new.key_id}")
    click.echo(f"add to {_SETTING[purpose]}: {encode_public(new.public)}")


# --------------------------------------------------------------------------- operators
@cli.group()
def operators() -> None:
    """Operator identities for administrative actions (Stage 12): per-person Ed25519 keys,
    a trusted registry with roles, and signed single-use assertions."""


@operators.command("keygen")
@click.option("--id", "operator_id", required=True, help="Your operator id, e.g. alice.")
@click.option("--out", "out", type=click.Path(path_type=Path, dir_okay=False), required=True)
def operators_keygen(operator_id: str, out: Path) -> None:
    """Create YOUR operator key (0600, never overwritten) and print the registry entry a
    security admin adds for you. Keep the private key to yourself (ideally on hardware)."""
    from fraud_ai.trust.keys import encode_public, generate, write_private_key

    pair = generate()
    try:
        write_private_key(pair, out)
    except FileExistsError:
        raise click.ClickException(f"{out} already exists; refusing to overwrite") from None
    click.echo(f"key id      {pair.key_id}")
    click.echo(f"private key {out} (0600)")
    entry = {"id": operator_id, "roles": ["<role>"], "public_keys": [encode_public(pair.public)]}
    click.echo(f"registry entry: {json.dumps(entry)}")


@operators.command("assert")
@click.option("--key", "key_file", type=click.Path(path_type=Path, dir_okay=False), required=True)
@click.option("--id", "operator_id", required=True)
@click.option("--action", required=True, help="e.g. policy.approve, policy.activate")
@click.option("--target", required=True, help="e.g. the policy version or review id")
@click.option("--bind", "binds", multiple=True, help="key=value binding (repeatable).")
@click.option(
    "--note",
    default=None,
    help="policy.approve: the approval note (adds its normalised note_sha256 binding).",
)
@click.option("--audience", default=None, help="Default OPERATOR_AUDIENCE.")
@click.option("--lifetime", type=click.IntRange(10, 3600), default=120, show_default=True)
@pass_app
def operators_assert(
    app: AppContext,
    key_file: Path,
    operator_id: str,
    action: str,
    target: str,
    binds: tuple[str, ...],
    note: str | None,
    audience: str | None,
    lifetime: int,
) -> None:
    """Sign a single-use assertion for one action (run on YOUR machine; paste the output
    into --operator-assertion). It is valid for --lifetime seconds, for this action,
    target and binding only. Treat it like a one-time password."""
    from fraud_ai.core.exceptions import FraudAIError
    from fraud_ai.trust.keys import TrustError, load_private_key
    from fraud_ai.trust.operators import create_assertion

    binding: dict[str, str] = {}
    for item in binds:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise click.BadParameter(f"{item!r} is not key=value", param_hint="--bind")
        binding[key] = value
    if note is not None:
        import hashlib

        from fraud_ai.risk.approvals import normalise_note

        try:
            binding["note_sha256"] = hashlib.sha256(normalise_note(note).encode()).hexdigest()
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
    try:
        pair = load_private_key(key_file)
        token = create_assertion(
            pair,
            operator_id,
            action=action,
            target=target,
            binding=binding,
            audience=audience or app.settings.operator_audience,
            lifetime_seconds=lifetime,
        )
    except (TrustError, FraudAIError) as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(token)


@operators.command("registry-check")
@pass_app
def operators_registry_check(app: AppContext) -> None:
    """Validate OPERATOR_REGISTRY_FILE: schema, roles, one owner per key, and no operator
    key reused as a model, audit or release key."""
    from fraud_ai.trust.operators import OperatorAuthError, registry_from_settings

    try:
        registry = registry_from_settings(app.settings)
    except OperatorAuthError as exc:
        raise click.ClickException(f"{exc.code}: {exc}") from None
    click.echo(f"registry {registry.source} sha256 {registry.sha256[:16]}…")
    for op in registry.operators.values():
        state = "DISABLED" if op.disabled else "enabled"
        click.echo(
            f"  {op.operator_id:<16} {state:<8} roles {','.join(sorted(op.roles)):<40} "
            f"keys {', '.join(op.keys)}"
        )


@operators.command("whoami")
@operator_options
@pass_app
def operators_whoami(
    app: AppContext, operator_assertion: str | None, operator_key: Path | None
) -> None:
    """Authenticate (action ``operator.check``; the assertion is consumed and audited) and
    print the verified identity and roles."""
    app.require_migrated()
    with session_scope(make_session_factory(app.engine)) as session:
        identity, _ = authenticate_cli(
            app,
            session,
            action="operator.check",
            target="whoami",
            binding={},
            assertion=operator_assertion,
            key_file=operator_key,
        )
    if identity is None:
        raise click.ClickException("no operator assertion given")
    click.echo(f"operator  {identity.operator_id}")
    click.echo(f"key id    {identity.key_id}")
    click.echo(f"roles     {', '.join(sorted(identity.roles))}")


# --------------------------------------------------------------------------- privacy export
@privacy.command("export")
@click.argument("pseudonym")
@click.option(
    "--out",
    "out",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Output file (created 0600, never overwritten); '-' for standard output.",
)
@operator_options
@pass_app
def privacy_export(
    app: AppContext,
    pseudonym: str,
    out: Path,
    operator_assertion: str | None,
    operator_key: Path | None,
) -> None:
    """Export the data held about ONE user (merchant reference or user id) as JSON: an
    explicit per-column allow-list; no other users, secrets, keyed pseudonyms, internal
    model data or signing material. A ``security_admin`` action; audited (counts only)."""
    import os

    from fraud_ai import audit as audit_log
    from fraud_ai.cli.operator_auth import actor
    from fraud_ai.privacy.export import export_subject

    app.require_migrated()
    to_stdout = str(out) == "-"
    if not to_stdout and out.exists():
        raise click.ClickException(f"{out} already exists; refusing to overwrite")
    with session_scope(make_session_factory(app.engine)) as session:
        identity, _ = authenticate_cli(
            app,
            session,
            action="privacy.export",
            target=pseudonym,
            binding={},
            assertion=operator_assertion,
            key_file=operator_key,
        )
        document = export_subject(session, pseudonym)
        if not document["found"]:
            raise click.ClickException(f"no user with reference or id {pseudonym!r}")
        audit_log.record(
            session,
            "privacy.exported",
            actor=actor(identity),
            target_type="user",
            target_id=document["user_id"],
            details={"row_counts": document["row_counts"], "to": "stdout" if to_stdout else "file"},
        )
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if to_stdout:
        click.echo(text, nl=False)
        return
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    total = sum(document["row_counts"].values())
    click.echo(f"exported {total} rows for user {document['user_id']} to {out} (0600)")
