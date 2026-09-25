"""Allow ``python -m fraud_ai``."""

from fraud_ai.cli.main import cli

if __name__ == "__main__":  # pragma: no cover
    cli(prog_name="fraud-ai")
