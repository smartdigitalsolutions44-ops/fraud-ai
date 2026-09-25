#!/usr/bin/env bash
# Run the same checks CI would: lint, format check, type check, tests.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m ruff check .
python -m ruff format --check fraud_ai tests migrations
python -m mypy
python -m pytest "$@"
