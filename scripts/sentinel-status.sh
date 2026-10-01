#!/usr/bin/env bash
# Show the API, console, PostgreSQL, Redis, active policy, models, demo mode and LLM.
#   ./scripts/sentinel-status.sh [--json]
set -euo pipefail
# shellcheck source=scripts/_sentinel.sh
source "$(dirname "${BASH_SOURCE[0]}")/_sentinel.sh"
sentinel status "$@"
