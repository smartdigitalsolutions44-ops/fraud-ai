#!/usr/bin/env bash
# Start SENTINEL: the fraud API and the analyst console, in one command.
#   ./scripts/sentinel-start.sh [--mode demo|dev|staginglike] [--reset] [--foreground] [--no-browser]
set -euo pipefail
# shellcheck source=scripts/_sentinel.sh
source "$(dirname "${BASH_SOURCE[0]}")/_sentinel.sh"
sentinel start "$@"
