#!/usr/bin/env bash
# Stop what the SENTINEL scripts started (tracked processes and containers only; nothing else).
set -euo pipefail
# shellcheck source=scripts/_sentinel.sh
source "$(dirname "${BASH_SOURCE[0]}")/_sentinel.sh"
sentinel stop "$@"
