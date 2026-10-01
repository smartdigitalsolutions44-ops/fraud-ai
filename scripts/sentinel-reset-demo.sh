#!/usr/bin/env bash
# Rebuild the synthetic demo world through the guarded `fraud-ai demo reset` (asks you to type
# RESET DEMO; or pass --confirm "RESET DEMO").
set -euo pipefail
# shellcheck source=scripts/_sentinel.sh
source "$(dirname "${BASH_SOURCE[0]}")/_sentinel.sh"
sentinel reset "$@"
