# shellcheck shell=bash
# Shared by the SENTINEL shell wrappers (Stage 14). Sourced, never run directly.
# The logic lives in scripts/localrun (Python); these wrappers only find the interpreter.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv_python="$repo/.venv/bin/python"

sentinel() {
  if [ ! -x "$venv_python" ]; then
    echo "  FAIL SENTINEL is not set up yet: run ./scripts/setup-local.sh first" >&2
    exit 2
  fi
  cd "$repo" && exec "$venv_python" "$repo/scripts/sentinel.py" "$@"
}
