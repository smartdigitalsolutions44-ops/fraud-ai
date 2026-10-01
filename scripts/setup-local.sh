#!/usr/bin/env bash
# Install or update everything SENTINEL needs (safe to run again; only changed parts are redone).
#   ./scripts/setup-local.sh [--docker] [--force]
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "  FAIL $*" >&2; exit 2; }

echo
echo "SENTINEL setup"
command -v git >/dev/null 2>&1 || fail "Git is not installed"

python=""
for candidate in python3.11 python3.12 python3.13 python3 python; do
  command -v "$candidate" >/dev/null 2>&1 || continue
  if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    python="$candidate"
    break
  fi
done
[ -n "$python" ] || fail "Python 3.11 or newer is required (python.org, or your package manager)"
echo "  OK   Python $("$python" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])') ($python)"

if [ ! -x "$repo/.venv/bin/python" ]; then
  echo "  >>   creating the virtual environment in $repo/.venv"
  "$python" -m venv "$repo/.venv" || fail "could not create the virtual environment (Debian/Ubuntu: apt install python3-venv)"
else
  echo "  OK   virtual environment $repo/.venv"
fi
cd "$repo"
exec "$repo/.venv/bin/python" "$repo/scripts/sentinel.py" setup "$@"
