#!/usr/bin/env bash
# Runs the local pytest suite using the project virtual environment
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -x "$SCRIPT_DIR/.venv/bin/pytest" ]; then
    exec "$SCRIPT_DIR/.venv/bin/pytest" "$@"
elif command -v pytest >/dev/null 2>&1; then
    exec pytest "$@"
else
    exec python3 -m pytest "$@"
fi

