#!/usr/bin/env bash
# Backward-compatible shim → the cross-platform Python entrypoint.
# On Windows, call `python scan.py <target>` directly (no bash needed).
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scan.py" "$@"
