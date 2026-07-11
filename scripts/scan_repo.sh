#!/usr/bin/env bash
# Backward-compatible shim → the cross-platform Python entrypoint.
# scan.py resolves a repo URL and clones it durably itself.
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scan.py" "$@"
