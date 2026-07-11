#!/usr/bin/env bash
# Install VibeScan directly into a Claude Code skills directory, so it's on disk
# regardless of whether the account-skill sync provisioned it. Run from the repo:
#
#   bash install.sh                       # -> ~/.claude/skills/vibescan
#   bash install.sh /path/to/.claude/skills
#
# In a Claude Code session you can also just clone straight into place:
#   git clone <your-repo-url> ~/.claude/skills/vibescan
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_ROOT="${1:-$HOME/.claude/skills}"
DEST="$DEST_ROOT/vibescan"

mkdir -p "$DEST"
cp -R "$SRC/SKILL.md" "$SRC/scripts" "$SRC/assets" "$SRC/references" "$DEST/" 2>/dev/null || {
  echo "error: run this from inside the vibescan repo (SKILL.md + scripts/ must be alongside it)" >&2
  exit 1
}
chmod +x "$DEST/scripts/"*.sh 2>/dev/null || true

echo "✓ VibeScan installed to $DEST"
echo "  Claude Code should now list 'vibescan' as an available skill."
echo "  If your Code session uses a different skills path, pass it as the first argument."
