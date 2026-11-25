#!/usr/bin/env bash
# Installs the /code-audit skill for Claude Code.
# Usage: ./install.sh [--project]   (default: user-level ~/.claude/skills; --project: ./.claude/skills)
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/skills/code-audit"
if [ "${1:-}" = "--project" ]; then DEST="$PWD/.claude/skills"; else DEST="$HOME/.claude/skills"; fi
[ -f "$SRC/SKILL.md" ] || { echo "SKILL.md not found in $SRC" >&2; exit 1; }
mkdir -p "$DEST"
rm -rf "$DEST/code-audit"
cp -R "$SRC" "$DEST/code-audit"
echo "Installed to $DEST/code-audit"
echo "Restart Claude Code, then run: /code-audit"
