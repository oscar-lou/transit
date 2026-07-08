#!/bin/sh
# Installs this repo's git hooks. .git/hooks/ is NOT version-controlled, so
# a fresh clone starts with no hooks - run this once after cloning:
#
#   sh scripts/install-hooks.sh
#
set -eu

REPO_ROOT="$(git rev-parse --show-toplevel)"
SRC="$REPO_ROOT/scripts/hooks/pre-commit"
DEST="$REPO_ROOT/.git/hooks/pre-commit"

cp "$SRC" "$DEST"
chmod +x "$DEST"

echo "Installed pre-commit hook -> $DEST"
echo "(runs the pytest suite before every commit; bypass a single commit with git commit --no-verify)"
