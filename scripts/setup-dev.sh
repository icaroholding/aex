#!/bin/sh
# One-shot dev setup for the AEX workspace.
#
#   $ scripts/setup-dev.sh
#
# Idempotent. Run again after pulling new tooling changes.

set -e

cd "$(git rev-parse --show-toplevel)"

echo "Configuring git to use .githooks/ for hooks …"
git config core.hooksPath .githooks
echo "  ✓ git config core.hooksPath = .githooks"

# Make sure the hooks are executable even if the working tree was
# checked out on a filesystem that lost the +x bit.
chmod +x .githooks/* 2>/dev/null || true

echo ""
echo "Active hooks:"
for hook in .githooks/*; do
    [ -f "$hook" ] && echo "  • $(basename "$hook")"
done

echo ""
echo "Setup complete. To bypass any hook once: git <cmd> --no-verify"
