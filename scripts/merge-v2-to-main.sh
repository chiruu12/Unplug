#!/usr/bin/env bash
# Run from jakarta/ on a machine with worktree git write access.
set -euo pipefail
cd "$(dirname "$0")/.."
git checkout main
git merge v2-enforcement-layer --no-edit
git push origin main
