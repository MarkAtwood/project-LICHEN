#!/bin/bash
# Safe bead mutations for NON-FLEET AI sessions (coordinators, Opus, one-off
# agents in the main checkout). Safe for anyone; recommended for
# long-running sessions writing many mutations. Single mutations from short
# sessions are durable with bare bd too (the rewind is gated off).
#
# Why: bare bd writes are now DURABLE in the main checkout (the .beads
# normalization rewind was removed — gated to legacy branches only, bead
# biod follow-up). This wrapper remains for extra safety: it serializes
# against the sync lock and checkpoint-commits immediately, which matters
# for long-running sessions writing many mutations (the store working tree
# is only as durable as the next checkpoint while uncommitted).
#
# Usage: scripts/beads-safe.sh <bd subcommand> [args...]
#   scripts/beads-safe.sh create --title="..." ...
#   scripts/beads-safe.sh update <id> --notes="..."
#   scripts/beads-safe.sh comment <id> "..."
#   scripts/beads-safe.sh close <id> --reason="..."
# Reads (list/show/ready) need no wrapper.
set -u
REPO="/home/mark/Developer/lichen-workspace/project-LICHEN"
LOCK="/tmp/lichen-beads-sync.lock"
cd "$REPO" || exit 1
[ $# -eq 0 ] && { echo "usage: $0 <bd subcommand> [args...]" >&2; exit 1; }

# Serialize against the sync loop + janitor (up to 20 min; they hold the lock
# for whole merge cycles).
ACQUIRED=0
for i in $(seq 1 120); do
    if mkdir "$LOCK" 2>/dev/null; then ACQUIRED=1; break; fi
    sleep 10
done
if [ "$ACQUIRED" -ne 1 ]; then
    echo "sync lock busy for 20 minutes — try again later" >&2
    exit 3
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

bd "$@"
rc=$?

# Checkpoint: make the mutation durable before anyone can rewind it.
# NEVER commit while a merge is in flight — committing mid-merge would commit
# the merge state prematurely (MERGE_HEAD present); durability then waits
# for the fleet's next checkpoint, which is fine.
if [ ! -f .git/MERGE_HEAD ] && [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    BEADS_ALLOW_STORE_COMMIT=1 git commit -m "chore(beads): safe-write $1" --quiet || true
fi
exit $rc
