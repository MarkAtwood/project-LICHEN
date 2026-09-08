#!/bin/bash
# Safe bead mutations for NON-FLEET AI sessions (coordinators, Opus, one-off
# agents in the main checkout). Fleet workers use bare bd; everyone else MUST
# use this wrapper.
#
# Why: bd writes land in the shared .beads working tree immediately (any bd
# list/show sees them), but they are DURABLE only after a checkpoint commit —
# and the sync loop's merge normalizations rewind uncommitted store state.
# This wrapper serializes each mutation against the sync lock and commits it
# before releasing, so nothing can eat it (bead biod, the orchestrator loss).
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
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    BEADS_ALLOW_STORE_COMMIT=1 git commit -m "chore(beads): safe-write $1" --quiet || true
fi
exit $rc
