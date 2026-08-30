#!/bin/bash
# Hourly sync loop for beads workers — the overnight/weekly driver.
# Runs in a tmux window; serializes all merges so worker agents never merge.
# Usage: ./scripts/sync-beads-loop.sh [interval_minutes]

set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
INTERVAL_MIN=${1:-60}
LOCK="/tmp/lichen-beads-sync.lock"

echo "sync loop: every ${INTERVAL_MIN}m; Ctrl+C to stop (workers keep running)"

while :; do
    # Single-flight: skip if another sync is mid-flight
    if ! mkdir "$LOCK" 2>/dev/null; then
        echo "$(date '+%H:%M') sync already running elsewhere, skipping"
    else
        trap 'rmdir "$LOCK" 2>/dev/null' EXIT
        # Requeue leases from workers that died overnight (dead-worker recovery)
        bd reclaim --json >/dev/null 2>&1 || true
        "$REPO_ROOT/scripts/sync-beads-workers.sh" >> "$REPO_ROOT/.beads-sync.log" 2>&1 || \
            echo "$(date '+%F %T') sync reported conflicts — see .beads-sync.log" >> "$REPO_ROOT/.beads-sync.log"
        trap - EXIT
        rmdir "$LOCK"
    fi
    sleep $((INTERVAL_MIN * 60))
done
