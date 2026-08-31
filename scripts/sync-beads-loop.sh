#!/bin/bash
# Hourly sync loop for beads workers — the overnight/weekly driver.
# Runs in a tmux window; serializes all merges so worker agents never merge.
# Usage: ./scripts/sync-beads-loop.sh [interval_minutes]

REPO_ROOT=$(git rev-parse --show-toplevel)
INTERVAL_MIN=${1:-60}
LOCK="/tmp/lichen-beads-sync.lock"

echo "sync loop: every ${INTERVAL_MIN}m; Ctrl+C to stop (workers keep running)"

while :; do
    echo "── sync cycle $(date '+%F %T') ──"
    # Single-flight: skip if another sync is mid-flight
    if ! mkdir "$LOCK" 2>/dev/null; then
        echo "   sync already running elsewhere, skipping"
    else
        trap 'rmdir "$LOCK" 2>/dev/null' EXIT
        # Requeue leases from workers that died overnight (dead-worker recovery)
        bd reclaim --json >/dev/null 2>&1 || true
        # Sync output goes to the window AND the log (tee) so every cycle is visible
        "$REPO_ROOT/scripts/sync-beads-workers.sh" 2>&1 | tee -a "$REPO_ROOT/.beads-sync.log" | \
            rg -v "^worker[0-9]+: (clean|syncing)" || true
        # Hourly OpenRouter burn entry (cost-per-bead trending)
        BURN=$("$REPO_ROOT/scripts/log-burn.sh" 2>/dev/null) || true
        [ -n "$BURN" ] && echo "   $BURN"
        trap - EXIT
        rmdir "$LOCK"
    fi
    echo "   next cycle in ${INTERVAL_MIN}m"
    sleep $((INTERVAL_MIN * 60))
done
