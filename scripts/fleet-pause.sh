#!/bin/bash
# Pause the fleet: driver stops dispatching, sync loop and janitor skip
# cycles. In-flight worker rounds finish naturally (workers idle after).
# Usage: scripts/fleet-pause.sh [reason...]
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo /home/mark/Developer/lichen-workspace/project-LICHEN)" || exit 1
echo "$(date '+%F %T') — ${*:-maintenance}" > .fleet-paused
echo "fleet paused: ${*:-maintenance} (driver/janitor/sync idle from their next cycle; in-flight rounds finish)"
