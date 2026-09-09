#!/bin/bash
# Resume the fleet after scripts/fleet-pause.sh.
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo /home/mark/Developer/lichen-workspace/project-LICHEN)" || exit 1
rm -f .fleet-paused
echo "fleet resumed — daemons pick up on their next cycle (driver ≤10m, janitor ≤10m, sync ≤15m)"
