#!/bin/bash
# Fleet watchdog: resurrects the four fleet daemons if they die, including
# after a heft reboot. Runs from cron every 2 minutes:
#   */2 * * * * flock -n /tmp/fleet-watchdog.lock $REPO/scripts/fleet-watchdog.sh
# Idempotent: only creates what is missing. Worker windows are the driver's
# job (it self-heals those); this covers the controllers.
set -u
REPO="/home/mark/Developer/lichen-workspace/project-LICHEN"
SESSION="lichen-workers"
cd "$REPO" || exit 1

ensure_window() {  # $1=index $2=name $3=command — create only if missing
    if ! tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux new-session -d -s "$SESSION" -n "$2" "cd $REPO && exec bash"
    fi
    if ! tmux list-windows -t "$SESSION" -F '#{window_name}' 2>/dev/null | grep -qx "$2"; then
        tmux new-window -d -t "$SESSION:$1" -n "$2" "cd $REPO && $3"
        echo "$(date '+%F %T') watchdog: recreated $2" >> "$REPO/.beads-sync.log"
    fi
}

# The four controllers (worker windows 0-6 are the driver's responsibility)
ensure_window 7 sync  "exec ./scripts/sync-beads-loop.sh 15"
ensure_window 8 driver "exec ./scripts/fleet-driver.sh 10 0"
ensure_window 10 janitor "exec ./scripts/merge-janitor.sh"

# sweep-all: only if discovery is still pending (any of the section stems
# missing) — a completed sweep must NOT be resurrected.
PENDING=0
for s in 09-packets-timing 02a-coordinated-capacity 03-adaptation 06-security \
         02-physical-link 12-apps 01-architecture 04-network 07-transport-app \
         08-gateway-coordination 08-nodes 10-implementation 11-lci \
         appendix-border-router appendix-bufferbloat appendix-c-safety \
         draft-lichen-schnorr-00; do
    [ -f "docs/spec-coverage/$s.md" ] || PENDING=1
done
if [ "$PENDING" -eq 1 ] && ! pgrep -f 'Spec Coverage Sweep' >/dev/null 2>&1; then
    ensure_window 9 sweep-all "exec ./scripts/spec-sweep-all.sh"
fi
