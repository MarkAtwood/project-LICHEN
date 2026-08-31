#!/bin/bash
# Fleet driver: the unattended orchestrator for the heft swarm.
# Every cycle: (1) un-stick workers paused by the credit floor or missed
# idle events, (2) enforce one-bead-per-worker at claim time, (3) rerun the
# spec wave runner when it paused on credits. Runs in its own tmux window.
# Usage: scripts/fleet-driver.sh [cycle_minutes] [credit_floor]

SESSION="lichen-workers"
CYCLE_MIN="${1:-10}"
FLOOR="${2:-50}"
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$HOME/Developer/lichen-workspace/project-LICHEN")
export BEADS_DIR="${BEADS_DIR:-$REPO_ROOT/.beads}"
export PATH="$HOME/.opencode/bin:$PATH"

ROUND_PROMPT='Continue the beads worker loop (instructions: scripts/beads-worker-full.txt). Claim the next ready bead, complete it fully (tests, 3x codereview delegating each pass to the reviewer model per step 4, findings filed as new beads, close, commit), then stop and report. Exactly one bead this round. TIMEBOX: if the bead is too big to finish within ~15 minutes, follow the TIMEBOX rule — commit the slice, file follow-ups, release, end the round.'

remaining_credits() {
    KEY=$(python3 - <<PYEOF
import json, os
c = json.load(open(os.path.expanduser("~/.config/opencode/opencode.json")))
def find(d):
    if isinstance(d, dict):
        for k, v in d.items():
            if k == "apiKey" and isinstance(v, str) and v.startswith("sk-or-"):
                print(v); return True
            if find(v): return True
    elif isinstance(d, list):
        for x in d:
            if find(x): return True
    return False
find(c)
PYEOF
)
    [ -z "$KEY" ] && { echo 0; return; }
    curl -s --max-time 30 https://openrouter.ai/api/v1/credits -H "Authorization: Bearer $KEY" | \
        python3 -c "import json,sys; d=json.load(sys.stdin).get('data',{}); print(int(d.get('total_credits',0)-d.get('total_usage',0)))" 2>/dev/null || echo 0
}

pane_busy() {  # exit 0 (true) only when the pane shows a running generation
    tmux capture-pane -t "$SESSION:$1" -p -S -5 2>/dev/null | rg -q "esc interrupt"
}

worker_in_progress() {  # worker number; count of that actor's in_progress beads
    BEADS_DIR="$BEADS_DIR" bd list --status in_progress --assignee "opencode-worker-$1" --json 2>/dev/null | jq "length" 2>/dev/null || echo 0
}

echo "fleet driver: cycle ${CYCLE_MIN}m, credit floor \$$FLOOR — Ctrl+C to stop"

while :; do
    CREDITS=$(remaining_credits)
    echo "── driver $(date '+%F %T') credits=$CREDITS ──"
    READY=$(BEADS_DIR="$BEADS_DIR" bd ready --json 2>/dev/null | jq "length" 2>/dev/null || echo 0)

    if [ "$READY" -eq 0 ]; then
        echo "   ready queue empty — nothing to dispatch"
    elif [ "$CREDITS" -lt "$FLOOR" ]; then
        echo "   credits $CREDITS below floor $FLOOR — rounds paused (auto-topup will replenish)"
    else
        for i in 1 2 3 4 5 6 7; do
            WIN="$SESSION:worker$i"
            tmux has-session -t "$SESSION" 2>/dev/null || break
            tmux select-window -t "$WIN" 2>/dev/null || { echo "   worker$i: window missing"; continue; }
            pane_busy "$WIN" && { echo "   worker$i: busy"; continue; }
            NIP=$(worker_in_progress "$i")
            [ "$NIP" -gt 0 ] && { echo "   worker$i: holds $NIP in-progress bead(s) — waiting"; continue; }
            echo "   worker$i: dispatching round"
            tmux send-keys -t "$WIN" -l "$ROUND_PROMPT"
            sleep 1
            tmux send-keys -t "$WIN" Enter
            sleep 3
        done
        # Un-stick the wave runner if it paused on credits and credits recovered
        SW=$(tmux capture-pane -t "$SESSION:sweep-all" -p -S -30 2>/dev/null | rg -c "pausing sweep" || true)
        if [ "${SW:-0}" -gt 0 ]; then
            tmux send-keys -t "$SESSION:sweep-all" -l "scripts/spec-sweep-all.sh $FLOOR"
            sleep 0.5
            tmux send-keys -t "$SESSION:sweep-all" Enter
            echo "   wave runner resumed"
        fi
    fi
    sleep $((CYCLE_MIN * 60))
done
