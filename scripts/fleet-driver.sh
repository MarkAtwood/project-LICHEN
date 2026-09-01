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

wait_ready() {  # poll until the worker pane shows the model banner (input-ready)
    local win="$1" n
    for n in $(seq 1 20); do
        tmux capture-pane -t "$win" -p 2>/dev/null | rg -q "Build ·" && return 0
        sleep 2
    done
    return 1
}

worker_in_progress() {  # worker number; count of that actor's in_progress beads
    BEADS_DIR="$BEADS_DIR" bd list --status in_progress --assignee "opencode-worker-$1" --json 2>/dev/null | jq "length" 2>/dev/null || echo 0
}

echo "fleet driver: cycle ${CYCLE_MIN}m, no credit gating (auto-topup) — Ctrl+C to stop"

EMPTY_N=0
while :; do
    CREDITS=$(remaining_credits)
    echo "── driver $(date '+%F %T') credits=$CREDITS ──"
    READY=$(BEADS_DIR="$BEADS_DIR" bd ready --json 2>/dev/null | jq "length" 2>/dev/null || echo 0)

    if [ "$READY" -eq 0 ]; then
        echo "   ready queue empty — nothing to dispatch"
        EMPTY_N=$((EMPTY_N + 1))
        if [ "$EMPTY_N" -eq 3 ] && [ ! -f "$REPO_ROOT/.fleet-drained" ]; then
            date '+%F %T' > "$REPO_ROOT/.fleet-drained"
            BEADS_DIR="$BEADS_DIR" bd create --title="[info] Fleet drained: ready queue empty" --description="The worker swarm exhausted all claimable work at $(date -u '+%F %T'). Remaining open beads are human-decision or hardware-blocked. Sync loop and janitor keep running; nothing was closed prematurely. Parked awaiting Mark." -t task -p 4 --json >/dev/null 2>&1
            echo "   fleet drained — marker filed"
        fi
    else
        EMPTY_N=0
        rm -f "$REPO_ROOT/.fleet-drained"
        echo "   workers have work"
        for i in 1 2 3 4 5 6 7; do
            WIN="$SESSION:worker$i"
            tmux has-session -t "$SESSION" 2>/dev/null || break
            tmux select-window -t "$WIN" 2>/dev/null || { echo "   worker$i: window missing"; continue; }
            pane_busy "$WIN" && { echo "   worker$i: busy"; continue; }
            NIP=$(worker_in_progress "$i")
            [ "$NIP" -gt 0 ] && { echo "   worker$i: holds $NIP in-progress bead(s) — waiting"; continue; }
            echo "   worker$i: dispatching round"
            wait_ready "$WIN"
            tmux send-keys -t "$WIN" -l "$ROUND_PROMPT"
            sleep 1
            tmux send-keys -t "$WIN" Enter
            sleep 3
        done
    fi
    sleep $((CYCLE_MIN * 60))
done
