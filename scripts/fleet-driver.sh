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

ROUND_PROMPT='SELF-CHECK first: if you notice yourself repeating actions you already did, arguing with your own output, or unable to form a next step — touch ~/Developer/lichen-workers/worker<YOUR_N>/SELF-REPORT-DEGENERATE and end the round immediately; the driver will restart you fresh. Otherwise: Continue the beads worker loop (instructions: scripts/beads-worker-full.txt). Claim the next ready bead, complete it fully (tests, 3x codereview delegating each pass to the reviewer model per step 4, findings filed as new beads, close, commit), then stop and report. Exactly one bead this round. TIMEBOX: if the bead is too big to finish within ~15 minutes, follow the TIMEBOX rule — commit the slice, file follow-ups, release, end the round.'

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
mkdir -p /tmp/fleet-driver-state
while :; do
    CREDITS=$(remaining_credits)
    echo "── driver $(date '+%F %T') credits=$CREDITS ──"
    # Burn ceiling marker (Mark: $2000 is the 'tell me' line). Marker only —
    # never pauses the fleet.
    if [ -f "$REPO_ROOT/.fleet-burn-2000" ]; then :; else
        TOTAL_USED=$(python3 - <<'PY'
import json, os, urllib.request
try:
    c = json.load(open(os.path.expanduser("~/.config/opencode/opencode.json")))
    def find(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if k == "apiKey" and isinstance(v, str) and v.startswith("sk-or-"):
                    return v
                r = find(v)
                if r: return r
        elif isinstance(d, list):
            for x in d:
                r = find(x)
                if r: return r
        return None
    key = find(c)
    req = urllib.request.Request("https://openrouter.ai/api/v1/credits", headers={"Authorization": "Bearer " + key})
    d = json.load(urllib.request.urlopen(req, timeout=30)).get("data", {})
    print(int(float(d.get("total_usage", 0))))
except Exception:
    print(0)
PY
)
        if [ "$TOTAL_USED" -ge 2000 ]; then
            date '+%F %T' > "$REPO_ROOT/.fleet-burn-2000"
            BEADS_DIR="$BEADS_DIR" bd create --title="[info] Burn reached 2000 USD (ceiling reached)" --description="Total OpenRouter usage crossed the 2000 USD watch line. Fleet continues per policy; marker on record. Remaining ready-queue size decides whether the work fits the budget - see bd stats." -t task -p 4 --json >/dev/null 2>&1
        fi
    fi
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
            if ! tmux select-window -t "$WIN" 2>/dev/null; then
                # Self-heal: a worker window that died (e.g. opencode crashed on
                # a fatal API error) is recreated automatically — the overnight
                # w4/w7 context-death sat unnoticed for hours (bead biod era).
                echo "   worker$i: window missing — recreating"
                tmux new-window -d -t "$SESSION" -n "worker$i" \
                    "cd $HOME/Developer/lichen-workers/worker$i && exec opencode"
                tmux set-window-option -t "$SESSION:worker$i" automatic-rename off 2>/dev/null
                continue
            fi
            pane_busy "$WIN" && { echo "   worker$i: busy"; continue; }
            NIP=$(worker_in_progress "$i")
            [ "$NIP" -gt 0 ] && { echo "   worker$i: holds $NIP in-progress bead(s) — waiting"; continue; }
            STATEF="/tmp/fleet-driver-state/worker$i"
            # Self-report bridge: the agent flagged itself degenerate.
            if [ -f "$HOME/Developer/lichen-workers/worker$i/SELF-REPORT-DEGENERATE" ]; then
                rm -f "$HOME/Developer/lichen-workers/worker$i/SELF-REPORT-DEGENERATE"
                tmux kill-window -t "$WIN" 2>/dev/null
                tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec opencode"
                tmux set-window-option -t "$SESSION:worker$i" automatic-rename off 2>/dev/null
                rm -f "$STATEF"
                BEADS_DIR="$BEADS_DIR" bd create --title="[info] worker$i self-reported degenerate (restarted)" --description="Worker$i touched SELF-REPORT-DEGENERATE: it detected its own context rot and asked for a fresh session. Driver restarted it. Watch for repeat self-reports from the same worker within a day." -t task -p 4 --json >/dev/null 2>&1
                echo "   worker$i: self-reported degenerate — restarted fresh"
                continue
            fi
            # Session-age rotation: cap context-rot exposure at 24h.
            BORN=$(cat "$STATEF.born" 2>/dev/null || echo 0)
            NOW=$(date +%s)
            if [ "$BORN" -eq 0 ]; then echo "$NOW" > "$STATEF.born"; fi
            if [ $((NOW - BORN)) -gt 86400 ]; then
                echo "   worker$i: session older than 24h — rotating (context-rot cap)"
                tmux kill-window -t "$WIN" 2>/dev/null
                tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec opencode"
                tmux set-window-option -t "$SESSION:worker$i" automatic-rename off 2>/dev/null
                echo "$NOW" > "$STATEF.born"
                echo 0 > "$STATEF.rounds"
                continue
            fi
            # Stall detection: 5+ dispatched rounds with zero closes = degenerate.
            CLOSES=$(BEADS_DIR="$BEADS_DIR" bd list --status=closed --assignee "opencode-worker-$i" --json 2>/dev/null | python3 -c "
import json, sys, datetime
now = datetime.datetime.now(datetime.timezone.utc)
n = 0
for i in json.load(sys.stdin):
    t = i.get('closed_at') or ''
    try:
        c = datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
        if (now - c).total_seconds() <= 86400: n += 1
    except Exception: pass
print(n)" 2>/dev/null || echo 0)
            if [ "${CLOSES:-0}" -gt 0 ]; then
                echo 0 > "$STATEF.rounds"
            else
                ROUNDS=$(cat "$STATEF.rounds" 2>/dev/null || echo 0)
                ROUNDS=$((ROUNDS + 1))
                echo "$ROUNDS" > "$STATEF.rounds"
                if [ "$ROUNDS" -ge 5 ]; then
                    rm -f "$STATEF.rounds" "$STATEF.born"
                    tmux kill-window -t "$WIN" 2>/dev/null
                    tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec opencode"
                    tmux set-window-option -t "$SESSION:worker$i" automatic-rename off 2>/dev/null
                    BEADS_DIR="$BEADS_DIR" bd create --title="[info] worker$i stalled (0 closes in 5+ rounds, restarted)" --description="Driver stall detector: worker$i burned 5+ dispatched rounds with zero closures in 24h — the 'jabbering' degeneration signature. Session restarted fresh. If it recurs on the same worker, investigate its affinity pool (hard beads repeating?)." -t task -p 4 --json >/dev/null 2>&1
                    echo "   worker$i: STALLED (5 rounds, 0 closes) — restarted fresh"
                    continue
                fi
            fi
            # Freshness rotation: 8 rounds (beads) per session max — fresh
            # sessions close briskly, old ones rot (the 4-day insanity lesson).
            # Fires only on idle bead-free workers, so no work is killed.
            TOTAL=$(cat "$STATEF.total" 2>/dev/null || echo 0)
            if [ "$TOTAL" -ge 8 ]; then
                echo "   worker$i: 8-round freshness rotation"
                tmux kill-window -t "$WIN" 2>/dev/null
                tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec opencode"
                tmux set-window-option -t "$SESSION:worker$i" automatic-rename off 2>/dev/null
                echo "$(date +%s)" > "$STATEF.born"
                echo 0 > "$STATEF.rounds"
                echo 0 > "$STATEF.total"
                continue
            fi
            echo "$((TOTAL + 1))" > "$STATEF.total"
            echo "   worker$i: dispatching round (session round $((TOTAL + 1))/8)"
            wait_ready "$WIN"
            tmux send-keys -t "$WIN" -l "$ROUND_PROMPT"
            sleep 1
            tmux send-keys -t "$WIN" Enter
            sleep 3
        done
    fi
    sleep $((CYCLE_MIN * 60))
done
