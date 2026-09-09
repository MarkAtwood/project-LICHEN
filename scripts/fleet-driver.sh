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

ROUND_PROMPT='SELF-CHECK first: if you notice yourself repeating actions you already did, arguing with your own output, or unable to form a next step — touch ~/Developer/lichen-workers/worker<YOUR_N>/SELF-REPORT-DEGENERATE and end the round immediately; the driver will restart you fresh. Otherwise: Continue the beads worker loop (instructions: scripts/beads-worker-full.txt). Claim the next ready bead, complete it fully (tests, 3x codereview delegating each pass to the reviewer model per step 4, findings filed as new beads, close, commit). Exactly one P0/P1/P2 bead this round. TAIL BATCHING: after your first bead, if it was quick, you may claim and close up to 3 more, but ONLY priority 3 or 4 beads (small polish) — never batch P0-P2. TIMEBOX: if any bead is too big to finish within ~15 minutes, follow the TIMEBOX rule — commit the slice, file follow-ups, release, end the round.'

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

HARD_PROMPT='SELF-CHECK first: if you notice yourself repeating actions you already did, arguing with your own output, or unable to form a next step — touch ~/Developer/lichen-workers/worker<YOUR_N>/SELF-REPORT-DEGENERATE and end the round immediately. Otherwise: You are the HARD-BEAD LANE (worker8, stronger model): claim P0/P1 priority beads first (bd ready --json, filter priority 0 or 1) — the beads others timebox out of. Same loop otherwise (instructions: scripts/beads-worker-full.txt): claim, complete fully (tests, 3x codereview, findings filed as beads, close, commit), then stop and report. Exactly one bead this round. If no P0/P1 is ready, take any ready bead.'

EMPTY_N=0
mkdir -p /tmp/fleet-driver-state
worker_cmd() {  # worker8 is the hard-bead lane on a stronger model
    if [ "$1" -eq 8 ]; then echo "opencode -m openai/gpt-5.6-luna"; else echo "opencode"; fi
}
while :; do
    if [ -f "$REPO_ROOT/.fleet-paused" ]; then
        PAUSE_AGE=$(( $(date +%s) - $(stat -c %Y "$REPO_ROOT/.fleet-paused") ))
        if [ "$PAUSE_AGE" -gt 3600 ]; then
            rm -f "$REPO_ROOT/.fleet-paused"
            BEADS_DIR="$BEADS_DIR" bd create --title="[ALARM] Pause expired after 60 min - auto-resumed" --description="A fleet-pause marker outlived 60 minutes (age: ${PAUSE_AGE}s). The pause protocol exists for short repairs; an orphaned pause is pure waste (2026-09-09: 2 hours lost this way). Auto-resumed; the operator who paused should verify their repair landed." -t bug -p 1 --json >/dev/null 2>&1
            echo "ALARM: pause expired (${PAUSE_AGE}s) — auto-resumed"
        else
            echo "driver PAUSED: $(head -1 "$REPO_ROOT/.fleet-paused") ($((PAUSE_AGE/60))m old)"
            sleep $((CYCLE_MIN * 60))
            continue
        fi
    fi
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

    # Outcome canary (the week's real lesson): if the fleet closes almost
    # nothing in 24h, ALARM — components can all look alive while the
    # worktrees are gone. Marker + bead so it's visible on any host.
    DAY_CLOSES=$(BEADS_DIR="$BEADS_DIR" bd list --status=closed --json 2>/dev/null | python3 -c "
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
    echo "   24h closures: $DAY_CLOSES"
    if [ "${DAY_CLOSES:-0}" -lt 5 ] && [ ! -f "$REPO_ROOT/.fleet-stalled" ]; then
        date '+%F %T' > "$REPO_ROOT/.fleet-stalled"
        BEADS_DIR="$BEADS_DIR" bd create --title="[ALARM] Fleet stalled: $DAY_CLOSES closures in 24h" --description="The outcome canary fired: fewer than 5 closures in 24 hours while the fleet should be closing 15-20/h. Components may look alive (windows present, sessions busy) while being unable to work — the 2026-09-02..07 outage looked exactly like this (vanished worktrees). CHECK: worktree dirs exist, driver dispatching, workers actually closing, merge state healthy." -t bug -p 1 --json >/dev/null 2>&1
        echo "   ALARM: fleet outcome stalled — bead filed"
    elif [ "${DAY_CLOSES:-0}" -ge 5 ]; then
        rm -f "$REPO_ROOT/.fleet-stalled"
    fi
    # Waste alarm: function-per-dollar. Burn over 24h ÷ closures over 24h.
    # If cost-per-close exceeds $3 (2.5x the ~$1.20 baseline), that is the
    # signature of spend buying no function — the dead-week signature.
    BURN_24H=$(python3 - <<'BURN'
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
    # total_usage is lifetime; snapshot it daily to derive the delta
    snap_path = "/tmp/fleet-driver-state/burn-snapshot.json"
    now_s = __import__("time").time()
    prev = json.load(open(snap_path)) if os.path.exists(snap_path) else None
    cur = {"usage": float(d.get("total_usage", 0)), "ts": now_s}
    json.dump(cur, open(snap_path, "w"))
    if prev and (now_s - prev["ts"]) > 20 * 3600:  # ~24h window
        burn = max(0.0, cur["usage"] - prev["usage"])
        print(f"{burn:.2f}")
    else:
        print("unknown")
except Exception:
    print("unknown")
BURN
)
    if [ "$BURN_24H" != "unknown" ] && [ "${DAY_CLOSES:-0}" -gt 0 ]; then
        CPC=$(python3 -c "print(f'{$BURN_24H/$DAY_CLOSES:.2f}')")
        echo "   cost-per-close (24h): \$${CPC} (burn \$${BURN_24H} / ${DAY_CLOSES})"
        OVER=$(python3 -c "print(1 if $BURN_24H/$DAY_CLOSES > 3.0 else 0)")
        if [ "$OVER" = "1" ] && [ ! -f "$REPO_ROOT/.fleet-waste" ]; then
            date '+%F %T' > "$REPO_ROOT/.fleet-waste"
            BEADS_DIR="$BEADS_DIR" bd create --title="[ALARM] Waste: cost-per-close \$${CPC} exceeds \$3" --description="24h burn \$$BURN_24H / $DAY_CLOSES closures = \$${CPC} per close (baseline ~\$1.20). Spend is buying less than half its normal function — the dead-week signature. Check: fleet stall? incident repair eating cycles? failed merge sessions? self-modification gone wrong?" -t bug -p 1 --json >/dev/null 2>&1
            echo "   ALARM: waste signature — \$${CPC}/close"
        elif [ "$OVER" = "0" ]; then
            rm -f "$REPO_ROOT/.fleet-waste"
        fi
    fi

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
        for i in 1 2 3 4 5 6 7 8; do
            WIN="$SESSION:worker$i"
            tmux has-session -t "$SESSION" 2>/dev/null || break
            if ! tmux select-window -t "$WIN" 2>/dev/null; then
                # Self-heal: a worker window that died (e.g. opencode crashed on
                # a fatal API error) is recreated automatically — the overnight
                # w4/w7 context-death sat unnoticed for hours (bead biod era).
                echo "   worker$i: window missing — recreating"
                tmux new-window -d -t "$SESSION" -n "worker$i" \
                    "cd $HOME/Developer/lichen-workers/worker$i && exec $(worker_cmd $i)"
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
                tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec $(worker_cmd $i)"
                tmux set-window-option -t "$SESSION:worker$i" automatic-rename off 2>/dev/null
                rm -f "$STATEF"
                BEADS_DIR="$BEADS_DIR" bd create --title="[info] worker$i self-reported degenerate (restarted)" --description="Worker$i touched SELF-REPORT-DEGENERATE: it detected its own context rot and asked for a fresh session. Driver restarted it. Watch for repeat self-reports from the same worker within a day." -t task -p 4 --json >/dev/null 2>&1
                echo "   worker$i: self-reported degenerate — restarted fresh"
                continue
            fi
            # Session-age rotation: cap context-rot exposure at 24h.
            NOW=$(date +%s)
            if [ ! -f "$STATEF.born" ]; then
                echo "$NOW" > "$STATEF.born"   # first sight: no rotation
                BORN=$NOW
            else
                BORN=$(cat "$STATEF.born")
            fi
            if [ $((NOW - BORN)) -gt 86400 ]; then
                echo "   worker$i: session older than 24h — rotating (context-rot cap)"
                tmux kill-window -t "$WIN" 2>/dev/null
                tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec $(worker_cmd $i)"
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
                    tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec $(worker_cmd $i)"
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
                tmux new-window -d -t "$SESSION" -n "worker$i" "cd $HOME/Developer/lichen-workers/worker$i && exec $(worker_cmd $i)"
                tmux set-window-option -t "$SESSION:worker$i" automatic-rename off 2>/dev/null
                echo "$(date +%s)" > "$STATEF.born"
                echo 0 > "$STATEF.rounds"
                echo 0 > "$STATEF.total"
                continue
            fi
            echo "$((TOTAL + 1))" > "$STATEF.total"
            if [ "$i" -eq 8 ]; then PROMPT="$HARD_PROMPT"; else PROMPT="$ROUND_PROMPT"; fi
            echo "   worker$i: dispatching round (session round $((TOTAL + 1))/8)${i:+}"
            wait_ready "$WIN"
            tmux send-keys -t "$WIN" -l "$PROMPT"
            sleep 1
            tmux send-keys -t "$WIN" Enter
            sleep 3
        done
    fi
    sleep $((CYCLE_MIN * 60))
done
