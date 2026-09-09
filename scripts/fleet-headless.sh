#!/bin/bash
# Headless worker fleet: each worker is a supervision loop spawning
# `opencode run --session` rounds — no tmux TUIs, no send-keys, no
# window management. One driver process per worker; run each in its own
# tmux window (or under systemd/nohup) via:
#   scripts/fleet-headless.sh <worker_n> [rounds_per_session]
#
# Why: the tmux+send-keys design dropped prompts into half-mounted TUIs
# (the 2026-09-08 empty-session plague: rounds "dispatched" into void,
# in_progress zero, workers mass-restarted). A process model has no
# mounting races, and exit codes verify every round.
#
# The driver's guards all carry over:
#   - stall detection: N rounds with no closes -> fresh session
#   - freshness rotation: max rounds per session (default 8)
#   - self-report bridge: SELF-REPORT-DEGENERATE marker -> fresh session
#   - model: worker8 = hard-bead lane on gpt-5.6-luna
set -u
N="${1:?usage: fleet-headless.sh <worker_n> [rounds_per_session]}"
MAXROUNDS="${2:-8}"
REPO="/home/mark/Developer/lichen-workspace/project-LICHEN"
WT="$HOME/Developer/lichen-workers/worker$N"
STATE="/tmp/fleet-driver-state"
SESSIONS="$STATE/sessions"
mkdir -p "$STATE" "$SESSIONS"
export BEADS_DIR="$REPO/.beads"
export PATH="$HOME/.opencode/bin:$PATH"
cd "$WT" || exit 1

model() { [ "$N" -eq 8 ] && echo "openai/gpt-5.6-luna" || echo ""; }

PROMPT_COMMON='SELF-CHECK first: if you notice yourself repeating actions you already did, arguing with your own output, or unable to form a next step — touch ~/Developer/lichen-workers/worker'"$N"'/SELF-REPORT-DEGENERATE and end the round immediately; you will be restarted fresh. Otherwise: Continue the beads worker loop (instructions: scripts/beads-worker-full.txt). Claim the next ready bead, complete it fully (tests, 3x codereview delegating each pass to the reviewer model per step 4, findings filed as new beads, close, commit).'
PROMPT_FLASH="$PROMPT_COMMON Exactly one P0/P1/P2 bead this round. TAIL BATCHING: after your first bead, if it was quick, you may claim and close up to 3 more, but ONLY priority 3 or 4 beads — never batch P0-P2. TIMEBOX: if any bead is too big for ~15 minutes, commit the slice, file follow-ups, release, end the round."
PROMPT_HARD="You are the HARD-BEAD LANE (worker8, stronger model): claim P0/P1 priority beads first (bd ready --json, filter priority 0 or 1). $PROMPT_COMMON Exactly one bead this round. If no P0/P1 is ready, take any ready bead."
if [ "$N" -eq 8 ]; then PROMPT="$PROMPT_HARD"; else PROMPT="$PROMPT_FLASH"; fi

sess_id() { cat "$SESSIONS/worker$N.sid" 2>/dev/null; }
new_session() { rm -f "$SESSIONS/worker$N.sid" "$WT/SELF-REPORT-DEGENERATE"; }

rounds=0
while :; do
    if [ -f "$REPO/.fleet-paused" ]; then sleep 60; continue; fi

    # Round: fresh session or continue existing
    SID=$(sess_id)
    if [ -n "$SID" ]; then
        opencode run --session "$SID" "$PROMPT" >> "$STATE/worker$N.log" 2>&1
    else
        M=$(model)
        if [ -n "$M" ]; then
            opencode run -m "$M" "$PROMPT" >> "$STATE/worker$N.log" 2>&1
        else
            opencode run "$PROMPT" >> "$STATE/worker$N.log" 2>&1
        fi
        # Capture the session id opencode just used (first round establishes it)
        SID=$(opencode sessions list --format json 2>/dev/null | python3 -c "
import json, sys
try:
    rows = json.load(sys.stdin)
    rows = sorted(rows, key=lambda r: r.get('updated_at', ''), reverse=True)
    for r in rows:
        if r.get('directory', '').endswith('worker$N'):
            print(r.get('id', '')); break
except Exception: pass" 2>/dev/null)
        [ -n "$SID" ] && echo "$SID" > "$SESSIONS/worker$N.sid"
    fi
    RC=$?
    rounds=$((rounds + 1))

    # Self-report bridge
    if [ -f "$WT/SELF-REPORT-DEGENERATE" ]; then
        bd create --title="[info] worker$N self-reported degenerate (headless, restarted)" --description="Worker$N touched SELF-REPORT-DEGENERATE during a headless round. Fresh session on next round." -t task -p 4 --json >/dev/null 2>&1
        new_session; rounds=0
        continue
    fi

    # Freshness rotation
    if [ "$rounds" -ge "$MAXROUNDS" ]; then
        echo "$(date '+%F %T') worker$N: $MAXROUNDS-round rotation" >> "$STATE/worker$N.log"
        new_session; rounds=0
        continue
    fi

    # Stall detection: 5 consecutive rounds with zero 24h closes -> fresh
    CLOSES=$(bd list --status=closed --assignee "opencode-worker-$N" --json 2>/dev/null | python3 -c "
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
    if [ "${CLOSES:-0}" -eq 0 ]; then
        NOCLOSE=$(( $(cat "$STATE/worker$N.noclose" 2>/dev/null || echo 0) + 1 ))
        echo "$NOCLOSE" > "$STATE/worker$N.noclose"
        if [ "$NOCLOSE" -ge 5 ]; then
            bd create --title="[info] worker$N stalled (headless, fresh session)" --description="5 consecutive rounds with zero 24h closures; session rotated." -t task -p 4 --json >/dev/null 2>&1
            new_session; rounds=0; echo 0 > "$STATE/worker$N.noclose"
        fi
    else
        echo 0 > "$STATE/worker$N.noclose"
    fi

    # Outcome canary contribution + small breath between rounds
    sleep 5
done
