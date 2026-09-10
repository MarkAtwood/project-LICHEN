#!/bin/bash
# Fleet guards: the outcome canary, waste alarm, burn marker, and pause
# expiry — extracted from the retired fleet-driver.sh so they survive the
# headless migration (they were orphaned overnight 2026-09-08/09: 8 hours
# of near-zero closures burned ~$720 with NO alarm, because the guards
# were dead code in a driver that no longer runs).
# Usage: scripts/fleet-guards.sh [cycle_minutes]  (watchdog ensures a window)
set -u
REPO="/home/mark/Developer/lichen-workspace/project-LICHEN"
CYCLE_MIN="${1:-10}"
case "$CYCLE_MIN" in ''|*[!0-9]*|0) echo "fleet-guards: cycle_minutes must be a positive integer (got '$CYCLE_MIN')" >&2; exit 1;; esac
export BEADS_DIR="$REPO/.beads"
cd "$REPO" || exit 1
STATE="/tmp/fleet-driver-state"
mkdir -p "$STATE"

closes_24h() {
    BEADS_DIR="$BEADS_DIR" bd list --status=closed --json 2>/dev/null | python3 -c "
import json, sys, datetime
now = datetime.datetime.now(datetime.timezone.utc)
n = 0
for i in json.load(sys.stdin):
    t = i.get('closed_at') or ''
    try:
        c = datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
        if (now - c).total_seconds() <= 86400: n += 1
    except Exception: pass
print(n)" 2>/dev/null || echo 0
}

# Escalate a failing waste-alarm helper to the queue, once per failure
# episode (flag cleared on the first clean parse below). Log-only WARNs
# would repeat every cycle with no durable record — the same silent-death
# class the guards exist to prevent (lh2z).
waste_helper_alarm() {
    if [ ! -f "$REPO/.fleet-waste-helper" ]; then
        date '+%F %T' > "$REPO/.fleet-waste-helper"
        bd create --title="[ALARM] Waste alarm helper failing: fleet_burn.py empty/unparseable output" --description="The waste alarm and the burn marker are blind: scripts/fleet_burn.py produced empty or non-JSON output from the guards loop. Check the helper exists at \$REPO/scripts/fleet_burn.py and inspect the interpreter traceback captured in \$STATE/fleet_burn.err (guards log has the last stderr line per cycle). Alarm re-arms automatically after the first clean helper run." -t bug -p 1 --json >/dev/null 2>&1
        echo "$(date '+%F %T') ALARM: waste alarm helper failing — bd issue filed"
    fi
}

total_used() {
    python3 - <<'PY'
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
}

echo "fleet guards: cycle ${CYCLE_MIN}m — Ctrl+C to stop"
while :; do
    # PAUSE EXPIRY: auto-resume after 60 min
    if [ -f "$REPO/.fleet-paused" ]; then
        PAUSE_AGE=$(( $(date +%s) - $(stat -c %Y "$REPO/.fleet-paused") ))
        if [ "$PAUSE_AGE" -gt 3600 ]; then
            rm -f "$REPO/.fleet-paused" "$REPO/.fleet-workers-paused"
            bd create --title="[ALARM] Pause expired after 60 min - auto-resumed" --description="Fleet pause outlived 60 minutes (${PAUSE_AGE}s). Auto-resumed by the guards loop; the operator who paused should verify their repair landed." -t bug -p 1 --json >/dev/null 2>&1
            echo "$(date '+%F %T') ALARM: pause expired (${PAUSE_AGE}s) — auto-resumed"
        fi
    fi

    # Workers-pause expiry: same 60-min guard, independent of full pause
    if [ -f "$REPO/.fleet-workers-paused" ]; then
        WP_AGE=$(( $(date +%s) - $(stat -c %Y "$REPO/.fleet-workers-paused") ))
        if [ "$WP_AGE" -gt 3600 ]; then
            rm -f "$REPO/.fleet-workers-paused"
            bd create --title="[ALARM] Workers-pause expired after 60 min - auto-resumed" --description="Workers-only pause outlived 60 minutes (${WP_AGE}s). Auto-resumed; merge drain should be checked." -t bug -p 1 --json >/dev/null 2>&1
        fi
    fi

    # OUTCOME CANARY: closures collapsing = silent fleet failure
    CLOSES=$(closes_24h)
    echo "$(date '+%F %T') 24h closures: $CLOSES"
    if [ "${CLOSES:-0}" -lt 5 ] && [ ! -f "$REPO/.fleet-stalled" ]; then
        date '+%F %T' > "$REPO/.fleet-stalled"
        bd create --title="[ALARM] Fleet stalled: $CLOSES closures in 24h" --description="Outcome canary: fewer than 5 closures in 24h while the fleet should be closing 15-40/h. Components may all look alive. CHECK: worktrees exist, headless loops running, store healthy, merge state." -t bug -p 1 --json >/dev/null 2>&1
        echo "$(date '+%F %T') ALARM: fleet outcome stalled"
    elif [ "${CLOSES:-0}" -ge 5 ]; then
        rm -f "$REPO/.fleet-stalled"
    fi

    # WASTE ALARM: cost-per-close against a retained 24h burn baseline.
    # The snapshot is the window baseline: written only on the first valid
    # observation or after a full window elapses. (Previously it was
    # overwritten every cycle, so AGE never crossed 24h and this alarm
    # never evaluated — lh2z.) Logic lives in fleet_burn.py for testability.
    USED=$(total_used)
    NOW_S=$(date +%s)
    W_ERR="$STATE/fleet_burn.err"
    WASTE=$(python3 "$REPO/scripts/fleet_burn.py" "$STATE" "$USED" "${CLOSES:-0}" "$NOW_S" 2>"$W_ERR")
    W_EVAL=$(echo "$WASTE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('evaluated', False))" 2>/dev/null || echo PARSE_FAIL)
    W_HINT=$(tail -n 1 "$W_ERR" 2>/dev/null)
    if [ -z "$WASTE" ]; then
        waste_helper_alarm
        echo "$(date '+%F %T') WARN: waste alarm skipped — fleet_burn.py produced no output (helper missing at $REPO/scripts/fleet_burn.py, or interpreter crash)${W_HINT:+ — last stderr: $W_HINT} [full stderr: $W_ERR]"
    elif [ "$W_EVAL" = "PARSE_FAIL" ]; then
        waste_helper_alarm
        echo "$(date '+%F %T') WARN: waste alarm skipped — fleet_burn.py output not valid JSON${W_HINT:+ — last stderr: $W_HINT} [full stderr: $W_ERR]"
    else
        rm -f "$REPO/.fleet-waste-helper"
        if [ "$W_EVAL" = "True" ]; then
            W_BURN=$(echo "$WASTE" | python3 -c "import json,sys; print(json.load(sys.stdin)['burn'])")
            W_CPC=$(echo "$WASTE" | python3 -c "import json,sys; print(json.load(sys.stdin)['cpc_str'])")
            W_OVER=$(echo "$WASTE" | python3 -c "import json,sys; print(json.load(sys.stdin)['over'])")
            echo "   cost-per-close (24h): \$$W_CPC (burn \$$W_BURN / $CLOSES)"
            if [ "$W_OVER" = "True" ] && [ ! -f "$REPO/.fleet-waste" ]; then
                date '+%F %T' > "$REPO/.fleet-waste"
                bd create --title="[ALARM] Waste: cost-per-close \$$W_CPC exceeds \$3" --description="24h-window burn \$$W_BURN / $CLOSES closures = \$$W_CPC/close (baseline ~\$1.20). Spend buying less than half its normal function. Check: stalls? failed merge sessions? store conflicts degrading bd? self-modification issues?" -t bug -p 1 --json >/dev/null 2>&1
                echo "   ALARM: waste signature — \$$W_CPC/close"
            elif [ "$W_OVER" = "False" ]; then
                rm -f "$REPO/.fleet-waste"
            fi
        fi
    fi

    # BURN MARKER: $2000 milestone (on record, never pauses)
    if [ "$USED" -ge 2000 ] && [ ! -f "$REPO/.fleet-burn-2000" ]; then
        date '+%F %T' > "$REPO/.fleet-burn-2000"
        bd create --title="[info] Burn reached 2000 USD (milestone, ceiling removed)" --description="Total OpenRouter usage crossed the former watch line. Per Mark: budget raised to an undisclosed ceiling; function-per-dollar is the only metric. Marker on record." -t task -p 4 --json >/dev/null 2>&1
        echo "$(date '+%F %T') milestone: $2,000 total crossed"
    fi

    sleep $((CYCLE_MIN * 60))
done
