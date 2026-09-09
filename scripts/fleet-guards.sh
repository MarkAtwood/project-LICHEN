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
            rm -f "$REPO/.fleet-paused"
            bd create --title="[ALARM] Pause expired after 60 min - auto-resumed" --description="Fleet pause outlived 60 minutes (${PAUSE_AGE}s). Auto-resumed by the guards loop; the operator who paused should verify their repair landed." -t bug -p 1 --json >/dev/null 2>&1
            echo "$(date '+%F %T') ALARM: pause expired (${PAUSE_AGE}s) — auto-resumed"
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

    # WASTE ALARM: cost-per-close over trailing 24h
    USED=$(total_used)
    SNAP="$STATE/burn-snapshot.json"
    NOW_S=$(date +%s)
    if [ -f "$SNAP" ]; then
        PREV_USED=$(python3 -c "import json; print(int(json.load(open('$SNAP'))['usage']))" 2>/dev/null || echo 0)
        PREV_TS=$(python3 -c "import json; print(int(json.load(open('$SNAP'))['ts']))" 2>/dev/null || echo 0)
        AGE=$((NOW_S - PREV_TS))
        if [ "$AGE" -gt 86400 ] && [ "${CLOSES:-0}" -gt 0 ]; then
            BURN=$((USED - PREV_USED))
            if [ "$BURN" -gt 0 ]; then
                CPC=$(python3 -c "print(f'{$BURN/$CLOSES:.2f}')")
                echo "   cost-per-close (24h): \$$CPC (burn \$$BURN / $CLOSES)"
                if [ "$CLOSES" -gt 0 ]; then
                    OVER=$(python3 -c "print(1 if $BURN/$CLOSES > 3.0 else 0)")
                    if [ "$OVER" = "1" ] && [ ! -f "$REPO/.fleet-waste" ]; then
                        date '+%F %T' > "$REPO/.fleet-waste"
                        bd create --title="[ALARM] Waste: cost-per-close \$$CPC exceeds \$3" --description="24h burn \$$BURN / $CLOSES closures = \$$CPC/close (baseline ~\$1.20). Spend buying less than half its normal function. Check: stalls? failed merge sessions? store conflicts degrading bd? self-modification issues?" -t bug -p 1 --json >/dev/null 2>&1
                        echo "   ALARM: waste signature — \$$CPC/close"
                    elif [ "$OVER" = "0" ]; then
                        rm -f "$REPO/.fleet-waste"
                    fi
                fi
            fi
        fi
    fi
    python3 -c "import json,time; json.dump({'usage': $USED, 'ts': $NOW_S}, open('$SNAP','w'))"

    # BURN MARKER: $2000 milestone (on record, never pauses)
    if [ "$USED" -ge 2000 ] && [ ! -f "$REPO/.fleet-burn-2000" ]; then
        date '+%F %T' > "$REPO/.fleet-burn-2000"
        bd create --title="[info] Burn reached 2000 USD (milestone, ceiling removed)" --description="Total OpenRouter usage crossed the former watch line. Per Mark: budget raised to an undisclosed ceiling; function-per-dollar is the only metric. Marker on record." -t task -p 4 --json >/dev/null 2>&1
        echo "$(date '+%F %T') milestone: $2,000 total crossed"
    fi

    sleep $((CYCLE_MIN * 60))
done
