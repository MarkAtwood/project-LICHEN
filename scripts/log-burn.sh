#!/bin/bash
# Append OpenRouter credit burn to ~/Developer/burn.log (one line per call).
# Called hourly by sync-beads-loop.sh; safe to run standalone.

set -e

KEY=$(python3 - <<'PYEOF'
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

if [ -z "$KEY" ]; then
    echo "$(date -Is) burn-log: no openrouter key found" >> "$HOME/Developer/burn.log"
    exit 1
fi

DATA=$(curl -s --max-time 30 https://openrouter.ai/api/v1/credits -H "Authorization: Bearer $KEY") || \
    { echo "$(date -Is) burn-log: curl failed" >> "$HOME/Developer/burn.log"; exit 1; }

python3 - "$DATA" <<'PYEOF'
import json, sys, os, datetime
d = json.loads(sys.argv[1]).get("data", {})
tc, tu = float(d.get("total_credits", 0)), float(d.get("total_usage", 0))
rem = tc - tu
line = f"{datetime.now().isoformat(timespec='seconds')} credits={tc:.2f} used={tu:.2f} remaining={rem:.2f}"
if rem < 10:
    line += "  WARNING: below $10 — fleet will die when credits run out"
with open(os.path.expanduser("~/Developer/burn.log"), "a") as f:
    f.write(line + "\n")
print(line)
PYEOF
