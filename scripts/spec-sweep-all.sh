#!/bin/bash
# Wave runner: sweeps remaining spec sections sequentially, then runs the Opus
# verification pass on each section's flagged set. Credit-gated: stops below
# the floor and exits 3 (rerun to resume — completed sections are skipped).
# Usage: scripts/spec-sweep-all.sh [credit_floor]
set -u
REPO_ROOT=$(git rev-parse --show-toplevel)
FLOOR="${1:-150}"
OPUS_MODEL="openrouter/anthropic/claude-opus-4.5"
FLASH_MODEL="${LICHEN_SWEEP_MODEL:-openrouter/z-ai/glm-5.3-flash}"
export OPENCODE_CONFIG_CONTENT='{"permission":{"edit":"allow","webfetch":"allow","bash":{"*":"allow","rm -rf *":"deny","sudo *":"deny","git push*":"deny"}}}'
export PATH="$HOME/.opencode/bin:$PATH"
export BEADS_DIR="${BEADS_DIR:-$REPO_ROOT/.beads}"
mkdir -p "$REPO_ROOT/docs/spec-coverage"

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

SECTIONS="spec/09-packets-timing.md spec/02a-coordinated-capacity.md spec/03-adaptation.md spec/06-security.md spec/02-physical-link.md spec/08-gateway-coordination.md spec/12-apps.md spec/04-network.md spec/11-lci.md spec/08-nodes.md spec/10-implementation.md spec/01-architecture.md spec/07-transport-app.md spec/appendix-border-router.md spec/appendix-bufferbloat.md spec/appendix-c-safety.md spec/drafts/draft-lichen-schnorr-00.md"

for SECTION in $SECTIONS; do
    SECNAME=$(basename "$SECTION" .md)
    MATRIX="$REPO_ROOT/docs/spec-coverage/$SECNAME.md"
    FLAGGED="$REPO_ROOT/docs/spec-coverage/$SECNAME-flagged.md"
    [ -f "$MATRIX" ] && { echo "skip $SECNAME (already swept)"; continue; }

    CREDITS=$(remaining_credits)
    if [ "$CREDITS" -lt "$FLOOR" ]; then
        echo "credit floor hit ($CREDITS < $FLOOR) — pausing sweep. Rerun to resume."
        exit 3
    fi

    echo "── sweeping $SECTION (credits: $CREDITS) ──"
    bash "$REPO_ROOT/scripts/spec-sweep.sh" "$SECTION" "$FLASH_MODEL" || { echo "sweep $SECNAME failed"; continue; }
    [ -f "$MATRIX" ] || { echo "no matrix produced for $SECNAME"; continue; }

    if [ -f "$FLAGGED" ]; then
        echo "── Opus verification: $SECNAME ──"
        opencode run --model "$OPUS_MODEL" "$(cat "$REPO_ROOT/scripts/opus-verify-prompt.md")

SPEC SECTION: $REPO_ROOT/$SECTION
FLAGGED SET: $(cat "$FLAGGED")" 2>&1 | tee -a "$REPO_ROOT/docs/spec-coverage/$SECNAME-verify.log" | tail -2
    fi
    git -C "$REPO_ROOT" add docs/spec-coverage/ && git -C "$REPO_ROOT" commit -qm "docs(spec): coverage sweep $SECNAME" || true
done
echo "=== sweep complete: all sections covered ==="
