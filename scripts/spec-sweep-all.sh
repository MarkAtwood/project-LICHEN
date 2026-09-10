#!/bin/bash
# Wave runner: sweeps remaining spec sections sequentially, then runs the Opus
# verification pass on each section's flagged set. Credit-gated: stops below
# the floor and exits 3 (rerun to resume — completed sections are skipped).
# Usage: scripts/spec-sweep-all.sh [credit_floor]
set -u
REPO_ROOT=$(git rev-parse --show-toplevel)
FLOOR="${1:-15}"
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

# Full corpus (2026-09-09 expansion): every normative spec file, including
# sections never swept (05-routing, 03-addressing, 02a-tdma, 02b, 19) and the
# appendix tail. Already-swept sections whose spec moved after their matrix
# are refreshed by deleting the stale matrix first (the skip logic then
# re-sweeps them). Unmatched names (kiss-framing, THINKING-APPLICATION,
# README, 99-acknowledgments, draft-yggdrasil-subnet-announcement) are
# intentionally excluded pending human confirmation they are normative.
SECTIONS="spec/09-packets-timing.md spec/02a-coordinated-capacity.md spec/03-adaptation.md spec/06-security.md spec/02-physical-link.md spec/08-gateway-coordination.md spec/12-apps.md spec/04-network.md spec/11-lci.md spec/08-nodes.md spec/10-implementation.md spec/01-architecture.md spec/07-transport-app.md spec/appendix-border-router.md spec/appendix-bufferbloat.md spec/appendix-c-safety.md spec/drafts/draft-lichen-schnorr-00.md spec/05-routing.md spec/03-addressing.md spec/02a-tdma.md spec/02b-ccp-receiver-aware.md spec/19-device-ux.md spec/appendix-ccp12-hopping.md spec/appendix-schc.md spec/appendix-senml.md spec/appendix-rpl.md spec/appendix-loadng.md spec/appendix-gatt-ipso.md spec/appendix-x509-cert-profile.md spec/appendix-design-rationale.md spec/appendix-misc.md"

# Refresh stale matrices: if the spec file is newer than its matrix, the
# matrix is out of date — remove it so the sweep re-runs that section.
for SECTION in $SECTIONS; do
    SECNAME=$(basename "$SECTION" .md)
    MATRIX="$REPO_ROOT/docs/spec-coverage/$SECNAME.md"
    if [ -f "$MATRIX" ] && [ "$REPO_ROOT/$SECTION" -nt "$MATRIX" ]; then
        echo "refresh: $SECNAME (spec moved after sweep) — removing stale matrix"
        rm -f "$MATRIX" "$REPO_ROOT/docs/spec-coverage/$SECNAME-flagged.md"
    fi
done

for SECTION in $SECTIONS; do
    SECNAME=$(basename "$SECTION" .md)
    MATRIX="$REPO_ROOT/docs/spec-coverage/$SECNAME.md"
    FLAGGED="$REPO_ROOT/docs/spec-coverage/$SECNAME-flagged.md"
    VERIFY_LOG="$REPO_ROOT/docs/spec-coverage/$SECNAME-verify.log"

    # Already-swept section: still run the Opus verify pass if it was swept but
    # never verified (flagged set present, verify log empty/missing). Closes the
    # resume gap where a prior run reached the matrix before the verify block.
    if [ -f "$MATRIX" ]; then
        if [ -f "$FLAGGED" ] && [ ! -s "$VERIFY_LOG" ]; then
            echo "── Opus verification (previously swept, unverified): $SECNAME ──"
            opencode run --model "$OPUS_MODEL" "$(cat "$REPO_ROOT/scripts/opus-verify-prompt.md")

SPEC SECTION: $REPO_ROOT/$SECTION
FLAGGED SET: $(cat "$FLAGGED")" 2>&1 | tee -a "$VERIFY_LOG" | tail -2
        else
            echo "skip $SECNAME (already swept)"
        fi
        continue
    fi

    # No credit gating: auto-topup keeps the balance healthy, and killing a
    # mid-extraction session wastes its paid work and forces a full-price
    # rerun (the 2026-08-31 five-section failure). Burn is logged, not gated.

    echo "── sweeping $SECTION ──"
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
