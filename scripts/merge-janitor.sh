#!/bin/bash
# Merge janitor: the dedicated resolver for "MANUAL MERGE NEEDED" leftovers.
# The sync loop's in-cycle kimi merge has a 15-min budget and resolves all
# conflicted files in one session (fails on big multi-file C conflicts). This
# janitor picks up exactly those branches: one conflicted FILE per kimi
# session, a 30-min per-file budget, escalating to a human bead after 3
# failed cycles on the same branch.
#
# Safe to run alongside sync-beads-loop.sh: both serialize through
# /tmp/lichen-beads-sync.lock; whichever holds it, the other skips.
# Usage: scripts/merge-janitor.sh [cycle_minutes] [max_failures]

set -u
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$HOME/Developer/lichen-workspace/project-LICHEN")
CYCLE_MIN="${1:-10}"
MAX_FAIL="${2:-3}"
MODEL="openrouter/moonshotai/kimi-k3"
STATE_DIR="/tmp/lichen-merge-janitor-state"
export PATH="$HOME/.opencode/bin:$PATH"
export BEADS_DIR="${BEADS_DIR:-$REPO_ROOT/.beads}"
mkdir -p "$STATE_DIR"

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

resolve_file() {
    # $1 = conflicted file path. One kimi session, one file.
    # No --agent: the resolver must be able to EDIT the file (the plan agent
    # is read-only); the prompt scopes it to this one file.
    local file="$1"
    timeout 1800 opencode run -m "$MODEL" "You are resolving ONE file's GIT MERGE CONFLICT in the LICHEN repo (branch main, merge in progress, merge --no-commit). The file is: $file. It contains conflict markers (<<<<<<< / ======= / >>>>>>>). Read the conflicted regions plus surrounding code and BOTH parents ('git show HEAD:$file' and 'git show MERGE_HEAD:$file'), understand each side's INTENT, and write the reconciled resolution into the file (both intents preserved when compatible; otherwise keep the correct one and say why in a comment). Do not touch any other file. Do not run cmake in-source: use a build/ subdirectory if you must compile. You are done when the file has no conflict markers and is syntactically plausible C/Rust. Finish with the single word RESOLVED on its own line." >/dev/null 2>&1
}

file_clean() {
    # No conflict markers left in the file.
    ! grep -q '^\(<<<<<<<\|>>>>>>>\)' "$1" 2>/dev/null
}

janitor_merge_branch() {
    # $1 = branch name. Returns 0 when the branch is fully merged.
    local branch="$1"
    if [ -f "$REPO_ROOT/.git/MERGE_HEAD" ]; then
        echo "   janitor: merge already in flight — skipping this cycle"
        return 2
    fi
    # Sweep debris from interrupted earlier merge cycles: locally modified
    # files that this branch's merge would rewrite anyway. Without this, a
    # killed kimi session leaves edited files that block every later merge
    # attempt with "local changes would be overwritten".
    local branch_changed debris
    branch_changed=$(git -C "$REPO_ROOT" diff --name-only main..."$branch" | sort)
    debris=$({ git -C "$REPO_ROOT" diff --name-only; git -C "$REPO_ROOT" diff --cached --name-only; } | sort -u | grep -xFf <(printf '%s\n' "$branch_changed") || true)
    if [ -n "$debris" ]; then
        echo "   janitor: restoring interrupted-merge debris: $(echo "$debris" | tr '\n' ' ')"
        git -C "$REPO_ROOT" checkout HEAD -- $debris
    fi
    if ! git -C "$REPO_ROOT" merge --no-ff --no-commit "$branch" >/dev/null 2>&1; then
        local files
        files=$(git -C "$REPO_ROOT" diff --name-only --diff-filter=U)
        if [ -z "$files" ]; then
            echo "   janitor: $branch merge failed without conflicts — aborting"
            git -C "$REPO_ROOT" merge --abort >/dev/null 2>&1
            return 2
        fi
        echo "   janitor: $branch conflicts in: $(echo "$files" | tr '\n' ' ')"

        local failed=0
        for f in $files; do
            echo "   janitor: resolving $f (one kimi session)"
            if resolve_file "$f" && file_clean "$REPO_ROOT/$f"; then
                git -C "$REPO_ROOT" add -- "$f"
            else
                echo "   janitor: FAILED to resolve $f"
                failed=1
                break
            fi
        done

        if [ "$failed" -eq 1 ]; then
            git -C "$REPO_ROOT" merge --abort >/dev/null 2>&1
            return 1
        fi
        if git -C "$REPO_ROOT" diff --check >/dev/null 2>&1 && git -C "$REPO_ROOT" commit --no-edit --quiet; then
            echo "   janitor: $branch merged via per-file kimi resolution"
            rm -f "$STATE_DIR/$branch.count"
            return 0
        fi
        git -C "$REPO_ROOT" merge --abort >/dev/null 2>&1
        return 1
    fi
    # Clean merge (rerere replayed everything): normalize .beads like the sync loop, commit.
    git -C "$REPO_ROOT" rm -rq --ignore-unmatch --cached .beads rust/crates/oscore >/dev/null 2>&1 || true
    git -C "$REPO_ROOT" checkout HEAD -- .beads 2>/dev/null || true
    if git -C "$REPO_ROOT" commit --no-edit --quiet; then
        echo "   janitor: $branch merged (rerere replay)"
        rm -f "$STATE_DIR/$branch.count"
    else
        git -C "$REPO_ROOT" merge --abort >/dev/null 2>&1
    fi
    return 0
}

escalate() {
    # $1 = branch. Called after MAX_FAIL consecutive failures.
    local branch="$1"
    local files
    files=$(git -C "$REPO_ROOT" ls-tree -r --name-only "main..$branch" 2>/dev/null | head -20 | tr '\n' ' ')
    bd create --title="Manual merge needed: $branch (janitor failed $MAX_FAIL cycles)" \
        --description="The merge janitor could not resolve $branch after $MAX_FAIL consecutive kimi sessions. Branch is $files. Human or implementer-agent resolution required; the sync loop keeps skipping it. Discovered-from: project-LICHEN-worker6-ba39" \
        -t task -p 1 --label fleet-implementable --json >/dev/null 2>&1
    echo "   janitor: escalated $branch to a bead after $MAX_FAIL failures"
}

echo "merge janitor: cycle ${CYCLE_MIN}m, model $MODEL, escalate after $MAX_FAIL failures — Ctrl+C to stop"

while :; do
    echo "── janitor $(date '+%F %T') ──"
    # Single-flight with the sync loop: skip if either lock is held.
    if ! mkdir /tmp/lichen-beads-sync.lock 2>/dev/null; then
        echo "   sync loop busy — skipping"
    else
        trap 'rmdir /tmp/lichen-beads-sync.lock 2>/dev/null' EXIT
        CREDITS=$(remaining_credits)
        LEFTOVERS=""
        for branch in $(git -C "$REPO_ROOT" for-each-ref --format='%(refname:short)' 'refs/heads/beads-worker-*'); do
            ahead=$(git -C "$REPO_ROOT" rev-list main.."$branch" --count 2>/dev/null || echo 0)
            [ "$ahead" -eq 0 ] && continue
            # Probe: does this branch still conflict with main?
            # (old-form merge-tree prefixes conflict markers with '+')
            if ! git -C "$REPO_ROOT" merge-tree "$(git -C "$REPO_ROOT" merge-base main "$branch")" main "$branch" 2>/dev/null | grep -q '<<<<<<<'; then
                continue
            fi
            LEFTOVERS="$LEFTOVERS $branch"
        done
        if [ -z "$LEFTOVERS" ]; then
            echo "   no conflicted leftovers"
        elif [ "$CREDITS" -lt 15 ]; then
            echo "   credits $CREDITS below 15 — pausing (auto-topup will replenish)"
        else
            for branch in $LEFTOVERS; do
                COUNT=$(cat "$STATE_DIR/$branch.count" 2>/dev/null || echo 0)
                if [ "$COUNT" -ge "$MAX_FAIL" ]; then
                    if [ ! -f "$STATE_DIR/$branch.escalated" ]; then
                        escalate "$branch"
                        touch "$STATE_DIR/$branch.escalated"
                    fi
                    continue
                fi
                echo "   janitor: attempting $branch (attempt $((COUNT + 1))/$MAX_FAIL)"
                if janitor_merge_branch "$branch"; then
                    :
                else
                    echo $((COUNT + 1)) > "$STATE_DIR/$branch.count"
                fi
            done
        fi
        trap - EXIT
        rmdir /tmp/lichen-beads-sync.lock 2>/dev/null
    fi
    sleep $((CYCLE_MIN * 60))
done
