#!/bin/bash
# Sync all beads worker worktrees: commit locally, merge code to main
# Usage: ./scripts/sync-beads-workers.sh
#
# Safe to run while workers are active (they work on separate branches)
#
# .beads is NEVER staged from worktrees: there it is a symlink to main's
# store, and committing it records a typechange that poisons every merge.
# Beads flat files are committed in the main repo at the end of this script.

set -e

# This script's checkpoint and merge commits are the only legitimate writers
# of .beads/ (the pre-commit hook blocks worker-side store staging, bead
# biod); opt this process out of the hook.
export BEADS_ALLOW_STORE_COMMIT=1

REPO_ROOT=$(git rev-parse --show-toplevel)
if [ -d /Volumes/Attic ]; then
    WORKTREE_BASE="${LICHEN_WORKTREE_BASE:-/Volumes/Attic/Desktop/Projects/lichen-workers}"
else
    WORKTREE_BASE="${LICHEN_WORKTREE_BASE:-$HOME/Developer/lichen-workers}"
fi

echo "=== Syncing Beads Workers ==="

# Reuse recorded conflict resolutions across syncs (common gitdir: shared by worktrees)
git config rerere.enabled true

# Commit in each worktree
for worktree in "$WORKTREE_BASE"/worker*/; do
    [ -d "$worktree" ] || continue
    name=$(basename "$worktree")

    cd "$worktree"

    # .beads excluded: symlink typechange must never be staged
    dirty=$(git status --porcelain -- ':!.beads' ':!.beads/**')
    if [ -z "$dirty" ]; then
        echo "$name: clean"
        continue
    fi

    untracked=$(git status --porcelain -- ':!.beads' ':!.beads/**' | grep -c '^??' || true)
    echo "$name: syncing (untracked leftovers: $untracked)"

    git add -u -- ':!.beads' ':!.beads/**'

    if [ -n "$(git diff --cached --name-only)" ]; then
        git commit -m "chore(beads): $name sync"
        echo "$name: committed"
    fi
done

# Back to main repo
cd "$REPO_ROOT"

# Merge worker branches to main. Beads flat files are authoritative in main
# only (bd writes the shared store via BEADS_DIR), so any .beads changes a
# worker branch carries (legacy symlink-era commits) are dropped at merge time.
echo ""
echo "=== Merging worker branches to main ==="

# LLM semantic merge (AgentSpawn-style, arXiv:2602.07072): reconcile both
# sides of a conflicted merge with an LLM, verified by the touched tests.
# Returns 0 only if every conflict is resolved AND the result compiles/tests.
llm_semantic_merge() {
    local branch="$1"
    local model="openrouter/moonshotai/kimi-k3"
    local files
    files=$(git diff --name-only --diff-filter=U | tr '\n' ' ')
    if [ -z "$files" ]; then
        return 1
    fi

    # State pin (bead project-LICHEN-worker6-d42k): the session runs with
    # shell/git access mid-merge. If it commits, switches branch, restarts the
    # merge on a different parent, aborts it, or stages foreign content, every
    # gate below is bypassed and the caller's 'git merge --abort' no-ops while
    # main advances ungated (or commits land on the wrong branch). Snapshot
    # HEAD + ref + merge parent + staged set; rewind any mutation before
    # gating. Rewind restores main's checkout only — a session-created branch
    # with commits survives as debris (the loop only consumes beads-worker-*).
    # Residuals by design (tracked in follow-up beads): session writes to
    # worker-branch refs, hooks/config, .beads content, push to remote,
    # staged CONTENT mutation of in-merge paths (name-set granularity only —
    # hashing staged entries breaks the happy path, which must re-stage its
    # resolutions), unstaged worktree vandalism of tracked files on the
    # success path, and untracked-file wedges against later loop merges.
    local head_before ref_before merge_head_before staged_before files_nl
    local ref_after head_after merge_head_after staged_after why
    head_before=$(git rev-parse HEAD)
    ref_before=$(git symbolic-ref HEAD 2>/dev/null || echo DETACHED)
    merge_head_before=$(git rev-parse MERGE_HEAD 2>/dev/null || echo NONE)
    # The conflicted paths ($files) are excluded from the staged-set pin: the
    # session MUST re-stage them to resolve, and an accept-ours resolution
    # (staged blob == HEAD blob) legitimately drops the path from the
    # name-only diff — comparing with them included wedges that valid
    # resolution as a false "mutation" every sync. --no-renames keeps the
    # name set stable against rename pairing.
    files_nl=$(printf '%s\n' $files)
    staged_before=$(git diff --cached --name-only --no-renames | grep -vxF "$files_nl" | sort)

    echo "  LLM merge session ($model) on: $files"
    # 15-minute cap so a hung session cannot wedge the sync loop.
    timeout 900 opencode run --model "$model" "You are resolving a GIT MERGE CONFLICT between the current branch (main, HEAD) and incoming branch $branch in the LICHEN repo. The conflicted files are: $files. For each conflict: read both sides plus surrounding code, understand each side's INTENT, and write the reconciled resolution (both intents preserved when compatible; otherwise pick the correct one and say why in a comment). Then run the touched crates'/packages' quick tests (cargo check / pytest for touched paths). You are done when: git diff --check passes, no conflict markers remain in any file, and the touched code compiles/tests clean. Do not resolve by deleting a side wholesale; do not touch .beads/ or spec text. Finish with the single word RESOLVED on its own line." >> /tmp/lichen-kimi-last.log 2>&1; rc=$?; echo "$(date +%FT%T) kimi budget=900s exit=$rc (124=timeout)" >> /tmp/lichen-kimi-last.log

    ref_after=$(git symbolic-ref HEAD 2>/dev/null || echo DETACHED)
    head_after=$(git rev-parse HEAD)
    merge_head_after=$(git rev-parse MERGE_HEAD 2>/dev/null || echo NONE)
    staged_after=$(git diff --cached --name-only --no-renames | grep -vxF "$files_nl" | sort)
    why=""
    [ "$ref_after" != "$ref_before" ] && why="$why ref"
    [ "$head_after" != "$head_before" ] && why="$why HEAD"
    [ "$merge_head_after" != "$merge_head_before" ] && why="$why MERGE_HEAD"
    [ "$staged_after" != "$staged_before" ] && why="$why staged-set"
    if [ -n "$why" ]; then
        echo "  LLM session mutated git state mid-merge (${why# }) — rewinding"
        echo "$(date +%FT%T) mutation:$why | ref $ref_before->$ref_after HEAD $head_before->$head_after MERGE_HEAD $merge_head_before->$merge_head_after" >> /tmp/lichen-kimi-last.log
        # .beads worktree changes from the session window are discarded with
        # the rewind — same policy as the caller's failure-path
        # 'git checkout -- .beads': session vandalism and live-worker writes
        # are indistinguishable in the window, and this path is PROVABLY
        # session-hostile (mutation detected). The per-branch checkpoint
        # bounds collateral to writes landed during this branch's session.
        # set -e is suppressed in this function's call context (if-condition),
        # so every rewind step MUST be status-checked: a silent failure leaves
        # ungated state on main and the loop would keep merging on top of it.
        if [ "$ref_before" = DETACHED ]; then
            # Ambiguous ref state (session may have attached+advanced some
            # branch): fail-stop rather than risk moving the wrong ref.
            echo "  FATAL: mutation from a detached HEAD start — manual repair required" | tee -a /tmp/lichen-kimi-last.log
            exit 2
        fi
        if ! git symbolic-ref HEAD "$ref_before" 2>>/tmp/lichen-kimi-last.log; then
            echo "  FATAL: could not repoint HEAD to $ref_before — manual repair required" | tee -a /tmp/lichen-kimi-last.log
            exit 2
        fi
        if git reset --hard "$head_before" >> /tmp/lichen-kimi-last.log 2>&1; then
            echo "$(date +%FT%T) kimi mutated git state (exit=$rc); rewound to $head_before on $ref_before" >> /tmp/lichen-kimi-last.log
        else
            echo "  FATAL: rewind failed; main may hold ungated state ($(git rev-parse HEAD)) — manual repair required" | tee -a /tmp/lichen-kimi-last.log
            exit 2
        fi
        return 1
    fi
    return $rc

    # stage whatever the LLM resolved; fail if anything is still conflicted
    git add -- $files
    if git diff --name-only --diff-filter=U | grep -q .; then
        return 1
    fi
    return 0
}

conflicted=()

# Checkpoint pending bd writes (closes, comments, new beads) BEFORE any
# merge: the merge normalization below runs `git checkout HEAD -- .beads`,
# which would silently discard store writes still uncommitted in this
# working tree (beads-worker-4 lost whole batches of verified closes this
# way, bead project-LICHEN-worker6-bd8h). Committing first makes them
# durable; the merge's .beads normalization then keeps main's committed
# state, which now includes those closes.
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    git commit -m "chore(beads): checkpoint store writes before merge" --quiet &&
        echo "checkpointed pending bd writes before merge"
fi

for branch in $(git for-each-ref --format='%(refname:short)' 'refs/heads/beads-worker-*'); do
    ahead=$(git rev-list main.."$branch" --count 2>/dev/null || echo 0)
    if [ "$ahead" -eq 0 ]; then
        continue
    fi

    # Per-branch checkpoint: closes written after the pre-loop checkpoint
    # (e.g. during the previous branch's kimi session) must be committed
    # BEFORE this branch's normalization rewinds .beads to HEAD, or they
    # are destroyed (bead biod — the measured loss mechanism).
    if [ -n "$(git status --porcelain .beads/)" ]; then
        git add .beads/
        git commit -m "chore(beads): per-branch store checkpoint" --quiet ||
            true
    fi

    echo "Merging $branch ($ahead commits ahead)..."

    if git merge --no-commit --no-ff "$branch" >/dev/null 2>&1; then
        # Normalize: beads store lives in main only; discard branch-side .beads entries.
        # rust/crates/oscore was vendored-then-removed (registry dep 0.1.2): worker
        # branches from before the deletion re-add stale copies — drop them too.
        git rm -rq --ignore-unmatch --cached .beads rust/crates/oscore >/dev/null 2>&1 || true
        git checkout HEAD -- .beads 2>/dev/null || true
        git rm -rq --ignore-unmatch .beads rust/crates/oscore >/dev/null 2>&1 || true
        git checkout HEAD -- .beads 2>/dev/null || true
        if git commit --no-edit --quiet; then
            echo "  merged (code only)"
        else
            echo "  nothing to commit after normalization"
            git merge --abort 2>/dev/null || true
        fi
    else
        # Single-file conflicts: in-loop kimi resolves immediately (measured
        # 100% success on single files). Multi-file conflicts go straight to
        # the janitor — the in-loop session fails ~80% there (75 dead sessions
        # measured), pure wasted spend.
        CONFLICT_N=$(git diff --name-only --diff-filter=U | wc -l)
        if [ "$CONFLICT_N" -le 1 ] && llm_semantic_merge "$branch"; then
            if git diff --name-only --diff-filter=U | grep -q .; then
                echo "  semantic merge left unresolved files — aborting"
                git merge --abort 2>/dev/null || true
                git checkout -- .beads 2>/dev/null || true
                conflicted+=("$branch")
            elif git commit --no-edit --quiet; then
                echo "  merged via LLM semantic reconciliation"
            else
                echo "  semantic merge produced no commit — aborting"
                git merge --abort 2>/dev/null || true
                conflicted+=("$branch")
            fi
        else
            echo "  CONFLICT — LLM merge failed, branch kept for manual resolution"
            git merge --abort 2>/dev/null || true
            git checkout -- .beads 2>/dev/null || true
            conflicted+=("$branch")
        fi
    fi
done

# Commit beads flat-file updates in main (workers wrote them via symlink).
# This checkpoint is REQUIRED even though one ran before the merge loop:
# workers (and this script's own merge handling) write to the store working
# tree continuously; any close written after the pre-loop checkpoint would
# otherwise be discarded by the LAST merge's normalization if the final
# commit here did not exist. Commit immediately after the loop, and again
# right before exit, so the window for losing a write is one script step.
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    git commit -m "chore(beads): sync from workers"
    echo "Main: committed beads sync"
fi

# Final checkpoint: capture anything written during merge handling above
# (conflict-path checkouts, worker writes racing the loop) so the next run's
# normalization cannot rewind a close that has already been reported to a
# worker (bead project-LICHEN-worker6-bd8h, recurring revert pattern).
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    git commit -m "chore(beads): checkpoint store writes after merge loop" --quiet &&
        echo "checkpointed post-merge store writes"
fi

if [ ${#conflicted[@]} -gt 0 ]; then
    echo ""
    echo "=== MANUAL MERGE NEEDED ==="
    printf '  %s\n' "${conflicted[@]}"
    echo "After resolving each: git merge <branch> again (rerere replays known resolutions)."
    exit 1
fi

echo ""
echo "=== Sync complete ==="
git status --short | head -10
