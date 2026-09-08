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
# biod). Each commit below opts itself out per-command. The opt-out must NOT
# be exported process-wide: it would reach the opencode/kimi subprocess and
# disable the guard for the one actor consuming untrusted branch content.

REPO_ROOT=$(git rev-parse --show-toplevel)
GIT_DIR=$(git rev-parse --absolute-git-dir)
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
        BEADS_ALLOW_STORE_COMMIT=1 git commit -m "chore(beads): $name sync"
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

    echo "  LLM merge session ($model) on: $files"
    # 15-minute cap so a hung session cannot wedge the sync loop.
    timeout 900 opencode run --model "$model" "You are resolving a GIT MERGE CONFLICT between the current branch (main, HEAD) and incoming branch $branch in the LICHEN repo. The conflicted files are: $files. For each conflict: read both sides plus surrounding code, understand each side's INTENT, and write the reconciled resolution (both intents preserved when compatible; otherwise pick the correct one and say why in a comment). Then run the touched crates'/packages' quick tests (cargo check / pytest for touched paths). You are done when: git diff --check passes, no conflict markers remain in any file, and the touched code compiles/tests clean. Do not resolve by deleting a side wholesale; do not touch .beads/ or spec text. Finish with the single word RESOLVED on its own line." >> /tmp/lichen-kimi-last.log 2>&1; rc=$?; echo "$(date +%FT%T) kimi budget=900s exit=$rc (124=timeout)" >> /tmp/lichen-kimi-last.log
    if [ "$rc" -ne 0 ]; then
        return "$rc"
    fi

    # stage whatever the LLM resolved; fail if anything is still conflicted
    git add -- $files
    if git diff --name-only --diff-filter=U | grep -q .; then
        return 1
    fi
    return 0
}

conflicted=()

# True when the in-flight merge put store entries in the INDEX (staged
# M/A/D/R or unmerged U under .beads) — legacy worker branches carried .beads
# commits; modern ones never do. Worktree-only changes (concurrent bd writes
# landing during the merge) have a space in the index column and never match.
merge_staged_store_entries() {
    git status --porcelain -- .beads | grep -qE '^[MADRU]'
}

# Snapshot the store worktree (committed + uncommitted) into .git before any
# operation that can rewind it (merge abort, normalization checkout). A no-op
# when the store is clean. Snapshots are never deleted automatically; recover
# with: tar -xf <file> -C <repo-root>. Without this, concurrent bd writes made
# during an up-to-900s kimi session are destroyed by the rewind (bead bd8h,
# 0i1p loss window).
snapshot_store() {
    git status --porcelain .beads/ | grep -q . || return 0
    local dir="$GIT_DIR/store-snapshots"
    mkdir -p "$dir"
    local f
    f="$dir/$(date +%Y%m%dT%H%M%S)-$1.tar"
    tar -C "$REPO_ROOT" -cf "$f" .beads 2>/dev/null || return 0
    echo "  store snapshot (concurrent bd writes preserved): $f"
}

# Checkpoint pending bd writes (closes, comments, new beads) BEFORE any
# merge: the merge normalization below runs `git checkout HEAD -- .beads`,
# which would silently discard store writes still uncommitted in this
# working tree (beads-worker-4 lost whole batches of verified closes this
# way, bead project-LICHEN-worker6-bd8h). Committing first makes them
# durable; the merge's .beads normalization then keeps main's committed
# state, which now includes those closes.
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    BEADS_ALLOW_STORE_COMMIT=1 git commit -m "chore(beads): checkpoint store writes before merge" --quiet &&
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
        BEADS_ALLOW_STORE_COMMIT=1 git commit -m "chore(beads): per-branch store checkpoint" --quiet ||
            true
    fi

    echo "Merging $branch ($ahead commits ahead)..."

    if git merge --no-commit --no-ff "$branch" >/dev/null 2>&1; then
        # Normalize: beads store lives in main only; discard branch-side .beads entries.
        # rust/crates/oscore was vendored-then-removed (registry dep 0.1.2): worker
        # branches from before the deletion re-add stale copies — drop them too.
        # Only when the merge actually staged store entries: a blind rewind here
        # destroys concurrent bd writes made during the merge (0i1p).
        snapshot_store "$branch-clean"
        if merge_staged_store_entries; then
            git rm -rq --ignore-unmatch --cached .beads rust/crates/oscore >/dev/null 2>&1 || true
            git checkout HEAD -- .beads 2>/dev/null || true
            git rm -rq --ignore-unmatch .beads rust/crates/oscore >/dev/null 2>&1 || true
            git checkout HEAD -- .beads 2>/dev/null || true
            # Merge-ADDED store/vendor files: the pair above unstages them but
            # leaves them as untracked worktree files (git rm skips untracked,
            # checkout HEAD only restores HEAD paths), and the final checkpoint
            # below would re-commit them. Delete only paths that exist on the
            # merged branch — concurrent bd writes are never branch-side.
            git ls-tree -r --name-only "$branch" -- .beads rust/crates/oscore 2>/dev/null |
                while IFS= read -r f; do
                    if [ -f "$f" ] && ! git ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
                        rm -f "$f"
                    fi
                done
        fi
        if BEADS_ALLOW_STORE_COMMIT=1 git commit --no-edit --quiet; then
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
            store_staged=0; merge_staged_store_entries && store_staged=1
            if git diff --name-only --diff-filter=U | grep -q .; then
                echo "  semantic merge left unresolved files — aborting"
                snapshot_store "$branch-unresolved"
                git merge --abort 2>/dev/null || true
                if [ "$store_staged" = 1 ]; then
                    git checkout HEAD -- .beads 2>/dev/null || true
                fi
                conflicted+=("$branch")
            elif BEADS_ALLOW_STORE_COMMIT=1 git commit --no-edit --quiet; then
                echo "  merged via LLM semantic reconciliation"
            else
                echo "  semantic merge produced no commit — aborting"
                snapshot_store "$branch-nocommit"
                git merge --abort 2>/dev/null || true
                conflicted+=("$branch")
            fi
        else
            echo "  CONFLICT — LLM merge failed, branch kept for manual resolution"
            store_staged=0; merge_staged_store_entries && store_staged=1
            snapshot_store "$branch-conflict"
            git merge --abort 2>/dev/null || true
            if [ "$store_staged" = 1 ]; then
                git checkout HEAD -- .beads 2>/dev/null || true
            fi
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
    BEADS_ALLOW_STORE_COMMIT=1 git commit -m "chore(beads): sync from workers"
    echo "Main: committed beads sync"
fi

# Final checkpoint: capture anything written during merge handling above
# (conflict-path checkouts, worker writes racing the loop) so the next run's
# normalization cannot rewind a close that has already been reported to a
# worker (bead project-LICHEN-worker6-bd8h, recurring revert pattern).
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    BEADS_ALLOW_STORE_COMMIT=1 git commit -m "chore(beads): checkpoint store writes after merge loop" --quiet &&
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
