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

REPO_ROOT=$(git rev-parse --show-toplevel)
WORKTREE_BASE="/Volumes/Attic/Desktop/Projects/lichen-workers"

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

conflicted=()
for branch in $(git for-each-ref --format='%(refname:short)' 'refs/heads/beads-worker-*'); do
    ahead=$(git rev-list main.."$branch" --count 2>/dev/null || echo 0)
    if [ "$ahead" -eq 0 ]; then
        continue
    fi

    echo "Merging $branch ($ahead commits ahead)..."

    if git merge --no-commit --no-ff "$branch" >/dev/null 2>&1; then
        # Normalize: beads store lives in main only; discard branch-side .beads entries
        if git diff --cached --name-only -- .beads | grep -q .; then
            git checkout HEAD -- .beads 2>/dev/null || git rm -r --cached --ignore-unmatch .beads >/dev/null 2>&1
            git checkout HEAD -- .beads 2>/dev/null || true
        fi
        if git commit --no-edit --quiet; then
            echo "  merged (code only)"
        else
            echo "  nothing to commit after normalization"
            git merge --abort 2>/dev/null || true
        fi
    else
        # Retry surgically: apply everything except .beads as a plain commit
        if git diff --name-only main..."$branch" -- ':!.beads' ':!.beads/**' | grep -q . \
           && git diff main..."$branch" -- ':!.beads' ':!.beads/**' | git apply --index 2>/dev/null; then
            git commit --no-edit -q -m "chore: merge $branch (code only, .beads excluded)"
            echo "  merged surgically (conflicts were .beads-only or patch-applied)"
        else
            echo "  CONFLICT — merge aborted, branch kept for manual resolution"
            git merge --abort 2>/dev/null || true
            git checkout -- .beads 2>/dev/null || true
            conflicted+=("$branch")
        fi
    fi
done

# Commit beads flat-file updates in main (workers wrote them via symlink)
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    git commit -m "chore(beads): sync from workers"
    echo "Main: committed beads sync"
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
