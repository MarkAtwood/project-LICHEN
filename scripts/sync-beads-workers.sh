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

# Restore the pre-session rr-cache snapshot unconditionally. Called after the
# LLM session on every path: the session may record an ungated postimage (via
# its own commit, a direct file write, or a legit bare 'git rerere'), and the
# next sync's clean-merge path replays rr-cache past every gate. Restoring on
# every path — not just on detected tamper — both neutralizes poisoning and
# avoids a false positive from a compliant session's 'git rerere' (which
# writes rr-cache without moving HEAD). Reads rr_had/rr_snap_b64 from the
# enclosing function (bash dynamic scoping).
rr_restore() {
    rm -rf "$GIT_DIR/rr-cache"
    if [ "$rr_had" = 1 ] && [ -n "$rr_snap_b64" ]; then
        printf '%s' "$rr_snap_b64" | base64 -d | tar -C "$GIT_DIR" -xf -
    fi
}

# LLM semantic merge (AgentSpawn-style, arXiv:2602.07072): reconcile both
# sides of a conflicted merge with an LLM. Returns 0 only when the session
# reported RESOLVED, no conflict markers remain in the content being
# committed, and the staged set stayed bounded to the merge's own changes
# plus the session's worktree edits. Every gate runs BEFORE the caller's
# commit: a commit is also the point where rerere records the resolution,
# so a rejected reconciliation is never replayed into later syncs.
llm_semantic_merge() {
    local branch="$1"
    local model="openrouter/moonshotai/kimi-k3"
    local files
    # Store paths are never handed to the session: the prompt forbids touching
    # .beads/, so a .beads conflict there is self-contradictory, and the LLM
    # must not stage store content for the success-path commit. A conflict
    # that is ONLY under .beads/ leaves $files empty -> manual resolution.
    files=$(git diff --name-only --diff-filter=U | grep -v '^\.beads/' | tr '\n' ' ')
    if [ -z "$files" ]; then
        return 1
    fi

    # Staged-set bound: the session runs with shell/git access and consumes
    # branch-controlled content (prompt-injection channel), so anything it
    # stages on its own must not reach the merge commit. Everything staged
    # right now is merge-auto-staged; together with the conflict files that
    # form the complete allowed set. Snapshot it before the session can touch
    # the index. Also snapshot the unstaged tracked set: the pickup below may
    # only take files the session NEWLY dirtied, not whatever main's worktree
    # already had dirty.
    local expected unstaged_before
    expected=$( { git diff --cached --name-only; printf '%s\n' $files; } | sort -u )
    unstaged_before=$(git diff --name-only | grep -v '^\.beads/' | sort -u)

    # Repo-state pin (bead d42k + review findings): the session has shell/git
    # access; if it runs 'git commit' itself the merge completes UNGATED
    # (MERGE_HEAD consumed, rerere records the resolution), the missing-gate
    # below then fails on the emptied index, and the caller's
    # 'git merge --abort' silently no-ops — main advanced while the branch is
    # reported manual-resolution. Pin commit id AND symbolic ref (a session
    # branch-switch keeps the id but strands the caller's commit on the wrong
    # branch) AND the replace-ref list (a session replace ref would rewrite
    # the pin check and the rewind target itself). rr-cache is integrity-
    # checked too: the merge already wrote its preimage, so a session can
    # record an ungated postimage — via its own commit or a direct file
    # write — that the next sync's clean-merge path replays past every gate.
    # Manifest and content snapshot live in shell variables, NOT /tmp files:
    # /tmp is same-UID-writable by the session, parent-shell memory is not.
    # Accepted residuals beyond this pin (hooks/config persistence, push-to-
    # remote, worker-branch ref moves, kill-parent, background delayed movers,
    # .git identity swap, no flock): bead project-LICHEN-worker6-nm0h — they
    # need a sandboxing design decision, not more pin lines.
    local head_before symref_before replace_before rr_had=0 rr_snap_b64=""
    head_before=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse HEAD)
    symref_before=$(git symbolic-ref -q HEAD 2>/dev/null || true)
    replace_before=$(git replace -l 2>/dev/null | sort)
    if [ -d "$GIT_DIR/rr-cache" ]; then
        rr_had=1
        rr_snap_b64=$(tar -C "$GIT_DIR" -cf - rr-cache 2>/dev/null | base64)
    fi
    # Detached HEAD at entry: the rewind would move whatever ref the session
    # left current; refuse fail-closed (the caller aborts the merge).
    if [ -z "$symref_before" ]; then
        echo "  detached HEAD at entry — refusing LLM merge"
        return 1
    fi

    echo "  LLM merge session ($model) on: $files"
    # 15-minute cap so a hung session cannot wedge the sync loop.
    local log=/tmp/lichen-kimi-last.log
    local session_log rc
    # Session output goes to a private file: the sentinel check must not be
    # satisfiable by a bare RESOLVED appended to the shared last.log by a
    # concurrent janitor session or a sibling worker's copy of this script.
    session_log=$(mktemp) || { echo "  mktemp failed — aborting merge"; return 1; }
    timeout 900 opencode run --model "$model" "You are resolving a GIT MERGE CONFLICT between the current branch (main, HEAD) and incoming branch $branch in the LICHEN repo. The conflicted files are: $files. For each conflict: read both sides plus surrounding code, understand each side's INTENT, and write the reconciled resolution (both intents preserved when compatible; otherwise pick the correct one and say why in a comment). Then run the touched crates'/packages' quick tests (cargo check / pytest for touched paths). You are done when: git diff --check passes, no conflict markers remain in any file, and the touched code compiles/tests clean. Do not resolve by deleting a side wholesale; do not touch .beads/ or spec text. Finish with the single word RESOLVED on its own line." > "$session_log" 2>&1; rc=$?
    cat "$session_log" >> "$log" 2>/dev/null || true
    echo "$(date +%FT%T) kimi budget=900s exit=$rc (124=timeout)" >> "$log"

    # Purge session-created replace refs on EVERY path: they rewrite object
    # reads repo-wide (including the caller's commit and future syncs).
    local replace_now replace_new
    replace_now=$(git replace -l 2>/dev/null | sort)
    replace_new=$(comm -13 <(printf '%s\n' "$replace_before") <(printf '%s\n' "$replace_now"))
    if [ -n "$replace_new" ]; then
        echo "  removing session-created replace refs: $(echo $replace_new | tr '\n' ' ')"
        printf '%s\n' "$replace_new" | while IFS= read -r r; do
            git replace -d "$r" >/dev/null 2>&1 || true
        done
    fi

    # Tamper check FIRST: a session that committed (or switched branches) and
    # then hung/failed would otherwise escape via the rc early-return below.
    # GIT_NO_REPLACE_OBJECTS on every pin read: the purge above already ran,
    # but never let replacement rewrite the rewind target.
    local head_now symref_now
    head_now=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse HEAD)
    symref_now=$(git symbolic-ref -q HEAD 2>/dev/null || true)
    if [ "$head_now" != "$head_before" ] ||
       [ "$symref_now" != "$symref_before" ]; then
        local sym_now_disp=${symref_now:-detached}
        echo "  LLM session tampered with repo state (HEAD ${head_before:0:7}@${symref_before##*/} -> ${head_now:0:7}@${sym_now_disp##*/}) — rewinding"
        snapshot_store "$branch-tamper"
        # Restore the checked-out branch BEFORE the reset so main — not
        # whatever ref the session left current — is what gets rewound.
        if [ "$symref_now" != "$symref_before" ]; then
            git symbolic-ref HEAD "$symref_before"
        fi
        GIT_NO_REPLACE_OBJECTS=1 git reset --hard "$head_before" >/dev/null
        rr_restore
        # Fail-stop if the rewind itself failed: continuing the merge loop on
        # unverified repo state risks exactly the ungated landing this guards.
        # Clear stale MERGE_HEAD/MSG/MODE first: exiting with a merge still
        # in flight lets the NEXT run's pre-loop .beads checkpoint complete a
        # phantom merge and silently strand the branch (review finding).
        if [ "$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse HEAD 2>/dev/null)" != "$head_before" ] ||
           [ "$(git symbolic-ref -q HEAD 2>/dev/null || true)" != "$symref_before" ]; then
            echo "  FATAL: rewind verification failed — stopping sync"
            rm -f "$GIT_DIR/MERGE_HEAD" "$GIT_DIR/MERGE_MSG" "$GIT_DIR/MERGE_MODE"
            rm -f "$session_log"
            exit 1
        fi
        rm -f "$session_log"
        return 1
    fi

    # Restore the pre-session rr-cache on every non-tamper path: a compliant
    # session's bare 'git rerere' (or a malicious direct postimage write)
    # changes rr-cache without moving HEAD, so it never trips the tamper
    # check — but it must still be discarded before the gates/commit.
    rr_restore
    if [ "$rc" -ne 0 ]; then
        rm -f "$session_log"
        return "$rc"
    fi

    # Success sentinel: the prompt demands RESOLVED on its own line, but exit
    # 0 alone is emitted for any finished session — a session that never
    # resolved must be treated as a failure, not a success.
    if ! grep -qx 'RESOLVED' "$session_log"; then
        rm -f "$session_log"
        echo "  LLM session did not report RESOLVED — treating as failure"
        return 1
    fi
    rm -f "$session_log"

    # MERGE_HEAD must still name exactly the branch being merged: the gates
    # below bound the committed TREE, not its ancestry — a session-appended
    # parent would ride the caller's commit into main (review finding).
    if [ "$(cat "$GIT_DIR/MERGE_HEAD" 2>/dev/null)" != "$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse "$branch" 2>/dev/null)" ]; then
        echo "  MERGE_HEAD no longer names exactly $branch — aborting"
        return 1
    fi

    # Stage the resolved files; fail if anything is still conflicted. git add
    # resolves an unmerged index entry regardless of content, so the marker
    # and bound gates below carry the real verification.
    git add -- $files
    if git diff --name-only --diff-filter=U | grep -q .; then
        return 1
    fi

    # Index-integrity gates, before any commit:
    # - nothing beyond the allowed set may be staged (session staging foreign
    #   content — possibly injected — must abort, not land on main);
    # - nothing merge-staged may have been unstaged (a silent drop of one
    #   merge side).
    local staged_now extra missing
    staged_now=$(git diff --cached --name-only | sort -u)
    extra=$(comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$staged_now"))
    missing=$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$staged_now"))
    if [ -n "$extra" ]; then
        echo "  LLM session staged unexpected paths — aborting: $(echo "$extra" | tr '\n' ' ')"
        return 1
    fi
    if [ -n "$missing" ]; then
        echo "  LLM session unstaged merge-side paths — aborting: $(echo "$missing" | tr '\n' ' ')"
        return 1
    fi

    # Pick up the session's edits to other tracked files (the compile/test
    # fixes it made for the resolution): they must land WITH the merge
    # commit, not strand in main's worktree while the commit implies they
    # are in. Only files NEWLY dirtied since the pre-session snapshot may be
    # staged — whatever main's worktree already had dirty (or a session edit
    # to such a file) stays unstaged; untracked files are left for the
    # per-worker sync loop.
    local touched_others
    touched_others=$(git diff --name-only | grep -v '^\.beads/' | sort)
    if [ -n "$touched_others" ] && [ -n "$unstaged_before" ]; then
        touched_others=$(comm -13 <(printf '%s\n' "$unstaged_before") <(printf '%s\n' "$touched_others"))
    fi
    if [ -n "$touched_others" ]; then
        echo "  LLM session also modified: $(echo "$touched_others" | tr '\n' ' ')"
        git add -- $touched_others
    fi

    # Final content gate over the exact commit set (the index): no conflict
    # markers anywhere. git grep --cached reads index content directly, so
    # staged deletions cannot error the check and paths are parsed safely;
    # -I skips binaries; grep rc 2 (error) aborts rather than passing. The
    # bare ======= / ||||||| forms are included: a false positive only
    # demotes to manual resolution, never to a wrong commit.
    local mrc=0
    git grep --cached -qIE -e '^<{7}' -e '^={7}$' -e '^\|{7}' -e '^>{7}' -- || mrc=$?
    if [ "$mrc" -ne 1 ]; then
        echo "  conflict-marker gate failed (grep rc=$mrc) — aborting"
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

# Drop branch-side .beads entries and stale vendored oscore from the merge
# index + worktree. Shared by the clean-merge path and the LLM-reconciled
# success path — both commits must carry code only. No-op unless the in-flight
# merge actually staged store entries: a blind rewind here destroys concurrent
# bd writes made during the merge (0i1p).
normalize_merge_store_entries() {
    local branch="$1"
    merge_staged_store_entries || return 0
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
        snapshot_store "$branch-clean"
        normalize_merge_store_entries "$branch"
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
            else
                # Same store normalization as the clean-merge path (bead
                # qfkj): the merge auto-staged non-conflicted branch-side
                # .beads/oscore entries, and the kimi session may have staged
                # more — none of that may land in main's commit.
                snapshot_store "$branch-llm"
                normalize_merge_store_entries "$branch"
                if BEADS_ALLOW_STORE_COMMIT=1 git commit --no-edit --quiet; then
                    echo "  merged via LLM semantic reconciliation"
                else
                    echo "  semantic merge produced no commit — aborting"
                    snapshot_store "$branch-nocommit"
                    git merge --abort 2>/dev/null || true
                    conflicted+=("$branch")
                fi
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
