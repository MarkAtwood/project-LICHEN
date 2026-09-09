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

# Shared fail-stop for the LLM-merge guards (bead ndtl). Exiting with
# MERGE_HEAD/MSG/MODE still in place lets the NEXT run's pre-loop .beads
# checkpoint commit a phantom merge (tree of HEAD + .beads, second parent
# the worker branch): 'git rev-list main..branch' then returns 0 forever and
# the branch's real commits are silently never synced. The index must also
# be unstaged (review finding): the session's never-gated staged resolution
# would otherwise ride that same checkpoint in as a normal commit. Both are
# best-effort — the exit is already fail-stop. The non-fatal 'return 1'
# paths leave merge state for the caller's 'git merge --abort' by design.
llm_merge_fatal() {
    echo "  FATAL: $1" | tee -a /tmp/lichen-kimi-last.log
    rm -f "$GIT_DIR/MERGE_HEAD" "$GIT_DIR/MERGE_MSG" "$GIT_DIR/MERGE_MODE"
    # A session-planted stale index.lock would make the reset fail and leave
    # never-gated staged content for the next run's checkpoint; the lock's
    # owner is dying with this process, so removing it is safe here.
    rm -f "$GIT_DIR/index.lock"
    git reset -q >/dev/null 2>&1 || true
    # A poisoned rr-cache must not survive a fail-stop either: the next run
    # would snapshot it as the pre-session baseline and replay its postimage
    # past every gate. Deleting costs only rerere history (re-recorded on
    # the next conflict); called from rr_restore too, where rm may already
    # have failed — best-effort.
    rm -rf "$GIT_DIR/rr-cache" 2>/dev/null || true
    rm -f "$session_log"
    exit 2
}

# rr-cache restore, on EVERY post-session path (bead ndtl): a compliant
# session's bare 'git rerere' — or a malicious direct postimage write —
# changes rr-cache without tripping the mutation guard (no commit, no
# HEAD/ref/MERGE_HEAD/MERGE_MSG/staged-set move), and the next sync's
# CLEAN-merge path replays the postimage past every gate. Restoring only on
# the mutation path both misses that poisoning and would false-positive a
# legit 'git rerere' if rr-cache were pinned instead. Restoring
# unconditionally neutralizes both. Fail-stop on error: a leftover polluted
# cache must not pass silently. Reads rr_had/rr_snap_b64 from the enclosing
# function (bash dynamic scoping); the snapshot is shell memory, not a /tmp
# file, so the session cannot craft what gets restored.
rr_restore() {
    if ! rm -rf "$GIT_DIR/rr-cache" 2>>/tmp/lichen-kimi-last.log; then
        llm_merge_fatal "could not clear $GIT_DIR/rr-cache — delete it manually before the next sync"
    fi
    if [ "$rr_had" = 1 ] && [ -n "$rr_snap_b64" ]; then
        if ! printf '%s' "$rr_snap_b64" | base64 -d | tar -C "$GIT_DIR" -xf - 2>>/tmp/lichen-kimi-last.log; then
            llm_merge_fatal "rr-cache restore failed — delete $GIT_DIR/rr-cache manually before the next sync"
        fi
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

    # State pin (bead project-LICHEN-worker6-d42k, from beads-worker-1): the
    # session runs with shell/git access mid-merge. If it commits, switches
    # branch, restarts the merge on a different parent, aborts it, or stages
    # foreign content, every gate below is bypassed and the caller's
    # 'git merge --abort' no-ops while main advances ungated (or commits land
    # on the wrong branch). Snapshot HEAD + ref + merge parent + staged set
    # alongside the staged-set bound above; rewind any mutation before
    # gating. Rewind restores main's checkout only — a session-created branch
    # with commits survives as debris (the loop only consumes beads-worker-*).
    # Residuals by design (tracked in follow-up beads): session writes to
    # worker-branch refs, hooks/config, .beads content, push to remote,
    # staged CONTENT mutation of in-merge paths (name-set granularity only —
    # hashing staged entries breaks the happy path, which must re-stage its
    # resolutions), unstaged worktree vandalism of tracked files on the
    # success path, untracked-file wedges against later loop merges, and
    # session grandchildren that outlive a TERM-compliant leader (timeout
    # exits with the leader, so the -k grace KILL never fires for them —
    # they can mutate state after the pin's single post-session sample).
    # (Resolution note, main vs beads-worker-1: compatible, both kept —
    # beads-worker-1's grandchildren residual item is load-bearing (the
    # '-k 10' timeout comment below cross-references this list).)
    # (Resolution note, this merge, main vs beads-worker-2: compatible, both
    # kept — main's four-dimension pin (HEAD + symref + MERGE_HEAD +
    # staged-set) subsumes beads-worker-2's HEAD+symref pin (its
    # symref_before ≡ ref_before with the DETACHED sentinel), so the pin
    # structure is main's. beads-worker-2's additional dimensions are kept:
    # the replace-ref list pin (a session-created replace ref would rewrite
    # the pin check and the rewind target itself — hence
    # GIT_NO_REPLACE_OBJECTS on the HEAD reads), the detached-HEAD entry
    # refusal (fail-closed before a session is spent), and the rr-cache
    # snapshot held in shell memory instead of main's /tmp temp file — /tmp
    # is same-UID-writable by the session, parent-shell memory is not, and
    # the shared rr_restore() helper above already consumes
    # rr_had/rr_snap_b64. Main's fail-closed-on-snapshot-error rule is kept
    # on top of the in-memory snapshot. beads-worker-2's replace-ref purge,
    # rewind verification, and stale-merge-state clearing are merged into
    # the post-session guard below. Accepted residuals beyond this pin
    # (hooks/config persistence, push-to-remote, worker-branch ref moves,
    # kill-parent, background delayed movers, .git identity swap, no flock):
    # bead project-LICHEN-worker6-nm0h — they need a sandboxing design
    # decision, not more pin lines. This note supersedes the earlier
    # main-vs-beads-worker-2 note, which predates the in-memory snapshot and
    # the replace-ref dimension.)
    # (Resolution note, this merge, main vs beads-worker-2 (bead ndtl round):
    # compatible, both kept — main's pin structure stands (detached-HEAD
    # entry refusal, in-pin in-memory rr-cache snapshot with the fail-closed
    # rule, rewind verification, and the MERGE_HEAD-names-branch gate before
    # staging), and beads-worker-2's bead-ndtl review findings are merged in
    # on top: the llm_merge_fatal / fail-stop rr_restore helpers above, the
    # full-content MERGE_HEAD pin via cat (a session-appended extra parent
    # is invisible to 'git rev-parse MERGE_HEAD', which prints only the
    # first line), the new MERGE_MSG pin dimension, sequencer-state
    # clearing, and GIT_NO_REPLACE_OBJECTS on every object read including
    # the rewind-failure path. An intervening accept-ours resolution had
    # dropped the ndtl set wholesale; this reconciliation restores it. The
    # pin is now five dimensions: HEAD + symref + MERGE_HEAD + MERGE_MSG +
    # staged-set.)
    local head_before ref_before merge_head_before merge_msg_before staged_before files_nl
    local ref_after head_after merge_head_after merge_msg_after staged_after why
    local replace_before replace_now replace_new rr_had=0 rr_snap_b64=""
    # GIT_NO_REPLACE_OBJECTS on every object read in this guard (review
    # finding, bead ndtl): a pre-session 'git replace <main-sha> <evil>'
    # would make head_before resolve to the attacker's object, and the
    # mutation-path 'git reset --hard "$head_before"' would then move main
    # straight onto it — the rewind becoming the landing vector. The
    # replace-ref list is pinned too and session-created ones are purged
    # post-session, before any gate or downstream 'git checkout HEAD'.
    head_before=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse HEAD)
    ref_before=$(git symbolic-ref HEAD 2>/dev/null || echo DETACHED)
    # Detached HEAD at entry (beads-worker-2): the rewind would move whatever
    # ref the session left current; refuse fail-closed (the caller aborts the
    # merge).
    if [ "$ref_before" = DETACHED ]; then
        echo "  detached HEAD at entry — refusing LLM merge"
        return 1
    fi
    replace_before=$(git replace -l 2>/dev/null | sort)
    # Full MERGE_HEAD content, not 'git rev-parse MERGE_HEAD': rev-parse
    # prints only the FIRST line of a multi-parent MERGE_HEAD, so a session
    # appending an extra parent (ancestry injection without a commit) would
    # be invisible to this pin (harness case merge_head_extra, bead ndtl).
    # cat is also immune to replace-refs.
    merge_head_before=$(cat "$GIT_DIR/MERGE_HEAD" 2>/dev/null || echo NONE)
    # MERGE_MSG too (review finding, bead ndtl): the caller commits with
    # --no-edit, so a session-rewritten message (forged trailers/signoffs)
    # would land ungated on main's merge commit without tripping any other
    # dimension.
    merge_msg_before=$(cat "$GIT_DIR/MERGE_MSG" 2>/dev/null || echo NONE)
    # rr-cache snapshot in shell memory: rerere.enabled is set at the top of
    # this script, so a session-run 'git commit' (or a direct postimage
    # write) RECORDS its ungated resolution; rewinding HEAD alone would let
    # the next sync's merge replay it past every gate (rerere pre-resolves
    # the conflict the LLM then validates). Restored on the rewind path
    # (status-checked) and again on every non-tamper path (rr_restore). The
    # bytes live in this shell variable, not a /tmp file (review finding,
    # bead ndtl): /tmp is same-UID-writable by the session for the full
    # 900s session window, so a file-held snapshot would let the session
    # craft the rr-cache that rr_restore "restores" — the restore becomes
    # the poisoning vector. Parent-shell memory is not reachable by the
    # session.
    if [ -d "$GIT_DIR/rr-cache" ]; then
        rr_had=1
        rr_snap_b64=$(tar -C "$GIT_DIR" -cf - rr-cache 2>/dev/null | base64)
        # Fail-closed (main): never run the session without a usable
        # snapshot — an unprotected session can record an ungated postimage.
        if [ -z "$rr_snap_b64" ]; then
            echo "  rr-cache snapshot failed — aborting merge"
            return 1
        fi
    fi
    # The conflicted paths ($files) are excluded from the staged-set pin: the
    # session MUST re-stage them to resolve, and an accept-ours resolution
    # (staged blob == HEAD blob) legitimately drops the path from the
    # name-only diff — comparing with them included wedges that valid
    # resolution as a false "mutation" every sync. --no-renames keeps the
    # name set stable against rename pairing.
    files_nl=$(printf '%s\n' $files)
    staged_before=$(git diff --cached --name-only --no-renames | grep -vxF "$files_nl" | sort)

    echo "  LLM merge session ($model) on: $files"
    # 15-minute cap plus a 10s kill grace (-k 10, bead 7mvj): without -k a
    # session that ignores SIGTERM wedges the sync loop forever. timeout
    # signals the child's process group (no --foreground), so the grace KILL
    # also reaps same-group grandchildren — but only while the session
    # leader is still being awaited: a TERM-compliant leader exits rc=124
    # immediately and a TERM-ignoring grandchild survives (see the pin's
    # residuals list above).
    local log=/tmp/lichen-kimi-last.log
    local session_log rc
    # Session output goes to a private file: the sentinel check must not be
    # satisfiable by a bare RESOLVED appended to the shared last.log by a
    # concurrent janitor session or a sibling worker's copy of this script.
    # (Resolution note, main vs beads-worker-1: main's private-session-log
    # form is kept — the RESOLVED sentinel check further down greps
    # "$session_log", so the private file is load-bearing — and
    # beads-worker-1's state-pin mutation guard above is preserved in full.
    # The shared log still gets a copy via cat >>.)
    session_log=$(mktemp) || { echo "  mktemp failed — aborting merge"; return 1; }
    # (Resolution note, this merge, main vs beads-worker-2: compatible, both
    # kept — main's '-k 10' kill grace on the session invocation (bead 7mvj,
    # matching the timeout comment above and the budget log line below) and
    # beads-worker-2's in-memory rr-cache snapshot (in the pin above), which
    # supersedes the $rr_snap temp file main used here: /tmp is
    # same-UID-writable by the session.)
    timeout -k 10 900 opencode run --model "$model" "You are resolving a GIT MERGE CONFLICT between the current branch (main, HEAD) and incoming branch $branch in the LICHEN repo. The conflicted files are: $files. For each conflict: read both sides plus surrounding code, understand each side's INTENT, and write the reconciled resolution (both intents preserved when compatible; otherwise pick the correct one and say why in a comment). Then run the touched crates'/packages' quick tests (cargo check / pytest for touched paths). You are done when: git diff --check passes, no conflict markers remain in any file, and the touched code compiles/tests clean. Do not resolve by deleting a side wholesale; do not touch .beads/ or spec text. Finish with the single word RESOLVED on its own line." > "$session_log" 2>&1; rc=$?
    cat "$session_log" >> "$log" 2>/dev/null || true
    echo "$(date +%FT%T) kimi budget=900s+10s-kill-grace exit=$rc (124=timeout, 137=TERM ignored then KILLed)" >> "$log"

    # Purge session-created replace refs on EVERY path (review finding, bead
    # ndtl): they rewrite object reads repo-wide — the caller's commit, the
    # conflict-path 'git checkout HEAD -- .beads' sites, and future syncs
    # all honor refs/replace/*. Must run before the mutation guard's pin
    # reads.
    replace_now=$(git replace -l 2>/dev/null | sort)
    replace_new=$(comm -13 <(printf '%s\n' "$replace_before") <(printf '%s\n' "$replace_now"))
    if [ -n "$replace_new" ]; then
        echo "  removing session-created replace refs: $(echo $replace_new | tr '\n' ' ')"
        printf '%s\n' "$replace_new" | while IFS= read -r r; do
            git replace -d "$r" >/dev/null 2>&1 || true
        done
    fi
    # Clear sequencer state on every path too (review finding, bead ndtl):
    # the caller's 'git merge --no-commit' would have refused pre-existing
    # CHERRY_PICK_HEAD/REVERT_HEAD, so any present now are session-planted;
    # 'git commit' reuses CHERRY_PICK_HEAD's AUTHOR (forged author on main).
    rm -f "$GIT_DIR/CHERRY_PICK_HEAD" "$GIT_DIR/REVERT_HEAD"

    # Mutation guard runs BEFORE the rc early-return: a session that exits
    # non-zero (or is killed at the timeout) after mutating git state must
    # still be rewound, or ungated state persists on main.
    # (Resolution note, main vs beads-worker-1: beads-worker-1's form is kept
    # — computing the after-values and the per-dimension why-list is the only
    # form consistent with the staged-set pin above, which excludes the
    # conflicted paths via $files_nl and --no-renames. Main's inline
    # `git diff --cached --name-only | sort` compares against a different set
    # than the pinned staged_before and would misfire as a false "mutation"
    # on every run; the why-list also names exactly which dimension mutated
    # and logs the full transitions. Main's ordering intent is preserved:
    # this guard still runs before the rc early-return below.)
    # (Resolution note, this merge, main vs beads-worker-2: main's
    # per-dimension detection is kept; beads-worker-2's safeguards are merged
    # in — GIT_NO_REPLACE_OBJECTS on the HEAD reads (a replacement must never
    # rewrite the rewind target), status-checked rr-cache restore from the
    # in-memory snapshot, and post-rewind verification with stale
    # MERGE_HEAD/MSG/MODE clearing (exiting with a merge still in flight lets
    # the NEXT run's pre-loop .beads checkpoint complete a phantom merge and
    # silently strand the branch — worker-2 review finding).)
    ref_after=$(git symbolic-ref HEAD 2>/dev/null || echo DETACHED)
    head_after=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse HEAD)
    merge_head_after=$(cat "$GIT_DIR/MERGE_HEAD" 2>/dev/null || echo NONE)
    merge_msg_after=$(cat "$GIT_DIR/MERGE_MSG" 2>/dev/null || echo NONE)
    staged_after=$(git diff --cached --name-only --no-renames | grep -vxF "$files_nl" | sort)
    why=""
    [ "$ref_after" != "$ref_before" ] && why="$why ref"
    [ "$head_after" != "$head_before" ] && why="$why HEAD"
    [ "$merge_head_after" != "$merge_head_before" ] && why="$why MERGE_HEAD"
    [ "$merge_msg_after" != "$merge_msg_before" ] && why="$why MERGE_MSG"
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
            # Defense in depth: the entry refusal above makes this
            # unreachable; fail-stop anyway rather than risk moving the
            # wrong ref (a session may have attached+advanced some branch).
            llm_merge_fatal "mutation from a detached HEAD start — manual repair required"
        fi
        # Preserve concurrent bd writes before the destructive reset
        # (beads-worker-2; snapshot_store is a no-op on a clean store).
        snapshot_store "$branch-headmoved"
        if ! git symbolic-ref HEAD "$ref_before" 2>>/tmp/lichen-kimi-last.log; then
            llm_merge_fatal "could not repoint HEAD to $ref_before — manual repair required"
        fi
        if GIT_NO_REPLACE_OBJECTS=1 git reset --hard "$head_before" >> /tmp/lichen-kimi-last.log 2>&1; then
            echo "$(date +%FT%T) kimi mutated git state (exit=$rc); rewound to $head_before on $ref_before" >> /tmp/lichen-kimi-last.log
        else
            llm_merge_fatal "rewind failed; main may hold ungated state ($(GIT_NO_REPLACE_OBJECTS=1 git rev-parse HEAD)) — manual repair required"
        fi
        # Rewind rerere: the session's commit recorded its ungated resolution
        # into rr-cache; replaying it next sync would bypass every gate.
        # rr_restore restores the in-memory snapshot (not a session-writable
        # /tmp file) and fail-stops via llm_merge_fatal on error: a leftover
        # polluted cache must not pass silently.
        rr_restore
        # Verify the rewind actually landed (beads-worker-2): continuing the
        # merge loop on unverified repo state risks exactly the ungated
        # landing this guards. llm_merge_fatal clears stale
        # MERGE_HEAD/MSG/MODE before the fail-stop: exiting with a merge
        # still in flight lets the NEXT run's pre-loop .beads checkpoint
        # complete a phantom merge and silently strand the branch.
        if [ "$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse HEAD 2>/dev/null)" != "$head_before" ] ||
           [ "$(git symbolic-ref -q HEAD 2>/dev/null || true)" != "$ref_before" ]; then
            llm_merge_fatal "rewind verification failed — manual repair required"
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
        git add -- $touched_others || return 1
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
