#!/bin/bash
# Launch parallel opencode TUI workers for beads processing.
#
# Each worker runs in its own tmux window with the beads-loop plugin active
# (OPENCODE_BEADS_LOOP=<i>): the TUI drives itself bead-by-bead until the
# ready queue drains. Watch progress live; interrupt or type anytime.
#
# Usage: ./scripts/launch-beads-workers.sh [num_workers]
#
# Workers accumulate uncommitted changes. Run periodically:
#   ./scripts/sync-beads-workers.sh   # commits in all worktrees, merges to main
#
# Stop: kill each tmux window (or: tmux kill-session -t lichen-workers)

set -e

NUM_WORKERS=${1:-5}
REPO_ROOT=$(git rev-parse --show-toplevel)
WORKTREE_BASE="/Volumes/Attic/Desktop/Projects/lichen-workers"
SESSION="lichen-workers"

command -v opencode >/dev/null 2>&1 || { echo "opencode not found"; exit 1; }
command -v bd >/dev/null 2>&1 || { echo "bd (beads) not found"; exit 1; }
command -v tmux >/dev/null 2>&1 || { echo "tmux not found (brew install tmux)"; exit 1; }

echo "=== Beads Worker Launcher (TUI mode) ==="
echo "Workers: $NUM_WORKERS"
echo "Repo: $REPO_ROOT"
echo ""

echo "=== Current Beads Status ==="
bd list --json 2>/dev/null | jq -r 'group_by(.status) | .[] | "\(.[0].status): \(length)"'
echo ""

mkdir -p "$WORKTREE_BASE"

# Target session: attach to the caller's session if inside tmux, else create on demand
if [ -n "${TMUX:-}" ]; then
    SESSION=$(tmux display-message -p '#S')
fi

for i in $(seq 1 $NUM_WORKERS); do
    WORKTREE="$WORKTREE_BASE/worker$i"
    BRANCH="beads-worker-$i"

    if [ ! -d "$WORKTREE" ]; then
        echo "Creating worktree: $WORKTREE"
        git worktree add "$WORKTREE" -b "$BRANCH" HEAD 2>/dev/null || \
        git worktree add "$WORKTREE" "$BRANCH" 2>/dev/null || \
        { echo "Failed to create worktree $i"; continue; }
    fi

    # Shared beads coordination
    if [ ! -L "$WORKTREE/.beads" ]; then
        rm -rf "$WORKTREE/.beads" 2>/dev/null
        ln -s "$REPO_ROOT/.beads" "$WORKTREE/.beads"
    fi

    # Worker prompt for the model
    mkdir -p "$WORKTREE/scripts"
    cp -f "$REPO_ROOT/scripts/beads-worker-full.txt" "$WORKTREE/scripts/"

    if tmux list-windows -t "$SESSION" 2>/dev/null | grep -q "^$i:.*worker$i"; then
        echo "Worker $i window already exists, skipping"
        continue
    fi

    echo "Launching worker $i in $WORKTREE"
    CMD="env BEADS_AGENT_ACTOR=opencode-worker-$i OPENCODE_BEADS_LOOP=$i opencode"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux new-window -d -t "$SESSION:" -n "worker$i" -c "$WORKTREE" "$CMD"
    else
        tmux new-session -d -s "$SESSION" -n "worker$i" -c "$WORKTREE" "$CMD"
    fi
    sleep 2
done

echo ""
echo "=== $NUM_WORKERS workers launched in tmux session '$SESSION' ==="
[ -z "${TMUX:-}" ] && echo "Attach with: tmux attach -t $SESSION"
echo "Stop all: tmux kill-session -t $SESSION"
