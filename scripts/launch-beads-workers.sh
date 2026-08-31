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
# Fleet worktree base: Mac (Attic) by default; override for other hosts.
if [ -d /Volumes/Attic ]; then
    WORKTREE_BASE="${LICHEN_WORKTREE_BASE:-/Volumes/Attic/Desktop/Projects/lichen-workers}"
else
    WORKTREE_BASE="${LICHEN_WORKTREE_BASE:-$HOME/Developer/lichen-workers}"
fi
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

    # Shared beads coordination via BEADS_DIR (no symlink: git in the worktree
    # never sees .beads changes; workers' bd reads/writes main's store).
    # Remove any stale symlink from the old launcher design.
    if [ -L "$WORKTREE/.beads" ]; then
        rm -f "$WORKTREE/.beads"
        git -C "$WORKTREE" checkout -- .beads 2>/dev/null || true
    fi

    # Worker prompt + current plugin/config files.
    # Never git-merge main into workers: .beads paths block merges, and workers
    # don't need main's beads content anyway.
    mkdir -p "$WORKTREE/scripts" "$WORKTREE/.opencode/plugins"
    cp -f "$REPO_ROOT/scripts/beads-worker-full.txt" "$WORKTREE/scripts/"
    cp -f "$REPO_ROOT/scripts/beads-worker-round.txt" "$WORKTREE/scripts/" 2>/dev/null || true
    cp -f "$REPO_ROOT"/.opencode/plugins/* "$WORKTREE/.opencode/plugins/"
    cp -f "$REPO_ROOT/.opencode/package.json" "$WORKTREE/.opencode/package.json"
    cp -f "$REPO_ROOT/tui.json" "$WORKTREE/tui.json"

    if tmux list-windows -t "$SESSION" 2>/dev/null | grep -q "^$i:.*worker$i"; then
        echo "Worker $i window already exists, skipping"
        continue
    fi

    # Area affinity per worker (disjoint-ish routing; workers fall back to any
    # ready bead when their pool is empty — see worker prompt affinity rule).
    case $i in
        1)   AFFINITY="zephyr" ;;
        2)   AFFINITY="zephyr,renode" ;;
        3)   AFFINITY="networking,gateway" ;;
        4)   AFFINITY="schc,link" ;;
        5)   AFFINITY="python" ;;
        6)   AFFINITY="coap,rust" ;;
        7)   AFFINITY="lci,hal,yggdrasil,phy,renode" ;;
    esac
    # Unattended workers: allow the tool surface, deny the catastrophic few.
    WORKER_POLICY='{"permission":{"edit":"allow","webfetch":"allow","bash":{"*":"allow","rm -rf *":"deny","sudo *":"deny","git push*":"deny"}}}'
    # Zephyr toolchain env per host (Mac Attic layout vs heft Developer layout),
    # so Zephyr beads work regardless of shell context. ~/.opencode/bin is kept
    # ahead of any stale system opencode install.
    if [ -d /Volumes/Attic ]; then
        ZEPHYR_ENV="ZEPHYR_SDK_INSTALL_DIR=/Volumes/Attic/zephyr-sdk-0.16.8 ZEPHYR_BASE=/Volumes/Attic/Developer/zephyr-workspace/zephyr PATH=/Volumes/Attic/Developer/zephyr-venv/bin:/Volumes/Attic/Developer/cmake-3.31.3-macos-universal/CMake.app/Contents/bin:$HOME/.opencode/bin:$PATH"
    else
        ZEPHYR_ENV="ZEPHYR_SDK_INSTALL_DIR=$HOME/Developer/zephyr-sdk/zephyr-sdk-0.16.8 ZEPHYR_BASE=$HOME/Developer/lichen-workspace/project-LICHEN/zephyr PATH=$HOME/Developer/lichen-venv/bin:$HOME/.opencode/bin:$PATH"
    fi
    CMD="env $ZEPHYR_ENV OPENCODE_CONFIG_CONTENT='$WORKER_POLICY' BEADS_DIR=$REPO_ROOT/.beads BEADS_ACTOR=opencode-worker-$i OPENCODE_BEADS_LOOP=$i LICHEN_AFFINITY='$AFFINITY' opencode"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux new-window -d -t "$SESSION:" -n "worker$i" -c "$WORKTREE" "$CMD"
    else
        tmux new-session -d -s "$SESSION" -n "worker$i" -c "$WORKTREE" "$CMD"
    fi
    sleep 2
done

# Hourly sync window: commits + merges worker code to main, reclaims dead
# workers' leases. This is what makes overnight/week-long runs self-sufficient.
if ! tmux list-windows -t "$SESSION:" 2>/dev/null | grep -q "sync"; then
    chmod +x "$REPO_ROOT/scripts/sync-beads-loop.sh"
    tmux new-window -d -t "$SESSION:" -n "sync" -c "$REPO_ROOT" \
        "$REPO_ROOT/scripts/sync-beads-loop.sh 15"
    echo "Sync loop window started (hourly; log: .beads-sync.log)"
fi

echo ""
echo "=== $NUM_WORKERS workers launched in tmux session '$SESSION' ==="
[ -z "${TMUX:-}" ] && echo "Attach with: tmux attach -t $SESSION"
echo "Stop all: tmux kill-session -t $SESSION"
