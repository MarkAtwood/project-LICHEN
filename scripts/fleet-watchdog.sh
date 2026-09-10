#!/bin/bash
# Fleet watchdog: resurrects the four fleet daemons if they die, including
# after a heft reboot. Runs from cron every 2 minutes:
#   */2 * * * * flock -n /tmp/fleet-watchdog.lock $REPO/scripts/fleet-watchdog.sh
# Idempotent: only creates what is missing. Worker windows are the driver's
# job (it self-heals those); this covers the controllers.
set -u
REPO="/home/mark/Developer/lichen-workspace/project-LICHEN"
SESSION="lichen-workers"
cd "$REPO" || exit 1

ensure_window() {  # $1=name $2=command — create only if missing (append at
    # end; never target indices — they drift as windows die and rebuild)
    if ! tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux new-session -d -s "$SESSION" -n "$1" "cd $REPO && exec bash"
    fi
    if ! tmux list-windows -t "$SESSION" -F '#{window_name}' 2>/dev/null | grep -qx "$1"; then
        tmux new-window -d -t "$SESSION" -n "$1" "cd $REPO && $2"
        tmux set-window-option -t "$SESSION:$1" automatic-rename off 2>/dev/null
        echo "$(date '+%F %T') watchdog: recreated $1" >> "$REPO/.beads-sync.log"
    fi
}

# Worker worktrees: if a worktree vanished (the week-long outage root cause),
# rebuild it from its branch + .beads symlink BEFORE the driver looks at it.
for n in 1 2 3 4 5 6 7 8; do
    if [ ! -d "$HOME/Developer/lichen-workers/worker$n" ]; then
        if git show-ref --verify -q "refs/heads/beads-worker-$n"; then
            git worktree add "$HOME/Developer/lichen-workers/worker$n" "beads-worker-$n" >/dev/null 2>&1
        else
            git worktree add -b "beads-worker-$n" "$HOME/Developer/lichen-workers/worker$n" main >/dev/null 2>&1
        fi
        [ -e "$HOME/Developer/lichen-workers/worker$n/.beads" ] || \
            ln -s "$REPO/.beads" "$HOME/Developer/lichen-workers/worker$n/.beads"
        echo "$(date '+%F %T') watchdog: rebuilt worktree worker$n" >> "$REPO/.beads-sync.log"
    fi
done

# Controllers (worker rounds are headless loops, one window per worker)
ensure_window sync "exec ./scripts/sync-beads-loop.sh 15"
ensure_window janitor "exec ./scripts/merge-janitor.sh"
ensure_window guards "exec ./scripts/fleet-guards.sh 10"
for n in 1 2 3 4 5 6 7 8; do
    ensure_window "hw$n" "exec ./scripts/fleet-headless.sh $n"
done

# (sweep-all retired: all 17 sections swept, discovery closed)
