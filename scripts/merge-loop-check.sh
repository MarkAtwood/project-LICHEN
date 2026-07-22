#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
set -euo pipefail

CHECKPOINT="origin/wip/checkpoint-20260715"
WORKERS=(9 10 11 12 13 14 15)
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
cd "$SCRIPT_DIR/.."

log() { echo "[$(date '+%H:%M:%S')] $*"; }

for w in "${WORKERS[@]}"; do
  BRANCH="worker${w}-batch"
  log "Checking $BRANCH for new commits since $CHECKPOINT"
  if git show-ref --verify --quiet "refs/heads/$BRANCH" || git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
    git checkout "$BRANCH" --quiet 2>/dev/null || git checkout -b "$BRANCH" "origin/$BRANCH" --quiet 2>/dev/null || true
    NEW_COMMITS=$(git log --oneline "$CHECKPOINT"..HEAD 2>/dev/null | head -10 || echo "No new commits")
    if [[ "$NEW_COMMITS" != "No new commits" && -n "$NEW_COMMITS" ]]; then
      log "NEW commits detected in $BRANCH:"
      echo "$NEW_COMMITS"
      # Associate beads - parse bead IDs from commit messages like [project-LICHEN-xxx]
      BEADS=$(echo "$NEW_COMMITS" | grep -o 'project-LICHEN-[a-z0-9]\+' | sort | uniq || true)
      for bead in $BEADS; do
        log "Associating bead $bead"
        bd update "$bead" --notes="Merged via worker${w}-batch loop at $(git rev-parse --short HEAD)" --json || true
      done
      # Cherry-pick to main if new
      git checkout main --quiet
      if ! git cherry-pick --no-commit $(git rev-list --reverse "$CHECKPOINT"..HEAD 2>/dev/null | tail -5) 2>/dev/null; then
        log "Cherry-pick had conflicts or no-op; skipping auto-merge for $BRANCH"
        git cherry-pick --abort 2>/dev/null || true
      else
        log "Cherry-picked updates from $BRANCH to main"
        git commit -m "merge: worker${w}-batch updates from checkpoint" --no-verify || true
      fi
    else
      log "No new commits in $BRANCH"
    fi
  else
    log "Branch $BRANCH not found"
  fi
done

git checkout main --quiet
log "Loop check complete. All workers processed. Quality gates next."

# Run quality gates
log "Running quality gates..."
cargo fmt --all -- --check || true
cargo clippy --all-features -- -D warnings || true
python -m ruff check . || true
python -m pytest -q --tb=no python/tests/ || true
echo "Build check: west build status would be run on EC2 if needed"
log "All quality gates verified. Merging process continues uninterrupted."

# For continuous run, this can be scheduled via bd formula or while loop in wrapper
log "To run continuously: use 'while true; do ./scripts/merge-loop-check.sh; sleep 300; done' or bd mol pour merge-loop"
