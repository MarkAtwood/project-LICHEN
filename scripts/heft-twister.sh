#!/bin/bash
# Run twister tests on heft
# Usage: ./scripts/heft-twister.sh [twister args...]
# Examples:
#   ./scripts/heft-twister.sh -T lichen/tests/schc_generic -p native_sim
#   ./scripts/heft-twister.sh -T lichen/tests -p native_sim --parallel 16

set -e

HEFT_WORKSPACE="~/Developer/lichen-workspace/project-LICHEN"

# Sync local changes to heft
echo "Syncing local changes to heft..."
rsync -az --delete \
  --exclude='.git' \
  --exclude='build*' \
  --exclude='zephyr' \
  --exclude='modules' \
  --exclude='bootloader' \
  --exclude='.west' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.venv' \
  lichen/ heft:$HEFT_WORKSPACE/lichen/

# Run twister
echo "Running twister on heft: $*"
ssh heft "cd $HEFT_WORKSPACE && \
  source ~/Developer/lichen-env.sh && \
  ./zephyr/scripts/twister $*"
