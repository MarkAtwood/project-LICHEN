#!/bin/bash
# Run native_sim builds on heft
# Usage: ./scripts/heft-native-sim.sh [west build args...]
# Examples:
#   ./scripts/heft-native-sim.sh -b native_sim lichen/samples/lora_ping
#   ./scripts/heft-native-sim.sh -t run

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

# Run the build
echo "Running on heft: west $*"
ssh heft "cd $HEFT_WORKSPACE && \
  source ~/Developer/lichen-env.sh && \
  west $*"
