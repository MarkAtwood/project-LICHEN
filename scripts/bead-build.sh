#!/bin/bash
# Automatic environment routing for bead builds
# Usage: ./scripts/bead-build.sh <bead-id> <build-command...>
# Example: ./scripts/bead-build.sh project-LICHEN-xyz west build -b native_sim lichen/tests/foo

set -e

BEAD_ID="$1"
shift

if [ -z "$BEAD_ID" ]; then
  echo "Usage: $0 <bead-id> <build-command...>" >&2
  exit 1
fi

# Get labels for bead
LABELS=$(bd show "$BEAD_ID" 2>/dev/null | grep "^LABELS:" | sed 's/LABELS: //')

if [ -z "$LABELS" ]; then
  echo "Warning: No labels found for $BEAD_ID, defaulting to local" >&2
  ROUTE="local"
elif echo "$LABELS" | grep -q "blocked:hardware"; then
  echo "Error: $BEAD_ID is blocked:hardware - cannot build without physical device" >&2
  exit 1
elif echo "$LABELS" | grep -q "needs-linux"; then
  ROUTE="heft"
elif echo "$LABELS" | grep -q "local-ok"; then
  ROUTE="local"
else
  echo "Warning: $BEAD_ID has no routing label (local-ok/needs-linux), defaulting to local" >&2
  ROUTE="local"
fi

echo "[$BEAD_ID] Routing to: $ROUTE"
echo "[$BEAD_ID] Command: $*"
echo ""

case "$ROUTE" in
  local)
    # Run locally with Attic toolchain
    export ZEPHYR_SDK_INSTALL_DIR=/Volumes/Attic/zephyr-sdk-0.16.8
    export ZEPHYR_BASE=/Volumes/Attic/Developer/zephyr-workspace/zephyr
    export PATH="/Volumes/Attic/Developer/cmake-3.31.3-macos-universal/CMake.app/Contents/bin:/opt/homebrew/opt/llvm/bin:$PATH"
    source /Volumes/Attic/Developer/zephyr-venv/bin/activate 2>/dev/null || true
    "$@"
    ;;
  heft)
    # Sync to heft and run there
    HEFT_WORKSPACE="~/Developer/lichen-workspace/project-LICHEN"

    echo "Syncing lichen/ to heft..."
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

    echo "Running on heft..."
    ssh heft "cd $HEFT_WORKSPACE && source ~/Developer/lichen-env.sh && $*"
    ;;
esac
