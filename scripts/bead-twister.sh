#!/bin/bash
# Automatic environment routing for bead twister runs
# Usage: ./scripts/bead-twister.sh <bead-id> <twister-args...>
# Example: ./scripts/bead-twister.sh project-LICHEN-xyz -T lichen/tests/schc_generic -p native_sim

set -e

BEAD_ID="$1"
shift

if [ -z "$BEAD_ID" ]; then
  echo "Usage: $0 <bead-id> <twister-args...>" >&2
  exit 1
fi

# Get labels for bead
LABELS=$(bd show "$BEAD_ID" 2>/dev/null | grep "^LABELS:" | sed 's/LABELS: //')

if [ -z "$LABELS" ]; then
  echo "Warning: No labels found for $BEAD_ID, defaulting to local" >&2
  ROUTE="local"
elif echo "$LABELS" | grep -q "blocked:hardware"; then
  echo "Error: $BEAD_ID is blocked:hardware - cannot test without physical device" >&2
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
echo "[$BEAD_ID] Twister args: $*"
echo ""

case "$ROUTE" in
  local)
    echo "Error: twister requires Linux (native_sim). This bead is labeled local-ok." >&2
    echo "If this bead needs twister, relabel it: bd label add $BEAD_ID needs-linux" >&2
    exit 1
    ;;
  heft)
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

    echo "Running twister on heft..."
    ssh heft "cd $HEFT_WORKSPACE && source ~/Developer/lichen-env.sh && ./zephyr/scripts/twister $*"
    ;;
esac
