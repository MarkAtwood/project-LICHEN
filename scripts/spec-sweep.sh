#!/bin/bash
# Spec coverage sweep runner: flash extraction pass over one spec section.
# Usage: scripts/spec-sweep.sh <section-file> [model]
# Requires: BEADS_DIR set (or .beads in cwd); opencode on PATH.
set -e
REPO_ROOT=$(git rev-parse --show-toplevel)
SECTION="${1:?usage: spec-sweep.sh <section-file> [model]}"
MODEL="${2:-openrouter/z-ai/glm-5.3-flash}"
SECNAME=$(basename "$SECTION" .md)
PROMPT="$REPO_ROOT/scripts/spec-sweep-prompt.md"

cd "$REPO_ROOT"
# Unattended: allow tools, deny destructive. The sweep writes docs/spec-coverage.md
# and files beads, so it needs a full agent (not plan) with the policy env.
export OPENCODE_CONFIG_CONTENT='{"permission":{"edit":"allow","webfetch":"allow","bash":{"*":"allow","rm -rf *":"deny","sudo *":"deny","git push*":"deny"}}}'
BEADS_DIR="${BEADS_DIR:-$REPO_ROOT/.beads}" \
opencode run --model "$MODEL" "$(cat "$PROMPT")

SPEC SECTION: $SECTION
Produce the coverage matrix section, gap beads, and the flagged set for
$SECNAME per the protocol above." 2>&1 | tee "$REPO_ROOT/.spec-sweep-$SECNAME.log"
