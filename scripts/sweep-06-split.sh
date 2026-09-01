#!/bin/bash
# Split sweep for spec/06-security.md — the section is too big for one flash
# session (3 consecutive "operation timed out" failures on single-generation
# matrix dumps). Runs three subsection passes with incremental writing, then
# assembles the final artifacts the wave runner expects.
# Usage: scripts/sweep-06-split.sh
set -u
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$HOME/Developer/lichen-workspace/project-LICHEN")
FLASH="${LICHEN_SWEEP_MODEL:-openrouter/z-ai/glm-5.3-flash}"
export OPENCODE_CONFIG_CONTENT='{"permission":{"edit":"allow","webfetch":"allow","bash":{"*":"allow","rm -rf *":"deny","sudo *":"deny","git push*":"deny"}}}'
export PATH="$HOME/.opencode/bin:$PATH"
export BEADS_DIR="${BEADS_DIR:-$REPO_ROOT/.beads}"
cd "$REPO_ROOT"

run_part() {
    local part="$1" range="$2"
    opencode run --model "$FLASH" "$(cat "$REPO_ROOT/scripts/spec-sweep-prompt.md")

SPEC SECTION: spec/06-security.md — PART $part OF 3 ONLY ($range).
Output files: WRITE matrix rows INCREMENTALLY (append after each subsection —
never build one giant response) to docs/spec-coverage/06-security-part$part.md
and flagged rows to docs/spec-coverage/06-security-part$part-flagged.md.
Other parts handle the rest of the section — do not touch them." || return 1
    [ -f "docs/spec-coverage/06-security-part$part.md" ] || return 1
}

run_part 1 "§1-§4: intro, terminology, key hierarchy, TOFU/trust models" || exit 1
echo "part 1 done"
run_part 2 "§5-§7: OSCORE, EDHOC, group keying — classify as human-only where the prompt says so; keep this part light" || exit 1
echo "part 2 done"
run_part 3 "§8-end: RPL security, link security, security considerations remainder" || exit 1
echo "part 3 done"

{
    echo "# Spec Coverage Matrix — spec/06-security.md (split sweep)"
    echo
    cat docs/spec-coverage/06-security-part1.md
    echo
    cat docs/spec-coverage/06-security-part2.md
    echo
    cat docs/spec-coverage/06-security-part3.md
} > docs/spec-coverage/06-security.md
{
    cat docs/spec-coverage/06-security-part1-flagged.md
    echo
    cat docs/spec-coverage/06-security-part2-flagged.md
    echo
    cat docs/spec-coverage/06-security-part3-flagged.md
} > docs/spec-coverage/06-security-flagged.md
git add docs/spec-coverage/06-security.md docs/spec-coverage/06-security-flagged.md docs/spec-coverage/06-security-part*.md
git commit -qm "docs(spec): coverage sweep 06-security (split into 3 passes)"
echo "06-security assembled and committed"
