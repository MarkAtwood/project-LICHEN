#!/usr/bin/env bash
# Create the per-host rust/oscore-fork symlink used by [patch.crates-io]
# oscore in Cargo.toml. The oscore fork lives OUTSIDE this repo at
# host-specific paths, so it is wired with a gitignored symlink rather than
# an absolute path (no sudo required on any host).
#
# Invoke by its in-repo path (rust/scripts/link-oscore-fork.sh); running a
# symlinked copy resolves rust_dir to the copy's parent and is unsupported.
#
# Idempotent: safe to run before every cargo invocation (CI, fresh clones).
# CI runners have neither candidate path and provisioning is not wired yet,
# so the script exits 1 there until the fork checkout is provisioned at a
# candidate location (tracked in the LICHEN beads: CI oscore provisioning).
set -euo pipefail

rust_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
link="$rust_dir/oscore-fork"

# A directory counts as the oscore fork only if its manifest declares the
# package that [patch.crates-io] replaces: path deps carry no lock checksum,
# so the identity check is all that separates the fork from a wrong clone.
is_oscore_checkout() {
  [[ -f "$1/Cargo.toml" ]] && grep -q '^name = "oscore"' "$1/Cargo.toml"
}

# Honor an existing symlink that already resolves to an oscore checkout,
# even at a path this script does not know about; dangling links fall
# through and get repointed below.
if [[ -L "$link" && -d "$link" ]] && is_oscore_checkout "$link"; then
  exit 0
fi

if [[ -e "$link" && ! -L "$link" ]]; then
  if is_oscore_checkout "$link"; then
    echo "oscore-fork is a real checkout at $link; leaving it in place"
    exit 0
  fi
  echo "error: $link exists but is not an oscore fork checkout" >&2
  exit 1
fi

# First candidate that is an oscore checkout wins.
candidates=(
  "${HOME:-}/crates/oscore"
  "/Volumes/Attic/Desktop/Projects/crates/oscore"
)

for candidate in "${candidates[@]}"; do
  if is_oscore_checkout "$candidate"; then
    ln -sfn "$candidate" "$link"
    echo "linked $link -> $candidate"
    exit 0
  fi
done

echo "error: no oscore fork checkout found; looked for:" >&2
printf '  - %s\n' "${candidates[@]}" >&2
echo "clone the rust-oscore fork with the LICHEN additions (package name" >&2
echo "'oscore') into one of these paths, or add its location to 'candidates'" >&2
echo "in $0" >&2
exit 1
