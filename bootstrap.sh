#!/bin/bash
# Resolve ./bin/bb — the barretenberg the differential tests compare against. Everything in this
# repo goes through that one path, so the tiers below are interchangeable from a test's point of
# view.
#
#   ./bootstrap.sh              # tier 1: download the released bb named in pin/VERSION
#   ./bootstrap.sh --local      # tier 2/3: symlink the bb built from pin/aztec-packages
#
# Tier 1 is the common case and needs nothing else: replay carries its own witnesses, so no
# toolchain, no acvm, no submodule. Use --local when testing an unreleased barretenberg, or when
# rebuilding the corpus.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/bin"

use_local=false
[[ ${1:-} == "--local" ]] && use_local=true

built=${AZTEC_REPO:-$here/pin/aztec-packages}/barretenberg/cpp/build/bin/bb

# A built pin wins when asked for, and is also the sane default if it is already there: a developer
# who built it means to test it.
if $use_local || [ -x "$built" ]; then
  if [ ! -x "$built" ]; then
    echo "bootstrap: no built bb at $built" >&2
    echo "           git submodule update --init --depth 1 pin/aztec-packages && ./pin/build.sh" >&2
    exit 1
  fi
  ln -sfn "$built" "$here/bin/bb"
  echo "bootstrap: bin/bb -> $built"
  exit 0
fi

version=$(cat "$here/pin/VERSION" 2>/dev/null || true)
if [ -z "$version" ]; then
  echo "bootstrap: pin/VERSION is empty — the pin is a branch, not a release, so there is no" >&2
  echo "           binary to download yet. Build it instead:" >&2
  echo "           git submodule update --init --depth 1 pin/aztec-packages && ./pin/build.sh" >&2
  exit 1
fi

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) asset=barretenberg-amd64-linux.tar.gz ;;
Linux-aarch64) asset=barretenberg-arm64-linux.tar.gz ;;
Darwin-x86_64) asset=barretenberg-amd64-darwin.tar.gz ;;
Darwin-arm64) asset=barretenberg-arm64-darwin.tar.gz ;;
*)
  echo "bootstrap: no released bb for $(uname -s)-$(uname -m); use --local" >&2
  exit 1
  ;;
esac

url=https://github.com/AztecProtocol/aztec-packages/releases/download/$version/$asset
echo "bootstrap: downloading $version $asset"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/bb.tar.gz"
tar -xzf "$tmp/bb.tar.gz" -C "$tmp"
# The archive layout has moved before now; take the binary wherever it landed.
found=$(find "$tmp" -type f -name bb -perm -u+x | head -1)
[ -n "$found" ] || { echo "bootstrap: no bb binary inside $asset" >&2; exit 1; }
install -m 0755 "$found" "$here/bin/bb"
echo "bootstrap: bin/bb <- $version"
