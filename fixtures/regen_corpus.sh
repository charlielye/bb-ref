#!/usr/bin/env bash
# Rebuild the conformance corpus from scratch: one script, from a bare checkout to a corpus file.
#
#   fixtures/regen_corpus.sh [--harvest]
#
# What it does, skipping whatever is already current:
#   1. checks out the pinned aztec-packages (fixtures/PIN) into pin/aztec-packages
#   2. builds it: bb, bb-avm and the labs yarn-project that drives them
#   3. harvests leaf assets -- real client-proven txs and the world state they anchor to -- if
#      they are missing or --harvest is given. Only a protocol change invalidates them.
#   4. runs corpus/driver.ts, which composes the recipe epochs over those assets and proves them
#      through ONE long-lived bb behind the capture proxy
#   5. writes corpus/rollup-<pin>.corpus.zst
#
# The result is the exact bytes the prover sent to bb, so `conformance.sh` and `bench.sh` replay it
# into bb or bb-ref with no format in between.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PIN=$(cat fixtures/PIN)
TREE=$ROOT/pin/aztec-packages
ASSETS=$ROOT/fixtures/corpus/leaf-assets
OUT=$ROOT/fixtures/corpus
BB=$TREE/barretenberg/cpp/build/bin/bb-avm
ACVM=$TREE/noir/noir-repo/target/release/acvm
YP=$TREE/labs/yarn-project

step() { printf '\n=== %s\n' "$1"; }

step "pinned tree @ ${PIN:0:9}"
git submodule update --init pin/aztec-packages
git -C "$TREE" fetch --depth 50 origin "$PIN" 2>/dev/null || true
git -C "$TREE" checkout -q "$PIN"
git -C "$TREE" submodule update --init --force --depth 1 \
    l1-contracts/lib/openzeppelin-contracts l1-contracts/lib/forge-std \
    barretenberg/sol/lib/forge-std barretenberg/sol/lib/solidity-stringutils

# labs-yarn-project builds bb and bb.js from THIS tree and portals them into labs. Running labs'
# own bootstrap instead would install the published nightly bb.js and silently prove against a
# different bb than the one under test.
step "building bb + labs yarn-project (first run takes ~20 min; cached afterwards)"
make -C "$TREE" labs-yarn-project
ninja -C "$TREE/barretenberg/cpp/build" bb-avm

# node resolves bare specifiers upward from the importing file, so the driver -- which lives here,
# not in the tree -- needs the built workspace's modules reachable from its own directory.
ln -sfn "$YP/node_modules" "$OUT/node_modules"

if [ ! -d "$ASSETS/txs" ] || [ "${1:-}" = "--harvest" ]; then
    step "harvesting leaf txs and world state (~6 min)"
    # Real client-proven txs are mandatory: a mock tx carries a random ChonkProof, which fails the
    # tx-base circuit's recursive verification inside bb.
    rm -rf "$ASSETS"; mkdir -p "$ASSETS"
    # The chain runs on fake proofs for speed; only the unsent txs are proven for real. Each needs
    # its own sender -- txs proven from one account against the same PXE state select the same
    # notes and collide on nullifiers.
    ( cd "$YP/end-to-end" && \
      BBREF_HARVEST_OUT=$ASSETS BBREF_FUNDED_ACCOUNTS=11 FAKE_PROOFS=1 \
      BB_BINARY_PATH=$BB ACVM_BINARY_PATH=$ACVM \
      yarn test:e2e src/single-node/prover/server/bbref_harvest.test.ts )
else
    echo "leaf assets present ($(ls "$ASSETS/txs" | wc -l) txs) -- pass --harvest to refresh"
fi

step "proving the recipe epochs into a corpus (~7 min)"
FRAMES=$(mktemp -d); trap 'rm -rf "$FRAMES"' EXIT
( cd "$OUT" && \
  BBREF_CORPUS_ASSETS=$ASSETS \
  BB_BINARY_PATH=$ROOT/fixtures/bb_capture_proxy.py BB_REAL=$BB ACVM_BINARY_PATH=$ACVM \
  IPC_FRAME_CAPTURE_DIR=$FRAMES BB_POOL_SIZE=1 BB_RNG_SEED=12345 \
  node --experimental-strip-types --experimental-transform-types --no-warnings driver.ts )

step "packing"
# One pooled bb means one connection carries the whole rollup; anything else is a stray client.
STREAM=$(ls -S "$FRAMES"/*.req | head -1)
python3 fixtures/replay.py --list "$STREAM" | tail -5
zstd -3 -T0 -q -f -o "$OUT/rollup-${PIN:0:7}.corpus.zst" "$STREAM"
printf '\ncorpus: %s (%s)\n' "$OUT/rollup-${PIN:0:7}.corpus.zst" \
    "$(du -h "$OUT/rollup-${PIN:0:7}.corpus.zst" | cut -f1)"
echo "verify it:  fixtures/conformance.sh $OUT/rollup-${PIN:0:7}.corpus.zst"
