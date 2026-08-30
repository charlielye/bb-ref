#!/bin/bash
# Rebuild the conformance corpus: one shaped, seeded epoch, captured as the wire frames the prover
# stack exchanges with bb. The corpus is that recording — replaying it against bb and against
# bb-ref and diffing the response streams is the conformance suite.
#
# This is a MAINTAINER task, run once per pin (or to extend circuit coverage). Running the
# conformance suite needs none of it: that only wants the committed corpus plus `pin/build.sh`.
#
#   ./fixtures/regen_corpus.sh <output-dir>
#
# Preconditions (see "Status" below — this script does not yet run end to end):
#   - pin/aztec-packages checked out and built:  ./pin/build.sh --noir
#   - the pin's yarn-project built. At this pin it lives in the `labs` submodule:
#       git -C pin/aztec-packages submodule update --init --depth 1 labs
#       (then labs' own bootstrap; see labs-patches/ for the overlay it expects)
#   - an AVM-capable bb, because the epoch proves public txs too:
#       ninja -C pin/aztec-packages/barretenberg/cpp/build bb-avm
#
# Status: the frame capture this relies on lives in ipc-runtime and fires only when the client
# speaks it — true from the pin branch onward, not at the older commit the dev fixtures use. The
# epoch shaping below is still a source edit rather than config (see SHAPE), so the run is not yet
# a single command. Both are tracked in docs/conformance.md.
set -euo pipefail

out=${1:?usage: regen_corpus.sh <output-dir>}
here=$(cd "$(dirname "$0")" && pwd)
repo=${AZTEC_REPO:-$here/../pin/aztec-packages}
e2e=$repo/labs/yarn-project/end-to-end
[ -d "$e2e" ] || e2e=$repo/yarn-project/end-to-end   # pre-labs layout

mkdir -p "$out"

# SHAPE. A checkpoint is a slot's worth of blocks, so coverage is governed by two knobs that must
# move together — `blockDurationMs` sets the per-slot block budget (3000 -> 2, 2000 -> 3,
# 1000 -> 8), and the txs-per-block cap must be lowered or a concurrent wave collapses into one
# block and no blocks accumulate. blockDurationMs=1000 + maxTxsPerBlock=1 + a 5-tx wave of
# DISTINCT calls (identical private transfers collide on nullifiers) gives a 5-block checkpoint,
# hence block merges (an N-block checkpoint yields N-2). fixtures/regen_backend.sh maps each shape
# to the circuits it produces.
#
# `rollup_checkpoint_padding` is NOT reachable from any live-chain shape: it needs an epoch holding
# exactly one checkpoint, while the sequencer cuts one per slot and fills idle slots with empty
# blocks. It comes from the recipe-driven generator instead (docs/conformance.md).
echo "regen_corpus: shaping is currently a source edit in $e2e/src/single-node/prover/server/full.test.ts"
echo "              (TIMEOUT, blockDurationMs, maxTxsPerBlock) — see SHAPE in this script."

# CAPTURE. IPC_FRAME_CAPTURE_DIR records what the *client* sends and receives, so the corpus is
# made without instrumenting the server under test. Streams are per connection and labelled by
# endpoint, so bb's traffic is separable from the world-state/AVM services the same process drives.
# BB_RNG_SEED makes the run reproducible; note ZK operations additionally need concurrency 1 to
# replay deterministically, which the corpus manifest records per operation.
export BB_RNG_SEED=${BB_RNG_SEED:-12345}
export IPC_FRAME_CAPTURE_DIR="$out/frames"
export BB_BINARY_PATH=${BB_BINARY_PATH:-$repo/barretenberg/cpp/build/bin/bb-avm}
export ACVM_BINARY_PATH=${ACVM_BINARY_PATH:-$repo/noir/noir-repo/target/release/acvm}
export LOG_LEVEL=info
mkdir -p "$IPC_FRAME_CAPTURE_DIR"

echo "regen_corpus: proving one epoch (this is a real proving run; expect tens of minutes)"
( cd "$e2e" && yarn test:e2e src/single-node/prover/server/full.test.ts ) 2>&1 | tee "$out/run.log"

echo "regen_corpus: captured streams:"
ls -la "$IPC_FRAME_CAPTURE_DIR"
echo
echo "Next: keep the bb-labelled .req/.resp pair(s), record the per-operation thread policy in a"
echo "manifest, and check coverage against the in-scope circuit list before committing."
