#!/bin/bash
# B0+: backend (server protocol) circuit fixtures under fixtures/legacy/data/<pin7>/:
#   backend/<name>/{program.json,witness.gz}   artifact compiled+executed with the PINNED nargo
#   instance/backend/<name>/                   bb UltraHonk instance dumps (gitignored; BbRefDump.UltraInstance)
#   backend_vk_hash/<name>                     bb's non-ZK UltraHonk vk_hash per artifact
#
# The committed noir-protocol-circuits/target artifacts predate the crates (stale compiler, removed
# parity crates) and the workspace Nargo.toml is stale too, so artifacts are rebuilt from the crates in
# a scratch copy of the crate closure and executed there with a deterministic Prover.toml.
set -e
F=$(cd "$(dirname "$0")" && pwd)
pin=$(cut -c1-7 "$F/PIN")
REPO=${AZTEC_REPO:-$F/../../aztec-packages2}
NARGO=${NARGO:-$REPO/noir/noir-repo/target/release/nargo}
BB=${BB_BUILD:-$REPO/barretenberg/cpp/build}/bin/bb
DSL=${BB_BUILD:-$REPO/barretenberg/cpp/build}/bin/dsl_tests
CRATES=$REPO/noir-projects/fnd/noir-protocol-circuits/crates
OUT=$F/data/$pin
WS=$(mktemp -d)

# name = crate dir; the Prover.toml written below covers the inbox-parity shape.
for crate in inbox-parity-64; do
  name=${crate//-/_}
  mkdir -p "$WS/crates"
  # crate closure over path dependencies (copied: nargo resolves symlinks back into the stale workspace)
  python3 - "$CRATES" "$WS" "$crate" <<'PY'
import os, re, shutil, sys
root, ws, start = sys.argv[1], sys.argv[2], sys.argv[3]
todo, seen = [start], set()
while todo:
    c = todo.pop()
    if c in seen:
        continue
    seen.add(c)
    for m in re.finditer(r'path\s*=\s*"\.\./([\w-]+)"', open(f'{root}/{c}/Nargo.toml').read()):
        todo.append(m.group(1))
for c in seen:
    if not os.path.exists(f'{ws}/crates/{c}'):
        shutil.copytree(f'{root}/{c}', f'{ws}/crates/{c}')
members = ',\n'.join(f'  "crates/{c}"' for c in sorted(seen))
open(f'{ws}/Nargo.toml', 'w').write(f'[workspace]\nmembers = [\n{members}\n]\n')
PY
  python3 - > "$WS/crates/$crate/Prover.toml" <<'PY'
msgs = ',\n'.join(f'"0x{i+1:064x}"' for i in range(64))
print(f'[inputs]\nmsgs = [\n{msgs}\n]\nnum_msgs = 64\nstart_rolling_hash = "0x0000000000000000000000000000000000000000000000000000000000000001"\nprover_id = "0x0000000000000000000000000000000000000000000000000000000000002a"')
PY
  (cd "$WS/crates/$crate" && "$NARGO" execute witness)
  mkdir -p "$OUT/backend/$name" "$OUT/backend_vk_hash" "$OUT/instance/backend/$name"
  cp "$WS/target/$name.json" "$OUT/backend/$name/program.json"
  cp "$WS/target/witness.gz" "$OUT/backend/$name/witness.gz"
  BBREF_PROGRAM="$OUT/backend/$name/program.json" BBREF_WITNESS="$OUT/backend/$name/witness.gz" \
    BBREF_OUT="$OUT/instance/backend/$name" "$DSL" --gtest_filter='BbRefDump.UltraInstance'
  T=$(mktemp -d)
  "$BB" write_vk --scheme ultra_honk --disable_zk -b "$OUT/backend/$name/program.json" -o "$T"
  cp "$T/vk_hash" "$OUT/backend_vk_hash/$name"
  rm -rf "$T"
done
rm -rf "$WS"

# bb's vk_hash for every server artifact in the pinned target/ (the node's production set), with the
# node's per-circuit flags (yarn-project/bb-prover/src/honk.ts). rollup_tx_base_public needs AVM
# recursion, which the stock bb binary refuses — expected to fail until the AVM is in scope.
TGT=$REPO/noir-projects/fnd/noir-protocol-circuits/target
for j in "$TGT"/parity_*.json "$TGT"/rollup_*.json "$TGT"/chonk_verifier_public.json; do
  name=$(basename "$j" .json)
  case $name in
  *simulated*) continue ;;
  parity_*) flags="--oracle_hash poseidon2" ;;
  rollup_root) flags="--oracle_hash keccak" ;;
  *) flags="--oracle_hash poseidon2 --ipa_accumulation" ;;
  esac
  T=$(mktemp -d)
  # shellcheck disable=SC2086
  if "$BB" write_vk --scheme ultra_honk --disable_zk $flags -b "$j" -o "$T" > "$T/log" 2>&1; then
    cp "$T/vk_hash" "$OUT/backend_vk_hash/$name"
    echo "vk_hash $name"
  else
    echo "vk_hash FAILED for $name (expected for rollup_tx_base_public: AVM)"
  fi
  rm -rf "$T"
done
# B5: UltraKeccak fixtures — bb proofs/VKs for a few acir_tests programs, non-ZK (byte-exact
# oracle) and ZK (verify-only oracle). ACIR_TESTS points at the pinned acir_tests checkout.
ACIR_TESTS=${ACIR_TESTS:-$REPO/barretenberg/acir_tests/acir_tests}
for prog in a_1_mul array_dynamic unsafe_range_constraint; do
  T2=$ACIR_TESTS/$prog/target
  mkdir -p "$OUT/keccak/$prog" "$OUT/keccak/${prog}_zk"
  cp "$T2/program.json" "$T2/witness.gz" "$OUT/keccak/$prog/"
  "$BB" prove --scheme ultra_honk --oracle_hash keccak --disable_zk --write_vk -b "$T2/program.json" \
    -w "$T2/witness.gz" -o "$OUT/keccak/$prog"
  "$BB" prove --scheme ultra_honk --oracle_hash keccak --write_vk -b "$T2/program.json" \
    -w "$T2/witness.gz" -o "$OUT/keccak/${prog}_zk"
  echo "keccak $prog"
done

# Real-witness instance dumps (BbRefDump.UltraInstance + BBREF_IPA + RNG tape). The
# program.json/witness.gz under backend/ for these circuits are HARVESTED from live e2e prover
# runs (BB_DEBUG_OUTPUT_DIR on yarn-project's single-node prover full test) — they cannot be
# rebuilt from the crates (they embed real recursive proofs), only re-harvested. The epoch SHAPE
# decides which circuits appear: the stock test sends one tx per block (tx_base, single-tx block
# root, single-block checkpoint root, root); adding a 3-tx second block to
# `single-node/prover/server/full.test.ts` also yields tx_merge, checkpoint_merge and the
# multi-tx first block root. Adding SEQ_MAX_TX_PER_BLOCK=1 to that same run makes each tx its own
# block, which additionally yields the non-first single-tx block root and the plain (multi-block)
# checkpoint root.
#
# Still unharvested, and NOT reachable by adding txs:
#   block_merge        needs 3+ blocks inside ONE checkpoint (an N-block checkpoint gives N-2 block
#                      merges). This setup advances blocks and checkpoints in lockstep — a 6-tx /
#                      6-block epoch still produced ~1 block per checkpoint — so it needs checkpoint
#                      CADENCE config (the slot/block timetable), not more txs.
#   checkpoint_padding fires only when an epoch has a single checkpoint, leaving the root rollup's
#                      second input unfilled; these runs always produce several checkpoints.
# Both are shape problems a recipe-driven generator (crafted checkpoints over the orchestrator with
# committed real leaf txs) would control directly.
for name in rollup_tx_base_private rollup_block_root_single_tx_first rollup_checkpoint_root_single_block rollup_parity_root rollup_tx_merge rollup_checkpoint_merge rollup_block_root_first rollup_block_root_single_tx rollup_checkpoint_root rollup_block_merge; do
  mkdir -p "$OUT/instance/backend/$name"
  ipa=1
  [ "$name" = rollup_parity_root ] && ipa=   # parity_root is plain HONK recursion, no RollupIO
  mkdir -p "$OUT/instance/backend/$name"
  HARDWARE_CONCURRENCY=1 BB_RNG_TAPE_OUT="$OUT/instance/backend/$name/rng_tape.bin" BBREF_IPA=$ipa \
    BBREF_PROGRAM=$OUT/backend/$name/program.json BBREF_WITNESS=$OUT/backend/$name/witness.gz \
    BBREF_OUT="$OUT/instance/backend/$name" "$DSL" --gtest_filter='BbRefDump.UltraInstance'
  echo "backend witness dump $name"
done

# B6: the harvested rollup_root proven with the seeded engine (keccak; seed-deterministic even
# multithreaded — all draws happen in the single-threaded phases). HARDWARE_CONCURRENCY=1 is NOT
# set: it trips a slab-allocator bound on the 2^23 circuit.
mkdir -p "$OUT/instance/backend/rollup_root/seeded"
BB_RNG_SEED=12345 "$BB" prove --scheme ultra_honk --disable_zk --oracle_hash keccak \
  -b "$OUT/backend/rollup_root/program.json" -w "$OUT/backend/rollup_root/witness.gz" \
  --write_vk -o "$OUT/instance/backend/rollup_root/seeded"
echo "backend witness golden rollup_root"

# B4b: write-VK instance dumps for the chonk-recursion circuits (BbRefDump.UltraWriteVk); witness
# polynomials are mock-random so only precomputed + sigma/id are comparable (backend_write_vk_instance_diff).
for name in chonk_verifier_public rollup_tx_base_private; do
  mkdir -p "$OUT/instance/backend_wvk/$name"
  HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 BBREF_IPA=1 BBREF_PROGRAM=$TGT/$name.json \
    BBREF_OUT="$OUT/instance/backend_wvk/$name" "$DSL" --gtest_filter='BbRefDump.UltraWriteVk'
  echo "backend_wvk $name"
done

# Epoch shapes that produce each harvested circuit (yarn-project single-node prover full.test.ts,
# run with BB_DEBUG_OUTPUT_DIR + an AVM-capable bb; see docs/oracle.md):
#   default PIPELINING_SETUP_OPTS ............ parity_base/root, tx_base_private, block_root_single_tx_first,
#                                              checkpoint_root_single_block, rollup_root
#   + a 3-tx batch in one block .............. tx_merge, checkpoint_merge, block_root_first
#   + maxTxsPerBlock=1 (one tx per block) .... block_root_single_tx, checkpoint_root
#   + blockDurationMs=1000 (8 blocks/slot)
#     and a 5-tx concurrent wave ............. block_merge (5 blocks land in ONE checkpoint;
#                                              an N-block checkpoint yields N-2 block merges)
# Not reachable from this test at any shape: checkpoint_padding (needs an epoch with exactly ONE
# checkpoint; every run here produces several). Its VK is still covered by backend_vk_hash_sweep.

echo "backend fixtures regenerated under $OUT"
