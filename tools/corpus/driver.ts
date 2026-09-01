// BBREF-CORPUS: the direct corpus generator. Composes the exact epoch shapes the conformance
// corpus needs — jaws' mkfixtures recipe table, private-only — out of REAL harvested txs on top of
// the harvested chain snapshot, and proves them with the real BBNativeRollupProver. Run with
// BB_POOL_SIZE=1 and bbBinaryPath pointed at the capture proxy, and the whole rollup lands on ONE
// recorded bb connection, in recipe order.
//
// The leaf assets come from end-to-end's bbref_harvest.test.ts: unsent client-proven txs (their
// nullifiers are unspent) plus the world state of the chain they anchor to. Mock txs are useless
// here: their random ChonkProof fails the tx-base circuit's recursive verification in bb.
//
// Merge layers follow the reduce-to-top-2 rule: an N-leaf tree yields N-2 merges, so merges need
// >=3 leaves. Epoch 1: cp0 (1 block / 1 tx + L1-to-L2 messages) gives parity base+root, the
// single-tx-first block root and the single-block checkpoint root; cp1 (blocks of 0/3/1 txs) gives
// the empty-tx-first root, a tx merge, a block merge and the plain+single-tx roots; cp2 (2/1)
// gives the multi-tx-first root and, with three checkpoints, the checkpoint merge. Epoch 2 (one
// checkpoint) exists solely for CheckpointPaddingRollup, which fires only when a lone checkpoint
// leaves the root rollup's second input unfilled.
//
// Driven by ../regen/corpus.sh, which builds the pinned tree, runs the harvest when the leaf
// assets are missing, and starts this with the environment it needs. Plain node, no test runner:
//   node --experimental-strip-types --experimental-transform-types driver.ts
import { BBNativeRollupProver } from '@aztec/bb-prover';
import { BackendType, Barretenberg, BarretenbergSync } from '@aztec/bb.js';
import { PAIRING_POINTS_SIZE } from '@aztec/constants';
import { BlockNumber, CheckpointNumber, EpochNumber, SlotNumber } from '@aztec/foundation/branded-types';
import { SerialQueue } from '@aztec/foundation/queue';
import { getVKTreeRoot } from '@aztec/noir-protocol-circuits-types/vk-tree';
import { protocolContractsHash } from '@aztec/protocol-contracts';
import { AztecAddress } from '@aztec/stdlib/aztec-address';
import { GasFees } from '@aztec/stdlib/gas';
import { CheckpointConstantData } from '@aztec/stdlib/rollup';
import { GlobalVariables } from '@aztec/stdlib/tx';
import type { FieldsOf } from '@aztec/foundation/types';
import { Fr } from '@aztec/foundation/curves/bn254';
import { EthAddress } from '@aztec/foundation/eth-address';
import { createLogger } from '@aztec/foundation/log';
import { PublicProcessorFactory } from '@aztec/simulator/server';
import { PublicSimulatorConfig } from '@aztec/stdlib/avm';
import { L2Block } from '@aztec/stdlib/block';
import { PublicDataTreeLeaf } from '@aztec/stdlib/trees';
import { MerkleTreeId } from '@aztec/stdlib/trees';
import type { BlockHeader, ProcessedTx, Tx } from '@aztec/stdlib/tx';
import { Tx as TxClass } from '@aztec/stdlib/tx';
import { NativeWorldStateService } from '@aztec/world-state/native';

import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { LightweightCheckpointBuilder } from '@aztec/prover-client/light';
import { buildFinalBlobChallenges } from '@aztec/prover-client/helpers';
import { CheckpointSubTreeOrchestrator } from '@aztec/prover-client/orchestrator';
import { ChonkCache } from '@aztec/prover-client/orchestrator';
import { type CheckpointTopTreeData, TopTreeOrchestrator } from '@aztec/prover-client/orchestrator';

/** Constants every circuit in a checkpoint shares. The defaults stand in only where the harvested
 * chain does not pin a value; callers MUST override chainId, version and gas fees with the tip's,
 * or the tx-base circuits assert against a chain they were not proven for. */
const makeCheckpointConstants = (
  slotNumber: number,
  overrides: Partial<FieldsOf<CheckpointConstantData>> = {},
) =>
  CheckpointConstantData.from({
    chainId: Fr.ZERO,
    version: Fr.ZERO,
    vkTreeRoot: getVKTreeRoot(),
    protocolContractsHash,
    proverId: Fr.ZERO,
    slotNumber: SlotNumber(slotNumber),
    coinbase: EthAddress.ZERO,
    feeRecipient: AztecAddress.ZERO,
    gasFees: GasFees.empty(),
    ...overrides,
  });

const makeGlobals = (
  blockNumber: number,
  slotNumber = blockNumber,
  overrides: Partial<FieldsOf<GlobalVariables> & FieldsOf<CheckpointConstantData>> = {},
) => {
  const constants = makeCheckpointConstants(slotNumber, overrides);
  return GlobalVariables.from({
    chainId: constants.chainId,
    version: constants.version,
    blockNumber: BlockNumber(blockNumber),
    slotNumber: SlotNumber(slotNumber),
    timestamp: BigInt(blockNumber * 123),
    coinbase: constants.coinbase,
    feeRecipient: constants.feeRecipient,
    gasFees: constants.gasFees,
    ...overrides,
  });
};

const makeDeferredJobQueue = (concurrency = 10) => {
  const queue = new SerialQueue();
  queue.start(concurrency);
  return queue;
};

const ASSETS = process.env.BBREF_CORPUS_ASSETS;
const ARCHIVE_TREE_ID = MerkleTreeId.ARCHIVE;

const log = createLogger('bbref-corpus');

interface Recipe {
  txsPerBlock: number[];
  numL1ToL2Messages: number;
}

const EPOCHS: Recipe[][] = [
  [
    { txsPerBlock: [1], numL1ToL2Messages: 2 },
    { txsPerBlock: [0, 3, 1], numL1ToL2Messages: 0 },
    { txsPerBlock: [2, 1], numL1ToL2Messages: 0 },
  ],
  [{ txsPerBlock: [1], numL1ToL2Messages: 0 }],
];

function loadAssets(dir: string) {
  const chainDir = path.join(dir, 'chain');
  const blocks = readdirSync(chainDir)
    .filter(f => /^block-\d+\.bin$/.test(f))
    .sort()
    .map(f => L2Block.fromBuffer(readFileSync(path.join(chainDir, f))));
  const txsDir = path.join(dir, 'txs');
  const txs = readdirSync(txsDir)
    .filter(f => f.endsWith('.bin'))
    .sort()
    .map(f => TxClass.fromBuffer(readFileSync(path.join(txsDir, f))));
  const info = JSON.parse(readFileSync(path.join(dir, 'node-info.json'), 'utf8')) as {
    rollupAddress: string;
    tipInboxRollingHash?: string;
    genesis?: {
      genesisTimestamp: string;
      prefilledPublicData: [string, string][];
      prefilledNullifiers?: string[];
    };
  };
  return { blocks, txs, info };
}

/** Open whichever harvested state snapshot verifies against the tip block's archive root. */
async function openWorldState(dir: string, rollupAddress: EthAddress, tip: L2Block, genesis: any) {
  const candidates = readdirSync(dir).filter(f => f.startsWith('state-candidate-'));
  const mapSizeKb = 10 * 1024 * 1024;
  const treeMapSizes = {
    archiveTreeMapSizeKb: mapSizeKb,
    nullifierTreeMapSizeKb: mapSizeKb,
    noteHashTreeMapSizeKb: mapSizeKb,
    messageTreeMapSizeKb: mapSizeKb,
    publicDataTreeMapSizeKb: mapSizeKb,
  };
  for (const candidate of candidates) {
    // Opened through a copy: appending crafted checkpoints writes to the world state, and doing
    // that in place would corrupt the committed snapshot for the next run.
    const work = mkdtempSync(path.join(tmpdir(), 'bbref-corpus-state-'));
    cpSync(path.join(dir, candidate), work, { recursive: true });
    const cleanup = () => rmSync(work, { recursive: true, force: true });
    const worldState = await NativeWorldStateService.new(rollupAddress, work, treeMapSizes, genesis);
    const info = await worldState.getCommitted().getTreeInfo(ARCHIVE_TREE_ID);
    const got = `0x${Buffer.from(info.root).toString('hex')}`;
    if (got === tip.archive.root.toString()) {
      log.info(`world state: ${candidate} verified against tip block ${tip.number}`);
      return { worldState, cleanup };
    }
    await worldState.close();
    cleanup();
    log.warn(`world state: ${candidate} archive root ${got} != ${tip.archive.root.toString()}, trying next`);
  }
  throw new Error('no harvested state candidate matches the tip block archive root');
}

async function main() {
  if (!ASSETS) {
    throw new Error('set BBREF_CORPUS_ASSETS to the harvested leaf assets (see ../regen/corpus.sh)');
  }
  {
    // Tx deserialization decompresses chonk proofs through the bb.js singleton (BB_BINARY_PATH,
    // which must be the REAL bb — only the prover's traffic goes through the capture proxy).
    await Barretenberg.initSingleton({ backend: BackendType.NativeUnixSocket });
    await BarretenbergSync.initSingleton();

    const { blocks, txs, info } = loadAssets(ASSETS);
    const tip = blocks[blocks.length - 1];
    const rollupAddress = EthAddress.fromString(info.rollupAddress);
    log.info(`assets: ${blocks.length} blocks, ${txs.length} txs, tip block ${tip.number}`);

    const totalNeeded = EPOCHS.flat().reduce((a, r) => a + r.txsPerBlock.reduce((x, y) => x + y, 0), 0);
    if (txs.length < totalNeeded) {
      throw new Error(`need ${totalNeeded} txs, harvested ${txs.length}`);
    }

    const genesis = info.genesis && {
      genesisTimestamp: BigInt(info.genesis.genesisTimestamp),
      prefilledPublicData: info.genesis.prefilledPublicData.map(
        ([slot, value]) => new PublicDataTreeLeaf(Fr.fromString(slot), Fr.fromString(value)),
      ),
      prefilledNullifiers: info.genesis.prefilledNullifiers?.map(n => Fr.fromString(n)),
    };
    const { worldState, cleanup } = await openWorldState(ASSETS, rollupAddress, tip, genesis);

    const prover = await BBNativeRollupProver.new({
      bbBinaryPath: process.env.BBREF_BB ?? process.env.BB_BINARY_PATH!,
      bbWorkingDirectory: mkdtempSync(path.join(tmpdir(), 'bbref-corpus-bb-')),
      bbSkipCleanup: false,
      numConcurrentIVCVerifiers: 1,
      bbIVCConcurrency: 1,
      bbChonkVerifyMaxBatch: 16,
      bbChonkVerifyConcurrency: 1,
      acvmBinaryPath: process.env.ACVM_BINARY_PATH!,
      acvmWorkingDirectory: mkdtempSync(path.join(tmpdir(), 'bbref-corpus-acvm-')),
    });

    // --- Checkpoint composition (jaws' BenchCheckpointBuilder, on pin APIs) ---
    // Constants must be the CHAIN's: a tx asserts its maxFeesPerGas covers the block's, the
    // kernel's chainId/version are checked against the block's, and the timeline must continue
    // forward from the tip or the rollup circuits reject the timestamps.
    const tipGlobals = tip.header.globalVariables;
    const first = blocks[0].header.globalVariables;
    const slotDuration =
      blocks.length > 1 && Number(tipGlobals.slotNumber) > Number(first.slotNumber)
        ? (BigInt(tipGlobals.timestamp) - BigInt(first.timestamp)) /
          BigInt(Number(tipGlobals.slotNumber) - Number(first.slotNumber))
        : 12n;

    let nextBlockNumber = Number(tip.number) + 1;
    let nextCheckpointNumber = Number(tip.checkpointNumber) + 1;
    const tipCheckpointNumber = Number(tip.checkpointNumber);
    const headers = new Map<number, BlockHeader>([[Number(tip.number), tip.header]]);
    const checkpointOutHashes: Fr[] = [];
    let currentInboxRollingHash = info.tipInboxRollingHash ? Fr.fromString(info.tipInboxRollingHash) : Fr.ZERO;

    // Private-only txs never touch the avm simulator or the contract data source; the processor
    // is still the real one so fees, tree insertions and validation are production logic.
    const processorFactory = new PublicProcessorFactory(
      undefined as unknown as ConstructorParameters<typeof PublicProcessorFactory>[0],
      undefined as unknown as ConstructorParameters<typeof PublicProcessorFactory>[1],
    );

    const txPool = [...txs];
    const makeCheckpoint = async (recipe: Recipe) => {
      const numBlocks = recipe.txsPerBlock.length;
      const checkpointNumber = nextCheckpointNumber++;
      const slotsAhead = checkpointNumber - tipCheckpointNumber;
      const slotNumber = Number(tipGlobals.slotNumber) + slotsAhead;
      const timestamp = BigInt(tipGlobals.timestamp) + slotDuration * BigInt(slotsAhead);
      const constants = makeCheckpointConstants(slotNumber, {
        gasFees: tipGlobals.gasFees,
        chainId: tipGlobals.chainId,
        version: tipGlobals.version,
      });

      const l1ToL2Messages = Array.from({ length: recipe.numL1ToL2Messages }, (_, i) => new Fr(slotNumber * 100 + i));

      const startBlockNumber = nextBlockNumber;
      const previousBlockHeader = headers.get(startBlockNumber - 1)!;
      const blockGlobals = Array.from({ length: numBlocks }, (_, i) =>
        makeGlobals(startBlockNumber + i, slotNumber, {
          chainId: tipGlobals.chainId,
          version: tipGlobals.version,
          coinbase: constants.coinbase,
          feeRecipient: constants.feeRecipient,
          gasFees: constants.gasFees,
          timestamp,
        }),
      );
      nextBlockNumber += numBlocks;

      // Process each block's txs sequentially against a running fork: real fee deduction and
      // tree insertions, so each block sees the previous block's state.
      const fork = await worldState.fork();
      const processedPerBlock: ProcessedTx[][] = [];
      for (let i = 0; i < numBlocks; i++) {
        const take: Tx[] = txPool.splice(0, recipe.txsPerBlock[i]);
        if (take.length === 0) {
          processedPerBlock.push([]);
          continue;
        }
        const processor = processorFactory.create(
          fork,
          blockGlobals[i],
          PublicSimulatorConfig.from({
            skipFeeEnforcement: false,
            collectDebugLogs: false,
            collectHints: true,
            collectPublicInputs: true,
            collectStatistics: false,
          }),
        );
        const [processed, failed] = await processor.process(take);
        if (failed.length > 0) {
          throw new Error(
            `checkpoint ${checkpointNumber} block ${i}: ${failed.length} tx(s) failed processing: ` +
              failed.map(f => `${f.error}`).join('; '),
          );
        }
        processedPerBlock.push(processed);
      }

      const cleanFork = await worldState.fork();
      const startInboxRollingHash = currentInboxRollingHash;
      const builder = LightweightCheckpointBuilder.startNewCheckpoint(
        CheckpointNumber(checkpointNumber),
        { ...constants, timestamp },
        [...checkpointOutHashes],
        startInboxRollingHash,
        cleanFork,
      );

      const builtBlocks: { header: BlockHeader; txs: ProcessedTx[] }[] = [];
      for (let i = 0; i < numBlocks; i++) {
        const { block } = await builder.addBlock(blockGlobals[i], processedPerBlock[i], i === 0 ? l1ToL2Messages : [], {
          insertTxsEffects: true,
        });
        headers.set(Number(block.number), block.header);
        await worldState.handleL2BlockAndMessages(block, block.indexWithinCheckpoint === 0 ? l1ToL2Messages : []);
        builtBlocks.push({ header: block.header, txs: processedPerBlock[i] });
      }

      const checkpoint = await builder.completeCheckpoint();
      checkpointOutHashes.push(checkpoint.getCheckpointOutHash());
      currentInboxRollingHash = checkpoint.header.inboxRollingHash;
      log.info(`built checkpoint ${checkpointNumber}: ${numBlocks} blocks`);
      return { constants, checkpoint, blocks: builtBlocks, l1ToL2Messages, previousBlockHeader, startInboxRollingHash };
    };

    // --- Compose then prove, epoch by epoch (the bb_prover_full_rollup driving pattern) ---
    try {
      for (let e = 0; e < EPOCHS.length; e++) {
        const epochNumber = EpochNumber(e + 1);
        const built = [];
        for (const recipe of EPOCHS[e]) {
          built.push(await makeCheckpoint(recipe));
        }

        const finalBlobChallenges = await buildFinalBlobChallenges(built.map(c => c.checkpoint.toBlobFields()));
        const chonkCache = new ChonkCache();
        const subTrees: CheckpointSubTreeOrchestrator[] = [];
        const topTreeData: CheckpointTopTreeData[] = [];
        try {
          for (const [checkpointIndex, cp] of built.entries()) {
            log.info(`proving checkpoint ${checkpointIndex} of epoch ${e + 1}`);
            const subTree = await CheckpointSubTreeOrchestrator.start(
              worldState,
              prover,
              EthAddress.ZERO,
              chonkCache,
              epochNumber,
              /* cancelJobsOnStop */ false,
              makeDeferredJobQueue(),
              cp.constants,
              cp.l1ToL2Messages,
              cp.startInboxRollingHash,
              cp.blocks.length,
              cp.previousBlockHeader,
            );
            subTrees.push(subTree);

            for (const block of cp.blocks) {
              const { blockNumber, timestamp } = block.header.globalVariables;
              await subTree.startNewBlock(blockNumber, timestamp, block.txs.length, cp.l1ToL2Messages);
              if (block.txs.length > 0) {
                await subTree.addTxs(block.txs);
              }
              await subTree.setBlockCompleted(blockNumber, block.header);
            }

            topTreeData.push({
              subTreeProofs: subTree
                .getSubTreeResult()
                .then(r => ({ blockProofOutputs: r.blockProofOutputs, inboxParityProof: r.inboxParityProof })),
              l2ToL1MsgsPerBlock: cp.blocks.map(b => b.txs.map(tx => tx.txEffect.l2ToL1Msgs)),
              blobFields: cp.checkpoint.toBlobFields(),
              previousBlockHeader: cp.previousBlockHeader,
              previousArchiveSiblingPath: subTree.getPreviousArchiveSiblingPath(),
            });
          }

          log.info(`proving top tree of epoch ${e + 1}`);
          const topTree = new TopTreeOrchestrator(prover, EthAddress.ZERO, makeDeferredJobQueue());
          let epochResult;
          try {
            epochResult = await topTree.prove(epochNumber, built.length, finalBlobChallenges, topTreeData);
          } finally {
            await topTree.stop();
          }

          epochResult.proof.numPublicInputs -= PAIRING_POINTS_SIZE;
          // Proving the root is not enough: a corpus whose goldens are wrong is worse than none.
          await prover.verifyProof('RootRollupArtifact', epochResult.proof);
          log.info(`epoch ${e + 1} root proof verified`);
        } finally {
          await Promise.all(subTrees.map(s => s.stop()));
        }
      }
    } finally {
      await worldState.close();
      cleanup();
    }
  }
}

main().then(
  () => process.exit(0),
  err => {
    log.error(`corpus generation failed: ${err?.stack ?? err}`);
    process.exit(1);
  },
);
