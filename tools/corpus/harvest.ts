// Harvest the leaf assets the corpus driver replays — real client-proven txs that are NEVER sent
// (so their nullifiers stay spendable), plus a snapshot of the chain they anchor to. The chain
// itself runs on fake proofs for speed; only the unsent txs are proven for real, through a
// dedicated proving PXE. Each unsent tx has its OWN sender: txs proven against the same PXE state
// from one sender select the same notes and collide on nullifiers.
//
// Driven by ../regen/regen_corpus.sh; plain node against the built pin workspace (the node_modules
// symlink beside this file), no test runner and no changes to the pinned tree:
//   BBREF_HARVEST_OUT=<dir> FAKE_PROOFS=1 node --experimental-strip-types \
//     --experimental-transform-types harvest.ts
import { generateSchnorrAccounts } from '@aztec-labs/accounts/testing';
import { EthAddress } from '@aztec-labs/aztec.js/addresses';
import { BackendType, Barretenberg } from '@aztec-foundation/bb.js';
import { BlockNumber, CheckpointNumber } from '@aztec-labs/foundation/branded-types';
import { jsonStringify } from '@aztec-labs/foundation/json-rpc';
import { createLogger } from '@aztec-labs/foundation/log';
import { TokenContract } from '@aztec-labs/noir-contracts.js/Token';
import { L2Block } from '@aztec-labs/stdlib/block';

import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

// The e2e fixtures are consumed as the compiled package ('./*' maps into dest/).
import { PIPELINING_SETUP_OPTS } from '@aztec-labs/end-to-end/fixtures/fixtures.js';
import { setup, setupPXEAndGetWallet } from '@aztec-labs/end-to-end/fixtures/setup.js';
import { proveInteraction } from '@aztec-labs/end-to-end/test-wallet/utils.js';

const OUT = process.env.BBREF_HARVEST_OUT;
const NUM_SENDERS = 9;
const logger = createLogger('bbref-harvest');

// The e2e fixtures name their logger via jest's `expect.getState()`; outside jest a shim suffices.
(globalThis as { expect?: unknown }).expect = {
  getState: () => ({ currentTestName: 'bbref_harvest harvest', testPath: 'bbref_harvest' }),
};

async function main() {
  if (!OUT) {
    throw new Error('set BBREF_HARVEST_OUT (see ../regen/regen_corpus.sh)');
  }
  // 2 base roles (admin, recipient) + NUM_SENDERS independent senders.
  const fundedAccounts = await generateSchnorrAccounts(2 + NUM_SENDERS);
  const context = await setup(0, {
    ...PIPELINING_SETUP_OPTS,
    startProverNode: true,
    coinbase: EthAddress.random(),
    fundSponsoredFPC: true,
    additionallyFundedAccounts: fundedAccounts,
    l1ContractsArgs: { realVerifier: false },
  });
  try {
    // The chain's wallet knows the funded accounts; deploy and mint the token the txs will move.
    const wallet = context.wallet;
    for (const { secret, salt, signingKey } of fundedAccounts) {
      await wallet.createSchnorrInitializerlessAccount(secret, salt, signingKey);
    }
    const accounts = fundedAccounts.map(a => a.address);
    const admin0 = accounts[0];
    logger.info('Deploying token and minting');
    const { contract: asset, instance: assetInstance } = await TokenContract.deploy(
      wallet,
      admin0,
      'BBRefToken',
      'BBRT',
      18,
    ).send({ from: admin0 });
    await asset.methods.mint_to_public(admin0, 20000n).send({ from: admin0 });
    await asset.methods.transfer_to_private(admin0, 10000n).send({ from: admin0 });

    // Our proving PXE needs the native backend; the fixture skipped it under fake proofs.
    await Barretenberg.initSingleton({ backend: BackendType.NativeUnixSocket });

    const admin = accounts[0];
    const recipient = accounts[1];
    const senders = accounts.slice(2, 2 + NUM_SENDERS);
    if (senders.length !== NUM_SENDERS) {
      throw new Error('needs BBREF_FUNDED_ACCOUNTS=11');
    }

    // Fund each sender with private tokens from the admin's minted balance (fake proofs: fast).
    // Sequential sends from one sender are fine — each is mined before the next is simulated.
    for (const [i, sender] of senders.entries()) {
      logger.info(`Funding sender ${i + 1}/${NUM_SENDERS} privately`);
      await asset.methods.transfer(sender, 500n).send({ from: admin });
    }

    // A dedicated real-proving PXE: the chain stays on fake proofs, these txs do not.
    const { wallet: realWallet, teardown: realTeardown } = await setupPXEAndGetWallet(
      context.aztecNode,
      context.aztecNode,
      { proverEnabled: true },
      undefined,
      'pxe-bbref-harvest',
    );
    try {
      await realWallet.registerContract(assetInstance, TokenContract.artifact);
      for (const a of fundedAccounts) {
        await realWallet.createSchnorrInitializerlessAccount(a.secret, a.salt, a.signingKey);
      }
      const provenAsset = TokenContract.at(asset.address, realWallet);

      mkdirSync(path.join(OUT, 'txs'), { recursive: true });
      // Distinct senders make the proofs independent; prove in parallel.
      const proven = await Promise.all(
        senders.map((sender, i) =>
          proveInteraction(realWallet, provenAsset.methods.transfer(recipient, 100n + BigInt(i)), { from: sender }),
        ),
      );
      proven.forEach((tx, i) => {
        writeFileSync(path.join(OUT, 'txs', `tx-wpriv-${String(i).padStart(2, '0')}.bin`), tx.toBuffer());
      });
      logger.info(`Saved ${proven.length} unsent proven txs`);
    } finally {
      await realTeardown();
    }

    // Quiesce the sequencer so the snapshot is taken at a stable tip.
    await context.aztecNodeAdmin!.setConfig({ minTxsPerBlock: 100 });
    await new Promise(r => setTimeout(r, 15_000));

    const tip = Number(await context.aztecNode.getBlockNumber());
    // getBlocks caps each call at MAX_RPC_BLOCKS_LEN (50); page through.
    const blockResponses = [];
    for (let from = 1; from <= tip; from += 50) {
      blockResponses.push(
        ...(await context.aztecNode.getBlocks(BlockNumber(from), Math.min(50, tip - from + 1), {
          includeTransactions: true,
        })),
      );
    }
    mkdirSync(path.join(OUT, 'chain'), { recursive: true });
    for (const br of blockResponses) {
      const block = new L2Block(br.archive, br.header, br.body!, br.checkpointNumber, br.indexWithinCheckpoint);
      writeFileSync(
        path.join(OUT, 'chain', `block-${String(Number(block.number)).padStart(4, '0')}.bin`),
        block.toBuffer(),
      );
    }

    // The next crafted checkpoint chains its inbox rolling hash from the tip checkpoint's.
    const tipCheckpointNumber = Number(blockResponses[blockResponses.length - 1].checkpointNumber);
    const [tipCheckpoint] = await context.aztecNode.getCheckpoints(CheckpointNumber(tipCheckpointNumber), 1, {});

    writeFileSync(
      path.join(OUT, 'node-info.json'),
      jsonStringify({
        rollupAddress: context.deployL1ContractsValues.l1ContractAddresses.rollupAddress.toString(),
        tipBlock: tip,
        tipCheckpointNumber,
        tipInboxRollingHash: tipCheckpoint?.header.inboxRollingHash.toString(),
        tipCheckpointOutHash: tipCheckpoint?.checkpointOutHash.toString(),
        // The snapshot's genesis is non-canonical (prefilled fee juice + protocol nullifiers);
        // re-opening the world state requires the same GenesisData or its init assertion fails.
        genesis: context.genesis && {
          genesisTimestamp: context.genesis.genesisTimestamp.toString(),
          prefilledPublicData: context.genesis.prefilledPublicData.map(l => [l.slot.toString(), l.value.toString()]),
          prefilledNullifiers: context.genesis.prefilledNullifiers?.map(n => n.toString()),
        },
      }),
    );

    // The main node's world state lives under its dataDirectory (world_state/, spawned into the
    // wsdb service). Copy it as a snapshot; the driver re-opens it with the same rollup address
    // and verifies its archive root against the tip block before building on it.
    const wsDir = path.join(context.aztecNodeConfig.dataDirectory!, 'world_state');
    const dest = path.join(OUT, 'state-candidate-0', 'world_state');
    rmSync(path.join(OUT, 'state-candidate-0'), { recursive: true, force: true });
    mkdirSync(dest, { recursive: true });
    cpSync(wsDir, dest, { recursive: true });
    execFileSync('find', [path.join(OUT, 'state-candidate-0'), '-name', 'lock.mdb', '-delete']);
    logger.info(`Harvest complete: ${NUM_SENDERS} txs, ${tip} blocks -> ${OUT}`);
  } finally {
    await context.teardown();
  }
}

main().then(
  () => process.exit(0),
  err => {
    logger.error(`harvest failed: ${err?.stack ?? err}`);
    process.exit(1);
  },
);
