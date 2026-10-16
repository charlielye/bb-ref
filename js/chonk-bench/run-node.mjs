// node run-node.mjs [bb-ref|bb] [flow ...]   (THREADS, BB_RNG_SEED as for the CLI)
// Proves the pinned flows through the chosen package's wasm module in node and prints timings, the
// proof sha256 and whether it matches the bb-ref fixture proof (a golden when BB_RNG_SEED=12345).
import { readFileSync, readdirSync, existsSync, openSync, readSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { unpack } from 'msgpackr';
import { decodeIvcInputs, initSrs, proveFlow, sha256Hex } from './flow.mjs';

const ROOT = new URL('../..', import.meta.url).pathname;
const which = process.argv[2] ?? 'bb-ref';
const FLOWS = process.env.BB_FLOWS ?? join(ROOT, 'pin/aztec-packages/barretenberg/cpp/chonk-pinned-flows');
const PIN7 = readFileSync(join(ROOT, 'tools/PIN'), 'utf8').slice(0, 7);
const CRS = process.env.CRS_PATH ?? join(process.env.HOME, '.bb-crs');
const threads = Number(process.env.THREADS ?? 8);
const flows = process.argv.slice(3).length
  ? process.argv.slice(3)
  : readdirSync(FLOWS).filter(f => existsSync(join(FLOWS, f, 'ivc-inputs.msgpack')));

const { BbService } = await import(which === 'bb' ? '@aztec-foundation/bb.js-api' : 'bb-ref.js');
const env = Object.fromEntries(['BB_RNG_SEED', 'RUST_BACKTRACE'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
const t = performance.now();
const api = await BbService.wasm({ threads, env, logger: process.env.VERBOSE ? m => console.error('[wasm]', m) : () => {} });
const read = (f, n) => {
  const fd = openSync(join(CRS, f), 'r');
  const buf = new Uint8Array(n);
  if (readSync(fd, buf, 0, n, 0) !== n) throw new Error(`${f}: shorter than ${n} bytes`);
  closeSync(fd);
  return buf;
};
console.error('module up');
await initSrs(api, {
  g1: read('bn254_g1.dat', (1 << 19) * 64),
  g2: read('bn254_g2.dat', 128),
  grumpkin: read('grumpkin_g1_v2.flat.dat', (1 << 16) * 64),
});
console.log(`${which}: ${threads} threads, module + SRS ready in ${(performance.now() - t).toFixed(0)} ms`);
for (const flow of flows) {
  const steps = await decodeIvcInputs(unpack, readFileSync(join(FLOWS, flow, 'ivc-inputs.msgpack')));
  const r = await proveFlow(api, steps);
  const sha = await sha256Hex(r.proofBytes);
  const fixture = join(ROOT, 'tests/data', PIN7, 'chonk_flows', flow, 'proof');
  if (process.env.PROOF_OUT) (await import('node:fs')).writeFileSync(`${process.env.PROOF_OUT}/${flow}.proof`, r.proofBytes);
  const golden = existsSync(fixture) ? (await sha256Hex(readFileSync(fixture))) === sha : '?';
  console.log(
    `${flow.padEnd(62)} accumulate ${(r.accumulate / 1e3).toFixed(2)}s  prove ${(r.prove / 1e3).toFixed(2)}s  ` +
      `total ${(r.total / 1e3).toFixed(2)}s  memory ${Math.round((api.backend?.memoryBytes?.() ?? 0) / 2 ** 20)} MiB  ` +
      `verified ${r.verified}  golden ${golden}`,
  );
}
await api.destroy();
