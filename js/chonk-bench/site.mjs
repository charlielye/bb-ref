// What the bench page is made of, shared by the live server (serve.mjs) and the static build
// (build-site.mjs): the packages, the pinned flows with their golden proof hashes, the CRS prefix,
// and each package's wasm modules with their sizes.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { constants, gzipSync } from 'node:zlib';

export const HERE = new URL('.', import.meta.url).pathname;
const ROOT = join(HERE, '../..');
// Read per call: a re-pin renames the fixture directory under a running server.
export const pin7 = () => readFileSync(join(ROOT, 'tools/PIN'), 'utf8').slice(0, 7);
export const FLOWS = process.env.BB_FLOWS ?? join(ROOT, 'pin/aztec-packages/barretenberg/cpp/chonk-pinned-flows');
export const CRS = process.env.CRS_PATH ?? join(process.env.HOME, '.bb-crs');

export const PACKAGES = {
  'bb-ref.js': join(HERE, 'node_modules/bb-ref.js'),
  'bb.js-api': join(HERE, 'node_modules/@aztec-foundation/bb.js-api'),
  'ipc-runtime': join(ROOT, 'pin/aztec-packages/ipc-runtime/ts'),
  msgpackr: join(HERE, 'node_modules/msgpackr'),
};

/** The CRS prefix the flows need: [file, bytes] (2^19 BN254 points, [x]_2, 2^16 Grumpkin points). */
export const CRS_FILES = {
  g1: ['bn254_g1.dat', (1 << 19) * 64],
  g2: ['bn254_g2.dat', 128],
  grumpkin: ['grumpkin_g1_v2.flat.dat', (1 << 16) * 64],
};

/** [{ name, golden }]: the pinned flows and the sha256 of bb's proof of each, where there is one. */
export const flows = () =>
  readdirSync(FLOWS)
    .filter(f => existsSync(join(FLOWS, f, 'ivc-inputs.msgpack')))
    .sort()
    .map(name => {
      const proof = join(ROOT, 'tests/data', pin7(), 'chonk_flows', name, 'proof');
      return {
        name,
        golden: existsSync(proof) ? createHash('sha256').update(readFileSync(proof)).digest('hex') : null,
      };
    });

const gzCache = new Map();
/** The file gzipped at level 9, kept until the file changes (a rebuild replaces the module). */
export function gzipped(path, version) {
  const hit = gzCache.get(path);
  if (hit?.version === version) return hit.body;
  const body = gzipSync(readFileSync(path), { level: constants.Z_BEST_COMPRESSION });
  gzCache.set(path, { version, body });
  return body;
}

// The engine each package's wasm modules belong to.
const MODULE_DIRS = { ref: 'bb-ref.js', bb: 'bb.js-api' };
/** [{ engine, file, raw, gzip }]: each package's wasm modules, raw and gzipped. */
export const modules = () =>
  Object.entries(MODULE_DIRS).flatMap(([engine, pkg]) => {
    const dir = join(realpathSync(PACKAGES[pkg]), 'wasm');
    return readdirSync(dir)
      .filter(f => f.endsWith('.wasm'))
      .sort()
      .map(file => {
        const path = join(dir, file);
        const st = statSync(path);
        return { engine, file, raw: st.size, gzip: gzipped(path, `${st.size}-${st.mtimeMs}`).length };
      });
  });
