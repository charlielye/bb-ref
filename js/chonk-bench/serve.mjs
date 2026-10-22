// node serve.mjs [port]   (BB_FLOWS, CRS_PATH as for the CLI; default port 8080)
//
// Serves the chonk bench page with no bundler and no dependencies: the page's bare imports
// resolve through an import map to the packages served under /pkg/, and every response carries
// the cross-origin isolation headers that SharedArrayBuffer (and so wasm threads) needs.
//
//   /                      index.html, app.mjs, flow.mjs
//   /pkg/<name>/...        bb-ref.js, bb.js-api, ipc-runtime, msgpackr (their published files)
//   /api/flows             [{ name, golden }]: the pinned flows and their bb proof sha256
//   /api/modules           [{ engine, file, raw, gzip }]: each package's wasm modules and their sizes
//   /flows/<name>          the flow's ivc-inputs.msgpack
//   /crs/g1 | g2 | grumpkin  the CRS prefix the flows need (2^19 BN254 points, [x]_2, 2^16 Grumpkin)
import { createServer } from 'node:http';
import { createReadStream, existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { extname, join, normalize } from 'node:path';
import { constants, gzipSync } from 'node:zlib';

const HERE = new URL('.', import.meta.url).pathname;
const ROOT = join(HERE, '../..');
// Read per request: a re-pin renames the fixture directory under a running server.
const pin7 = () => readFileSync(join(ROOT, 'tools/PIN'), 'utf8').slice(0, 7);
const FLOWS = process.env.BB_FLOWS ?? join(ROOT, 'pin/aztec-packages/barretenberg/cpp/chonk-pinned-flows');
const CRS = process.env.CRS_PATH ?? join(process.env.HOME, '.bb-crs');
const port = Number(process.argv[2] ?? 8080);

const PACKAGES = {
  'bb-ref.js': join(HERE, 'node_modules/bb-ref.js'),
  'bb.js-api': join(HERE, 'node_modules/@aztec-foundation/bb.js-api'),
  'ipc-runtime': join(ROOT, 'pin/aztec-packages/ipc-runtime/ts'),
  msgpackr: join(HERE, 'node_modules/msgpackr'),
};
const CRS_FILES = {
  g1: ['bn254_g1.dat', (1 << 19) * 64],
  g2: ['bn254_g2.dat', 128],
  grumpkin: ['grumpkin_g1_v2.flat.dat', (1 << 16) * 64],
};
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.map': 'application/json',
};

const flows = () =>
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

// Each package's wasm modules, served gzipped (as a deployment would) and listed with both sizes.
const MODULE_DIRS = { ref: 'bb-ref.js', bb: 'bb.js-api' };
const gzCache = new Map();
/** The file gzipped at level 9, kept until the file changes (a rebuild replaces the module). */
function gzipped(path, version) {
  const hit = gzCache.get(path);
  if (hit?.version === version) return hit.body;
  const body = gzipSync(readFileSync(path), { level: constants.Z_BEST_COMPRESSION });
  gzCache.set(path, { version, body });
  return body;
}
const modules = () =>
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

/** A file under `base`, or null when `rel` escapes it or names no file. */
function inside(base, rel) {
  const path = normalize(join(base, rel));
  if (!path.startsWith(normalize(base))) return null;
  return existsSync(path) && statSync(path).isFile() ? path : null;
}

function send(res, status, body, type = 'text/plain') {
  res.writeHead(status, { 'Content-Type': type });
  res.end(body);
}

/** A file, revalidated by an ETag (size + mtime): a reload re-downloads only what changed. */
function sendFile(req, res, path, length, cache = 'no-cache') {
  const st = statSync(path);
  // ctime too: extracted archives (the pinned flows) carry a zero mtime.
  const changed = Math.floor(Math.max(st.mtimeMs, st.ctimeMs));
  const gzip = extname(path) === '.wasm' && !length && /\bgzip\b/.test(req.headers['accept-encoding'] ?? '');
  const etag = `"${st.size.toString(36)}-${changed.toString(36)}-${length ?? 'all'}${gzip ? '-gz' : ''}"`;
  res.setHeader('Vary', 'Accept-Encoding');
  res.setHeader('Cache-Control', cache);
  res.setHeader('ETag', etag);
  if (req.headers['if-none-match'] === etag) {
    res.writeHead(304);
    return res.end();
  }
  if (gzip) {
    const body = gzipped(path, `${st.size}-${st.mtimeMs}`);
    res.writeHead(200, { 'Content-Type': TYPES['.wasm'], 'Content-Encoding': 'gzip', 'Content-Length': body.length });
    return res.end(body);
  }
  res.writeHead(200, {
    'Content-Type': TYPES[extname(path)] ?? 'application/octet-stream',
    'Content-Length': length ?? st.size,
  });
  createReadStream(path, length ? { start: 0, end: length - 1 } : {}).pipe(res);
}

createServer((req, res) => {
  // Cross-origin isolation: without both, browsers withhold SharedArrayBuffer.
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  const url = new URL(req.url, 'http://localhost');
  const parts = decodeURIComponent(url.pathname).split('/').filter(Boolean);
  try {
    if (parts.length === 0) return sendFile(req, res, join(HERE, 'index.html'));
    if (parts[0] === 'api' && parts[1] === 'flows') return send(res, 200, JSON.stringify(flows()), TYPES['.json']);
    if (parts[0] === 'api' && parts[1] === 'modules') return send(res, 200, JSON.stringify(modules()), TYPES['.json']);
    if (parts[0] === 'flows' && parts.length === 2) {
      const path = inside(FLOWS, join(parts[1], 'ivc-inputs.msgpack'));
      return path ? sendFile(req, res, path) : send(res, 404, 'no such flow');
    }
    if (parts[0] === 'crs' && CRS_FILES[parts[1]]) {
      const [file, length] = CRS_FILES[parts[1]];
      // The CRS prefix never changes.
      return sendFile(req, res, join(CRS, file), length, 'public, max-age=31536000, immutable');
    }
    if (parts[0] === 'pkg' && PACKAGES[parts[1]]) {
      const path = inside(realpathSync(PACKAGES[parts[1]]), parts.slice(2).join('/'));
      return path ? sendFile(req, res, path) : send(res, 404, 'not found');
    }
    const path = parts.length === 1 && inside(HERE, parts[0]);
    return path ? sendFile(req, res, path) : send(res, 404, 'not found');
  } catch (e) {
    send(res, 500, String(e));
  }
}).listen(port, () => console.log(`chonk bench: http://localhost:${port}/  (pin ${pin7()}, flows ${FLOWS})`));
