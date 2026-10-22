// The chonk bench page: each pinned flow proven by bb-ref.js and by bb's bb.js-api, one at a time,
// through the same generated API and the same command sequence (flow.mjs).
import { unpack } from 'msgpackr';
import { decodeIvcInputs, initSrs, proveFlow, sha256Hex } from './flow.mjs';

const ENGINES = {
  ref: { label: 'bb-ref.js', load: () => import('bb-ref.js') },
  bb: { label: 'bb.js-api', load: () => import('@aztec-foundation/bb.js-api') },
};

const $ = id => document.getElementById(id);
const log = msg => {
  if (verbose) console.log(msg);
  $('log').textContent += `${msg}\n`;
  $('log').scrollTop = $('log').scrollHeight;
};
const secs = ms => (ms / 1e3).toFixed(2);
const mib = bytes => (bytes === undefined ? '?' : `${Math.round(bytes / 2 ** 20)} MiB`);
/** The module's linear memory size: the service's wasm backend reads it even mid-call (shared memory). */
const memoryBytes = api => api?.backend?.memoryBytes?.();
// ?verbose forwards the modules' own log to the console.
const verbose = new URLSearchParams(location.search).has('verbose');

if (!crossOriginIsolated) log('Not cross-origin isolated: SharedArrayBuffer is unavailable, so wasm threads are too.');
// Powers of two up to twice the core count (to see what oversubscription does), plus the core count
// itself, which is the default.
const cores = Math.min(navigator.hardwareConcurrency || 1, 32);
const counts = new Set([cores]);
for (let t = 1; t <= Math.min(2 * cores, 32); t *= 2) counts.add(t);
for (const t of [...counts].sort((a, b) => a - b)) {
  $('threads').add(new Option(t === cores ? `${t} (cores)` : String(t), String(t)));
}
$('threads').value = String(cores);

// The package picks its wide-arithmetic module wherever the engine supports it; the checkbox can
// force the normal one, for a side-by-side.
const wideModule = threads => {
  const { defaultWasmModule } = refPackage;
  const url = defaultWasmModule(threads);
  return url.pathname.includes('-wide-') ? url : undefined;
};
const refPackage = await ENGINES.ref.load();
if (!wideModule(Number($('threads').value))) {
  $('wide').checked = false;
  $('wide').disabled = true;
  $('wide-note').textContent = 'not available in this browser';
}

// One live service per engine; a change of threads, seeding or module starts a fresh one.
const live = {};
let srs;
async function service(key) {
  // One module at a time: wasm memory never shrinks, so a module kept from the other engine would
  // hold its peak alongside this one's (two storage_proof peaks are more than a phone tab gets).
  for (const other of Object.keys(live)) {
    if (other !== key) {
      const old = live[other].api;
      delete live[other];
      await old.destroy();
    }
  }
  const config = `${$('threads').value}/${$('seeded').checked}/${$('wide').checked}`;
  if (live[key]?.config === config && !$('fresh').checked) return live[key].api;
  if (live[key]) {
    // Drop every reference first: the old instance's memory is freed only once nothing holds it.
    const old = live[key].api;
    delete live[key];
    await old.destroy();
  }
  const t = performance.now();
  const lap = () => {
    const ms = performance.now() - laps.at;
    laps.at = performance.now();
    return secs(ms);
  };
  const laps = { at: t };
  srs ??= await fetchSrs();
  const crs = lap();
  const { BbService, defaultWasmModule } = await ENGINES[key].load();
  const env = $('seeded').checked ? { BB_RNG_SEED: '12345' } : {};
  const threads = Number($('threads').value);
  const wide = key === 'ref' && wideModule(threads);
  // Unticked: the normal module beside the wide one.
  const wasmModule = wide && !$('wide').checked ? new URL('bb-ref-threads.wasm', wide) : undefined;
  const api = await BbService.wasm({
    module: wasmModule,
    threads,
    env,
    init: false,
    logger: verbose ? m => console.log(`[${key}] ${m}`) : undefined,
  });
  const module = lap();
  await api.init({});
  const init = lap();
  await initSrs(api, srs);
  const load = lap();
  log(
    `${ENGINES[key].label}: ${$('threads').value} threads, ` +
      `${(wasmModule ?? defaultWasmModule?.(threads))?.pathname.split('/').pop() ?? 'default module'}, ` +
      `ready in ${secs(performance.now() - t)}s ` +
      `(CRS download ${crs}s, module fetch + compile ${module}s, Init + warmup ${init}s, SRS load ${load}s)`,
  );
  live[key] = { api, config, proved: 0 };
  return api;
}

async function fetchSrs() {
  const get = async name => new Uint8Array(await (await fetch(`/crs/${name}`)).arrayBuffer());
  const [g1, g2, grumpkin] = await Promise.all([get('g1'), get('g2'), get('grumpkin')]);
  return { g1, g2, grumpkin };
}

const inputs = {};
async function flowSteps(name) {
  // Revalidated every time (a 304 when unchanged): a re-pin changes the flows under the same URL.
  inputs[name] ??= new Uint8Array(
    await (await fetch(`/flows/${encodeURIComponent(name)}`, { cache: 'no-cache' })).arrayBuffer(),
  );
  return decodeIvcInputs(unpack, inputs[name]);
}

const results = {};
function render(flow, key) {
  const row = $(`row-${flow.name}`);
  const r = results[flow.name]?.[key];
  const cells = row.querySelectorAll(`td.${key}`);
  if (r?.error) {
    cells[0].textContent = 'error';
    cells[0].title = r.error;
    cells[0].className = `${key} bad`;
    return;
  }
  if (!r) return;
  cells[0].textContent = secs(r.total);
  cells[0].title = r.times.length > 1 ? `mean of ${r.times.length} runs: ${r.times.map(secs).join(', ')}s` : '';
  cells[0].className = key;
  cells[1].textContent = mib(r.memory);
  // bb's seeded ZK proofs reproduce only on one thread (its own warning); bb-ref's on any.
  const comparable = r.seeded && flow.golden && (key === 'ref' || r.threads === 1);
  const golden = !comparable ? '—' : r.sha === flow.golden ? '✓' : '✗';
  cells[2].textContent = r.verified ? golden : 'not verified';
  cells[2].className = `${key} ${r.verified && golden !== '✗' ? 'ok' : 'bad'}`;
  const ref = results[flow.name]?.ref;
  const bb = results[flow.name]?.bb;
  row.querySelector('td.ratio').textContent = ref?.total && bb?.total ? `${(ref.total / bb.total).toFixed(2)}×` : '';
}

let busy = false;
function setBusy(b, what = '') {
  busy = b;
  document.querySelectorAll('button').forEach(x => (x.disabled = b));
  $('status').textContent = what;
}

// One proof of the flow on the engine's live service.
async function proveOnce(flow, key, label) {
  const api = await service(key);
  // Init again restarts a seeded stream, so every flow proven on one module starts where a fresh
  // process would (its golden); the first flow's Init has just run.
  if ($('seeded').checked && live[key].proved++ > 0) await api.init({ warmup: false });
  const steps = await flowSteps(flow.name);
  let step = '';
  const show = () => ($('status').textContent = `${label}${step} — ${mib(memoryBytes(api))}`);
  const tick = setInterval(show, 250);
  let r;
  try {
    r = await proveFlow(api, steps, (i, n) => {
      step = ` (${i}/${n})`;
      show();
    });
  } finally {
    clearInterval(tick);
  }
  r.memory = memoryBytes(api);
  r.sha = await sha256Hex(r.proofBytes);
  return r;
}

// Proves the flow `runs` times and keeps the mean time, the highest memory, and a golden/verified
// mark that holds only if it held on every run.
async function run(flow, key) {
  const runs = Math.max(1, Math.floor(Number($('runs').value)) || 1);
  setBusy(true, `${ENGINES[key].label}: ${flow.name}`);
  try {
    const times = [];
    let memory = 0;
    let verified = true;
    const shas = new Set();
    for (let i = 1; i <= runs; i++) {
      const label = `${ENGINES[key].label}: ${flow.name}${runs > 1 ? ` [run ${i}/${runs}]` : ''}`;
      const r = await proveOnce(flow, key, label);
      times.push(r.total);
      memory = Math.max(memory, r.memory ?? 0);
      verified &&= r.verified;
      shas.add(r.sha);
      log(
        `${label}: accumulate ${secs(r.accumulate)}s, prove ${secs(r.prove)}s, ` +
          `total ${secs(r.total)}s, memory ${mib(r.memory)}`,
      );
    }
    const total = times.reduce((a, b) => a + b, 0) / runs;
    (results[flow.name] ??= {})[key] = {
      total,
      times,
      memory: memory || undefined,
      verified,
      // Unseeded proofs differ run to run; a seeded flow is golden only if every run's proof is.
      sha: shas.size === 1 ? [...shas][0] : undefined,
      seeded: $('seeded').checked,
      threads: Number($('threads').value),
    };
    if (runs > 1) {
      log(
        `${ENGINES[key].label} ${flow.name}: mean of ${runs} runs ${secs(total)}s ` +
          `(min ${secs(Math.min(...times))}s, max ${secs(Math.max(...times))}s)`,
      );
    }
  } catch (e) {
    (results[flow.name] ??= {})[key] = { error: String(e?.message ?? e) };
    log(`${ENGINES[key].label} ${flow.name}: ${e?.message ?? e}`);
  } finally {
    render(flow, key);
    setBusy(false);
  }
}

const flows = await (await fetch('/api/flows')).json();
for (const flow of flows) {
  const tr = document.createElement('tr');
  tr.id = `row-${flow.name}`;
  tr.innerHTML =
    `<td class="flow" title="${flow.name}">${flow.name}</td>` +
    `<td><button data-k="ref">bb-ref</button> <button data-k="bb">bb</button></td>` +
    `<td class="ref"></td><td class="ref"></td><td class="ref"></td>` +
    `<td class="bb"></td><td class="bb"></td><td class="bb"></td>` +
    `<td class="ratio"></td>`;
  tr.querySelectorAll('button').forEach(b => (b.onclick = () => !busy && run(flow, b.dataset.k)));
  $('rows').append(tr);
}
// Engine by engine, so each module starts once (only one is alive at a time).
$('all').onclick = async () => {
  for (const key of $('engines').value.split(',')) {
    for (const flow of flows) await run(flow, key);
  }
};
