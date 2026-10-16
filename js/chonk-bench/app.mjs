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
const maxThreads = Math.min(navigator.hardwareConcurrency || 1, 32);
for (let t = 1; t <= maxThreads; t *= 2) $('threads').add(new Option(String(t), String(t)));
if (!Array.from($('threads').options).some(o => o.value === String(maxThreads))) {
  $('threads').add(new Option(String(maxThreads), String(maxThreads)));
}
$('threads').value = String(Math.min(maxThreads, 8));

// One live service per engine; a change of threads or seeding starts a fresh one.
const live = {};
let srs;
async function service(key) {
  const config = `${$('threads').value}/${$('seeded').checked}`;
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
  const { BbService } = await ENGINES[key].load();
  const env = $('seeded').checked ? { BB_RNG_SEED: '12345' } : {};
  const api = await BbService.wasm({
    threads: Number($('threads').value),
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
    `${ENGINES[key].label}: ${$('threads').value} threads, ready in ${secs(performance.now() - t)}s ` +
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
  inputs[name] ??= new Uint8Array(await (await fetch(`/flows/${encodeURIComponent(name)}`)).arrayBuffer());
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
  cells[0].textContent = secs(r.accumulate);
  cells[1].textContent = secs(r.prove);
  cells[2].textContent = secs(r.total);
  cells[3].textContent = mib(r.memory);
  // bb's seeded ZK proofs reproduce only on one thread (its own warning); bb-ref's on any.
  const comparable = r.seeded && flow.golden && (key === 'ref' || r.threads === 1);
  const golden = !comparable ? '—' : r.sha === flow.golden ? '✓' : '✗';
  cells[4].textContent = r.verified ? golden : 'not verified';
  cells[4].className = `${key} ${r.verified && golden !== '✗' ? 'ok' : 'bad'}`;
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

async function run(flow, key) {
  setBusy(true, `${ENGINES[key].label}: ${flow.name}`);
  try {
    const api = await service(key);
    // Init again restarts a seeded stream, so every flow proven on one module starts where a fresh
    // process would (its golden); the first flow's Init has just run.
    if ($('seeded').checked && live[key].proved++ > 0) await api.init({ warmup: false });
    const steps = await flowSteps(flow.name);
    let step = '';
    const show = () =>
      ($('status').textContent = `${ENGINES[key].label}: ${flow.name}${step} — ${mib(memoryBytes(api))}`);
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
    const sha = await sha256Hex(r.proofBytes);
    (results[flow.name] ??= {})[key] = { ...r, sha, seeded: $('seeded').checked, threads: Number($('threads').value) };
    log(
      `${ENGINES[key].label} ${flow.name}: accumulate ${secs(r.accumulate)}s, prove ${secs(r.prove)}s, ` +
        `total ${secs(r.total)}s, memory ${mib(r.memory)}`,
    );
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
    `<td class="ref"></td><td class="ref"></td><td class="ref"></td><td class="ref"></td><td class="ref"></td>` +
    `<td class="bb"></td><td class="bb"></td><td class="bb"></td><td class="bb"></td><td class="bb"></td>` +
    `<td class="ratio"></td>`;
  tr.querySelectorAll('button').forEach(b => (b.onclick = () => !busy && run(flow, b.dataset.k)));
  $('rows').append(tr);
}
$('all').onclick = async () => {
  for (const flow of flows) {
    for (const key of ['ref', 'bb']) await run(flow, key);
  }
};
