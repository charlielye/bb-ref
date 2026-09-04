// Run a wasm32-wasip1-threads CLI under node/V8: wasi-threads via worker_threads, the same
// shape browsers use (bb.js does the equivalent with web workers). The wasm "main" runs inside
// a worker too — a blocked main event loop can never bootstrap new workers, so the JS main
// thread stays free and acts purely as the spawn broker. Thread ids come from a shared atomic
// counter, so `wasi.thread-spawn` returns synchronously from any thread.
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';
import { Worker, isMainThread, workerData, parentPort } from 'node:worker_threads';
import { argv, env, exit } from 'node:process';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);

function makeThreadSpawn(ctl) {
  return (startArg) => {
    const tid = Atomics.add(ctl, 0, 1);
    parentPort.postMessage({ spawn: { tid, startArg } });
    return tid;
  };
}

function minimalWasi(memory) {
  const view = () => new DataView(memory.buffer);
  return {
    clock_time_get: (_id, _prec, out) => {
      const ns = BigInt(Math.round(performance.timeOrigin * 1e6)) + BigInt(Math.round(performance.now() * 1e6));
      view().setBigUint64(out, ns, true);
      return 0;
    },
    sched_yield: () => 0,
    random_get: (ptr, len) => {
      const b = new Uint8Array(memory.buffer, ptr, len);
      for (let i = 0; i < len; i++) b[i] = (Math.random() * 256) | 0;
      return 0;
    },
    fd_write: (fd, iovs, iovsLen, nwritten) => {
      let total = 0;
      let s = '';
      for (let i = 0; i < iovsLen; i++) {
        const ptr = view().getUint32(iovs + i * 8, true);
        const len = view().getUint32(iovs + i * 8 + 4, true);
        s += Buffer.from(memory.buffer.slice(ptr, ptr + len)).toString();
        total += len;
      }
      if (fd === 2) process.stderr.write(s);
      view().setUint32(nwritten, total, true);
      return 0;
    },
    proc_exit: (c) => { throw new Error(`worker proc_exit(${c})`); },
    environ_sizes_get: (a, b) => { view().setUint32(a, 0, true); view().setUint32(b, 0, true); return 0; },
    environ_get: () => 0,
    poll_oneoff: () => 52,
  };
}

if (isMainThread) {
  const wasmPath = argv[2];
  const module = await WebAssembly.compile(await readFile(wasmPath));
  if (!WebAssembly.Module.imports(module).some((i) => i.kind === 'memory')) {
    throw new Error('module does not import memory (not a threads build?)');
  }
  // The provided maximum must not exceed the module's declared maximum, which the JS API
  // doesn't expose — probe downward from WASM_MAX_PAGES until instantiation-by-limits works.
  const probe = (pages) => new WebAssembly.Memory({ initial: 1200, maximum: pages, shared: true });
  let maxPages = Number(env.WASM_MAX_PAGES ?? 65536);
  let memory = probe(maxPages);
  const limitOk = async (mem) => {
    try {
      // A dry instantiate just to validate the memory import; aborts on missing functions is
      // fine — LinkError mentioning "maximum" is the only signal we probe for.
      await WebAssembly.instantiate(module, { env: { memory: mem } });
      return true;
    } catch (e) {
      return !(e instanceof WebAssembly.LinkError && String(e).includes('maximum'));
    }
  };
  while (maxPages > 1200 && !(await limitOk(memory))) {
    maxPages = maxPages / 2;
    memory = probe(maxPages);
  }
  const ctl = new Int32Array(new SharedArrayBuffer(8));
  ctl[0] = 2; // next tid
  let spawned = 0;
  const prof = env.WASI_CPU_PROF; // directory: write one .cpuprofile per thread
  const spawn = (role, extra) => {
    if (role === 'thread' && env.WASI_THREADS_DEBUG) console.error(`[harness] spawn #${++spawned} tid=${extra.tid} @${(performance.now()/1000).toFixed(2)}s`);
    const w = new Worker(SELF, {
      workerData: { role, module, memory, ctl, args: argv.slice(2), ...extra },
      execArgv: prof ? ['--cpu-prof', '--cpu-prof-dir', prof] : [],
    });
    w.on('message', (m) => {
      if (m.spawn) spawn('thread', m.spawn);
      if (m.exit !== undefined) {
        // Linear memory only grows, so its size at exit is the run's peak — the number that
        // matters for browsers, free of the host's per-worker isolate overhead.
        console.error(`[wasm-mem] ${memory.buffer.byteLength}`);
        exit(m.exit);
      }
    });
    w.on('error', (e) => { console.error(e); exit(1); });
    if (role === 'thread') w.unref();
    return w;
  };
  spawn('main', {});
} else if (workerData.role === 'main') {
  const { module, memory, ctl, args } = workerData;
  const wasi = new WASI({ version: 'preview1', args, env, preopens: { '/': '/' } });
  const imports = {
    ...wasi.getImportObject(),
    env: { memory },
    wasi: { 'thread-spawn': makeThreadSpawn(ctl) },
  };
  const instance = await WebAssembly.instantiate(module, imports);
  const code = wasi.start({ exports: { memory, _start: instance.exports._start } });
  parentPort.postMessage({ exit: code ?? 0 });
} else {
  const { module, memory, ctl, tid, startArg } = workerData;
  // The module imports one fixed set of wasi functions; satisfy them all, real or NOSYS stub.
  const wasiImports = {};
  for (const imp of WebAssembly.Module.imports(module)) {
    if (imp.module === 'wasi_snapshot_preview1' && imp.kind === 'function') {
      wasiImports[imp.name] = () => 52; // ERRNO_NOSYS
    }
  }
  Object.assign(wasiImports, minimalWasi(memory));
  const imports = {
    wasi_snapshot_preview1: wasiImports,
    env: { memory },
    wasi: { 'thread-spawn': makeThreadSpawn(ctl) },
  };
  const instance = await WebAssembly.instantiate(module, imports);
  instance.exports.wasi_thread_start(tid, startArg);
  parentPort.close();
}
