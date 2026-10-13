// runwasi_threads.mjs + a linear-memory growth trace: the JS main thread polls memory.buffer.byteLength
// every ms and prints `[memtrace] <ms since start> <bytes>` on each change, interleaved (in order, both
// writers are synchronous) with the prover's own stderr phase marks (BBREF_TIMING=1 / bb's (mem: ...) lines).
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

// The memory import's declared limits, read from the module's import section (the JS API does not
// expose them). Memory is created at the declared minimum, as bb.js does, so the reported peak is
// the module's own: a larger `initial` is space the module's allocator never uses.
function memoryLimits(bytes) {
  let p = 8;
  const u8 = () => bytes[p++];
  const leb = () => { let r = 0, s = 0, b; do { b = u8(); r += (b & 0x7f) * 2 ** s; s += 7; } while (b & 0x80); return r; };
  const name = () => { const n = leb(); p += n; };
  const limits = () => { const f = u8(); const min = leb(); return { min, max: f & 1 ? leb() : undefined }; };
  while (p < bytes.length) {
    const id = u8(), size = leb(), end = p + size;
    if (id !== 2) { p = end; continue; }
    for (let n = leb(); n > 0; n--) {
      name(); name();
      const kind = u8();
      if (kind === 2) return limits();
      if (kind === 0) leb();
      else if (kind === 1) { u8(); limits(); }
      else if (kind === 3) p += 2;
      else if (kind === 4) { u8(); leb(); }
    }
    p = end;
  }
  throw new Error('module does not import memory (not a threads build?)');
}

if (isMainThread) {
  const wasmPath = argv[2];
  const bytes = await readFile(wasmPath);
  const module = await WebAssembly.compile(bytes);
  const { min, max } = memoryLimits(bytes);
  const memory = new WebAssembly.Memory({ initial: Number(env.WASM_INITIAL_PAGES ?? min), maximum: max ?? 65536, shared: true });
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
  let last = 0;
  const t0 = performance.now();
  setInterval(() => {
    const n = memory.buffer.byteLength;
    if (n !== last) { console.error(`[memtrace] ${(performance.now() - t0).toFixed(1)} ${n}`); last = n; }
  }, 1).unref();
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
