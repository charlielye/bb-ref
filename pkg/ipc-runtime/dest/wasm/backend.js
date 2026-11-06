import { WasmInstanceHost } from "./host.js";
import { compileWasmModule } from "./module_source.js";
/** Above this, more wasi threads stop paying for themselves; the engine clamps to it. */
export const MAX_THREADS = 32;
const DEFAULT_INITIAL_PAGES = 64;
const DEFAULT_MAXIMUM_PAGES = 65536;
const FIRST_THREAD_ID = 2;
function awaitReady(worker, what) {
    return new Promise((resolve, reject) => {
        worker.onMessage((msg) => {
            if (msg?.type === "ready") {
                resolve(msg);
            }
            else if (msg?.type === "init-error") {
                reject(new Error(`${what}: ${msg.message}`));
            }
        });
        worker.onError((err) => reject(err instanceof Error ? err : new Error(`${what}: ${String(err)}`)));
    });
}
/**
 * One worker per wasi thread, created when the module spawns it and dropped when it exits.
 *
 * A worker runs a thread to completion inside `wasi_thread_start`, so it can serve exactly one
 * thread at a time; giving each its own worker is both the simplest arrangement and the only
 * correct one. The module decides how many threads it wants — typically a pool of its own, sized
 * from the thread count it was told — and this follows.
 */
class Threads {
    createWorker;
    init;
    logger;
    workers = new Map();
    nextTid = FIRST_THREAD_ID;
    unrefed = false;
    constructor(createWorker, init, logger) {
        this.createWorker = createWorker;
        this.init = init;
        this.logger = logger;
    }
    /**
     * wasi-threads `thread-spawn`: start the module's thread entry on a new worker and return its
     * tid. The import is synchronous, so the worker boots while the caller carries on; its `init`
     * and `start` messages are queued in order and the worker serializes them.
     */
    spawn(startArg) {
        const tid = this.nextTid++;
        let worker;
        try {
            worker = this.createWorker();
        }
        catch (e) {
            this.logger(`wasm thread ${tid} could not be created: ${String(e)}`);
            return -1;
        }
        this.workers.set(tid, worker);
        worker.onMessage((msg) => {
            if (msg?.type === "log") {
                this.logger(msg.message);
            }
            else if (msg?.type === "thread-exit" || msg?.type === "init-error") {
                if (msg.type === "init-error") {
                    this.logger(`wasm thread ${tid} failed to start: ${msg.message}`);
                }
                this.workers.delete(tid);
                void worker.terminate();
            }
        });
        worker.onError((err) => {
            this.logger(`wasm thread ${tid}: ${String(err)}`);
            this.workers.delete(tid);
        });
        worker.postMessage({ type: "init", ...this.init });
        worker.postMessage({ type: "start", tid, startArg });
        if (this.unrefed) {
            worker.unref();
        }
        return tid;
    }
    unref() {
        this.unrefed = true;
        for (const w of this.workers.values()) {
            w.unref();
        }
    }
    async destroy() {
        const workers = [...this.workers.values()];
        this.workers.clear();
        await Promise.all(workers.map((w) => w.terminate()));
    }
}
/**
 * The module running on the current thread: memory, main instance, and the workers serving its
 * `thread-spawn` requests. `call` is synchronous and blocks until the module returns.
 */
export class WasmFfiEngine {
    host;
    threadWorkers;
    memory;
    threads;
    constructor(
    /** The module instance, for reaching exports of its own beyond the FFI entry. */
    host, threadWorkers, memory, threads) {
        this.host = host;
        this.threadWorkers = threadWorkers;
        this.memory = memory;
        this.threads = threads;
    }
    static async create(opts, binding) {
        const { platform } = binding;
        const logger = opts.logger ?? (() => { });
        const module = await compileWasmModule(opts.module, platform);
        const wantThreads = Math.max(1, Math.min(opts.threads ?? platform.hardwareConcurrency(), MAX_THREADS));
        const wantShared = opts.memory?.shared ??
            (wantThreads > 1 && platform.sharedMemoryAvailable());
        const memory = createMemory(module, opts.memory?.initial ?? DEFAULT_INITIAL_PAGES, opts.memory?.maximum ??
            platform.maximumMemoryPages?.() ??
            DEFAULT_MAXIMUM_PAGES, wantShared);
        // The module's declaration wins over the request: a threads build gets a shared memory even
        // for one thread, and workers need a shared memory, so the thread count follows the memory.
        // A module that defines its own memory instead of importing one cannot be threaded at all —
        // every instance would get a memory of its own, with nothing shared between them.
        const importsMemory = WebAssembly.Module.imports(module).some((i) => i.kind === "memory");
        const shared = memory.buffer instanceof SharedArrayBuffer;
        const threads = importsMemory && shared && platform.sharedMemoryAvailable()
            ? wantThreads
            : 1;
        const env = {
            HARDWARE_CONCURRENCY: String(threads),
            RAYON_NUM_THREADS: String(threads),
            ...(opts.env ?? {}),
        };
        // Threads are created when the module asks for them, so nothing is spawned here — and
        // nothing at all if the module never spawns a thread.
        const threadWorkers = threads > 1
            ? new Threads(binding.createThreadWorker, {
                module,
                memory,
                env,
                entry: opts.entry,
            }, logger)
            : undefined;
        const host = await WasmInstanceHost.instantiate({
            module,
            memory,
            env,
            logger,
            entry: opts.entry,
            threads,
            spawnThread: (startArg) => threadWorkers?.spawn(startArg) ?? -1,
        });
        // host.memory is the one the module actually uses, which is its own when it exports one.
        logger(`wasm: ${threads} thread(s), memory ${host.memory.buffer.byteLength >> 16} pages initial, ` +
            `shared=${host.memory.buffer instanceof SharedArrayBuffer}, ` +
            `${importsMemory ? "imported" : "owned by the module"}`);
        return new WasmFfiEngine(host, threadWorkers, host.memory, threads);
    }
    call(input) {
        return this.host.call(input);
    }
    unref() {
        this.threadWorkers?.unref();
    }
    async destroy() {
        await this.threadWorkers?.destroy();
    }
}
/**
 * The module's declared maximum is not visible from JS: instantiating with a larger `maximum`
 * fails with a LinkError naming it, so probe downward until the import links.
 */
function createMemory(module, initial, maximum, shared) {
    const imported = WebAssembly.Module.imports(module).find((i) => i.kind === "memory");
    let max = Math.max(initial, maximum);
    let flippedShared = false;
    for (;;) {
        let memory;
        try {
            memory = new WebAssembly.Memory({ initial, maximum: max, shared });
        }
        catch (e) {
            // The engine could not reserve that much address space (e.g. mobile browsers).
            if (max > initial) {
                max = Math.max(initial, Math.floor(max / 2));
                continue;
            }
            throw e;
        }
        if (!imported) {
            return memory;
        }
        try {
            // A dry instantiation only to validate the memory import. V8 checks that every import
            // module exists before it validates any single import, so stub every function import;
            // the only errors left are then about the memory itself.
            const stubs = {};
            for (const imp of WebAssembly.Module.imports(module)) {
                stubs[imp.module] ??= {};
                if (imp.kind === "memory") {
                    stubs[imp.module][imp.name] = memory;
                }
                else if (imp.kind === "function") {
                    stubs[imp.module][imp.name] = () => 0;
                }
            }
            new WebAssembly.Instance(module, stubs);
            return memory;
        }
        catch (e) {
            const message = e instanceof WebAssembly.LinkError ? String(e) : "";
            if (message.includes("maximum") && max > initial) {
                max = Math.max(initial, Math.floor(max / 2));
                continue;
            }
            // A threads build declares its memory shared even when it will run with one thread (and a
            // single-thread build declares it unshared): follow the module's declaration.
            if (message.includes("shared") && !flippedShared) {
                flippedShared = true;
                shared = !shared;
                continue;
            }
            return memory;
        }
    }
}
/**
 * Asynchronous FFI backend over a wasm module. Implements the runtime's `IpcClientAsync`, so the
 * generated `AsyncApi` sits on it exactly as it sits on a spawned process.
 */
export class WasmFfiBackend {
    engine;
    worker;
    seq = 0;
    pending = new Map();
    /** The module's memory when it is shared and lives in the main worker (see `memoryBytes`). */
    sharedMemory;
    constructor(engine, worker) {
        this.engine = engine;
        this.worker = worker;
    }
    /**
     * The module's linear memory size in bytes, readable at any time (also while a call runs, when the
     * memory is shared). Wasm memory only grows, so this is the instance's high-water mark. Undefined
     * when the module runs in a worker with an unshared memory.
     */
    memoryBytes() {
        return (this.engine?.memory ?? this.sharedMemory)?.buffer.byteLength;
    }
    static async create(opts, binding) {
        const bound = {
            platform: binding.platform,
            createThreadWorker: opts.createThreadWorker ?? binding.createThreadWorker,
            createMainWorker: opts.createMainWorker ?? binding.createMainWorker,
        };
        if (opts.worker === false) {
            return new WasmFfiBackend(await WasmFfiEngine.create(opts, bound), undefined);
        }
        // Compile here so the (cached, streaming) compilation happens once and the compiled Module is
        // what crosses to the worker, rather than each side compiling the same bytes.
        const module = await compileWasmModule(opts.module, bound.platform);
        const worker = bound.createMainWorker();
        const backend = new WasmFfiBackend(undefined, worker);
        const ready = awaitReady(worker, "wasm main worker");
        worker.onMessage((msg) => backend.onWorkerMessage(msg, opts.logger));
        worker.postMessage({
            type: "init",
            module,
            options: {
                threads: opts.threads,
                memory: opts.memory,
                env: opts.env,
                entry: opts.entry,
            },
        });
        backend.sharedMemory = (await ready).memory;
        return backend;
    }
    onWorkerMessage(msg, logger) {
        if (msg?.type === "log") {
            logger?.(msg.message);
            return;
        }
        if (msg?.type !== "result" && msg?.type !== "error") {
            return;
        }
        const pending = this.pending.get(msg.id);
        if (!pending) {
            return;
        }
        this.pending.delete(msg.id);
        if (msg.type === "result") {
            pending.resolve(new Uint8Array(msg.output));
        }
        else {
            pending.reject(new Error(msg.message));
        }
    }
    call(input) {
        if (this.engine) {
            try {
                return Promise.resolve(this.engine.call(input));
            }
            catch (e) {
                return Promise.reject(e);
            }
        }
        const id = ++this.seq;
        // A private copy so the request can be transferred rather than cloned. Not `slice()`: on a
        // node Buffer that aliases the caller's (pooled) memory, which the transfer would detach.
        const copy = new Uint8Array(input.byteLength);
        copy.set(input);
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            this.worker.postMessage({ type: "call", id, input: copy }, [
                copy.buffer,
            ]);
        });
    }
    /** Let the host process exit even while the module's workers are alive (node). */
    unref() {
        this.engine?.unref();
        this.worker?.unref();
    }
    async destroy() {
        if (this.engine) {
            await this.engine.destroy();
            return;
        }
        // The page's reference would keep the old instance's memory alive until it is collected.
        this.sharedMemory = undefined;
        const worker = this.worker;
        const done = new Promise((resolve) => {
            worker.onMessage((msg) => {
                if (msg?.type === "destroyed") {
                    resolve();
                }
            });
        });
        worker.postMessage({ type: "destroy" });
        await Promise.race([done, new Promise((r) => setTimeout(r, 2000))]);
        await worker.terminate();
        for (const p of this.pending.values()) {
            p.reject(new Error("wasm backend destroyed"));
        }
        this.pending.clear();
    }
}
/**
 * Synchronous FFI backend: the module runs on the calling thread and every call blocks until it
 * returns. Defaults to one thread, since a blocked caller cannot service anything else.
 */
export class WasmFfiBackendSync {
    engine;
    constructor(engine) {
        this.engine = engine;
    }
    /** The module's linear memory size in bytes (its high-water mark: wasm memory only grows). */
    memoryBytes() {
        return this.engine.memory.buffer.byteLength;
    }
    static async create(opts, binding) {
        return new WasmFfiBackendSync(await WasmFfiEngine.create({ threads: 1, ...opts }, binding));
    }
    call(input) {
        return this.engine.call(input);
    }
    unref() {
        this.engine.unref();
    }
    destroy() {
        void this.engine.destroy();
    }
}
