import { type WasmFfiBackend, type WasmFfiBackendSync, type WasmModuleSource } from '@aztec-foundation/ipc-runtime/wasm';
export { sharedMemoryAvailable } from '@aztec-foundation/ipc-runtime/wasm';
/** Options for running the bb wasm module in-process. */
export interface BbWasmOptions {
    /**
     * Threads to run with (1 = no worker threads; selects the single-thread module). Default: the
     * platform's parallelism where a shared memory is available, else 1. More than one thread where
     * no shared memory is available is an error, not a silent downgrade.
     */
    threads?: number;
    /** Linear memory bounds in 64 KiB pages. */
    memory?: {
        initial?: number;
        maximum?: number;
    };
    /**
     * The module to run instead of the package's own: a URL or path, raw or gzipped bytes, a fetch
     * Response, or an already compiled WebAssembly.Module. The package's own module is uncompressed,
     * so that a browser can stream it into compileStreaming and cache the compiled code; point this
     * at a gzipped copy when serving from a host that applies no compression of its own.
     */
    module?: WasmModuleSource;
    /**
     * Where a call runs. Default (true) is a dedicated worker, so a long call never blocks the
     * caller — the right choice for proving, and the only safe one on a browser's main thread.
     * False runs the module on the calling thread and every call blocks it until the module
     * returns, which is cheaper per call and fine for short work off the main thread. For short
     * work *on* the main thread, prefer the synchronous backend, which always runs there.
     */
    worker?: boolean;
    /** WASI environ for the module. */
    env?: Record<string, string>;
    logger?: (msg: string) => void;
    /** Let node exit while the module's workers are alive. */
    unref?: boolean;
}
/** The module to run for a thread count: the threads build above one thread, else single. */
export declare function defaultWasmModule(threads: number): URL;
/** The thread count to run with: the host's parallelism by default, a request checked against it. */
export declare function resolveThreads(threads?: number): number;
/**
 * The bb wasm module in-process: the main instance in a worker by default, wasi
 * threads on further workers. The workers are ipc-runtime's own, spawned with the literal
 * expression bundlers detect, so they ship as worker chunks of the consuming application.
 */
export declare function createWasmBackend(options?: BbWasmOptions): Promise<WasmFfiBackend>;
/**
 * The module on the calling thread, single-threaded: every call blocks until it returns, with no
 * worker and no message passing. This is the form for short synchronous work such as hashing,
 * including on a browser's main thread.
 */
export declare function createWasmBackendSync(options?: BbWasmOptions): Promise<WasmFfiBackendSync>;
//# sourceMappingURL=wasm.d.ts.map