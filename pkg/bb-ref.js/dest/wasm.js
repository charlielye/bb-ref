import { chooseWasmModule, createWasmFfiBackend, createWasmFfiBackendSync, platform, resolveWasmThreads, } from '@aztec-foundation/ipc-runtime/wasm';
export { sharedMemoryAvailable } from '@aztec-foundation/ipc-runtime/wasm';
// This package's own modules, as URLs relative to its own files: only the package can express
// these, which is why the choosing lives here and the deciding does not.
const MODULES = {
    threads: new URL('../wasm/bb-ref-threads.wasm', import.meta.url),
    single: undefined,
    wideThreads: new URL('../wasm/bb-ref-wide-threads.wasm', import.meta.url),
};
/** The module to run for a thread count: the threads build above one thread, else single. */
export function defaultWasmModule(threads) {
    return chooseWasmModule(MODULES, 'bb-ref.js', threads);
}
/** The thread count to run with: the host's parallelism by default, a request checked against it. */
export function resolveThreads(threads) {
    return resolveWasmThreads(platform, 'bb-ref.js', threads);
}
/**
 * The bb-ref wasm module in-process: the main instance in a worker by default, wasi
 * threads on further workers. The workers are ipc-runtime's own, spawned with the literal
 * expression bundlers detect, so they ship as worker chunks of the consuming application.
 */
export async function createWasmBackend(options = {}) {
    const threads = resolveThreads(options.threads);
    const backend = await createWasmFfiBackend({
        module: options.module ?? defaultWasmModule(threads),
        threads,
        memory: options.memory,
        env: options.env,
        logger: options.logger,
        worker: options.worker,
        entry: 'bb_ipc_ffi_entry',
    });
    if (options.unref) {
        backend.unref();
    }
    return backend;
}
/**
 * The module on the calling thread, single-threaded: every call blocks until it returns, with no
 * worker and no message passing. This is the form for short synchronous work such as hashing,
 * including on a browser's main thread.
 */
export async function createWasmBackendSync(options = {}) {
    const backend = await createWasmFfiBackendSync({
        module: options.module ?? defaultWasmModule(1),
        threads: 1,
        memory: options.memory,
        env: options.env,
        logger: options.logger,
        entry: 'bb_ipc_ffi_entry',
    });
    if (options.unref) {
        backend.unref();
    }
    return backend;
}
