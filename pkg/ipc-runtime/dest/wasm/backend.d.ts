import type { IpcClientAsync, IpcClientSync } from "../types.js";
import { WasmInstanceHost } from "./host.js";
import { type WasmModuleSource } from "./module_source.js";
import type { WasmPlatform, WorkerHandle } from "./platform.js";
/** Options shared by every way of running an FFI-contract module. */
export interface WasmFfiOptions {
    /** The module: a compiled `Module`, bytes (gzipped or not), a `Response`, or a URL/string. */
    module: WasmModuleSource;
    /** Threads to run with (1 = no worker threads). Default: the platform's parallelism, capped at 32. */
    threads?: number;
    /** Linear memory bounds in 64 KiB pages; `shared` defaults to `threads > 1`. */
    memory?: {
        initial?: number;
        maximum?: number;
        shared?: boolean;
    };
    /** WASI environ for the module. `HARDWARE_CONCURRENCY` and `RAYON_NUM_THREADS` default to `threads`. */
    env?: Record<string, string>;
    logger?: (msg: string) => void;
    /** FFI entry export; default: the module's one `<service>_ipc_ffi_entry` export. */
    entry?: string;
}
/**
 * What a platform entry (`index.node.ts` / `index.browser.ts`) binds for the backend. Workers are
 * created through factories rather than URLs: bundlers only bundle a worker's dependency graph when
 * they see the literal `new Worker(new URL('./x.js', import.meta.url), { type: 'module' })`, so
 * that expression has to live in the code that owns the worker script.
 */
export interface WasmFfiBinding {
    platform: WasmPlatform;
    /** Spawn a worker hosting one module instance per wasi thread. */
    createThreadWorker: () => WorkerHandle;
    /** Spawn the worker hosting the main instance when `worker: true`. */
    createMainWorker: () => WorkerHandle;
}
export interface WasmFfiBackendOptions extends WasmFfiOptions {
    /**
     * Run the main instance in a dedicated worker (default true), so a long call never blocks the
     * caller's event loop and, in browsers, the thread pool is spawned from a worker. With `false`
     * the main instance runs on the calling thread and every call blocks it until it returns.
     */
    worker?: boolean;
    /** Override the worker factories the platform entry binds. */
    createThreadWorker?: () => WorkerHandle;
    createMainWorker?: () => WorkerHandle;
}
/** Above this, more wasi threads stop paying for themselves; the engine clamps to it. */
export declare const MAX_THREADS = 32;
/**
 * The module running on the current thread: memory, main instance, and the workers serving its
 * `thread-spawn` requests. `call` is synchronous and blocks until the module returns.
 */
export declare class WasmFfiEngine {
    /** The module instance, for reaching exports of its own beyond the FFI entry. */
    readonly host: WasmInstanceHost;
    private readonly threadWorkers;
    readonly memory: WebAssembly.Memory;
    readonly threads: number;
    private constructor();
    static create(opts: WasmFfiOptions, binding: WasmFfiBinding): Promise<WasmFfiEngine>;
    call(input: Uint8Array): Uint8Array;
    unref(): void;
    destroy(): Promise<void>;
}
/**
 * Asynchronous FFI backend over a wasm module. Implements the runtime's `IpcClientAsync`, so the
 * generated `AsyncApi` sits on it exactly as it sits on a spawned process.
 */
export declare class WasmFfiBackend implements IpcClientAsync {
    private readonly engine;
    private readonly worker;
    private seq;
    private readonly pending;
    /** The module's memory when it is shared and lives in the main worker (see `memoryBytes`). */
    private sharedMemory?;
    private constructor();
    /**
     * The module's linear memory size in bytes, readable at any time (also while a call runs, when the
     * memory is shared). Wasm memory only grows, so this is the instance's high-water mark. Undefined
     * when the module runs in a worker with an unshared memory.
     */
    memoryBytes(): number | undefined;
    static create(opts: WasmFfiBackendOptions, binding: WasmFfiBinding): Promise<WasmFfiBackend>;
    private onWorkerMessage;
    call(input: Uint8Array): Promise<Uint8Array>;
    /** Let the host process exit even while the module's workers are alive (node). */
    unref(): void;
    destroy(): Promise<void>;
}
/**
 * Synchronous FFI backend: the module runs on the calling thread and every call blocks until it
 * returns. Defaults to one thread, since a blocked caller cannot service anything else.
 */
export declare class WasmFfiBackendSync implements IpcClientSync {
    private readonly engine;
    private constructor();
    /** The module's linear memory size in bytes (its high-water mark: wasm memory only grows). */
    memoryBytes(): number;
    static create(opts: WasmFfiOptions, binding: WasmFfiBinding): Promise<WasmFfiBackendSync>;
    call(input: Uint8Array): Uint8Array;
    unref(): void;
    destroy(): void;
}
