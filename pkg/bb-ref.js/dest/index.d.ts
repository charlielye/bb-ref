import { type IpcClientAsync, type IpcClientSync } from '@aztec-foundation/ipc-runtime';
import { AsyncApi } from './generated/async.js';
import { SyncApi } from './generated/sync.js';
import type { Init } from './generated/api_types.js';
import { type BbWasmOptions } from './wasm.js';
export * from './generated/api_types.js';
export { AsyncApi } from './generated/async.js';
export { SyncApi } from './generated/sync.js';
export * from './wasm.js';
export { findBbBinary } from './platform.js';
export type BbBackend = 'wasm';
/** Options for BbService.create / createBackend. */
export interface BbCreateOptions {
    /**
     * Unset: the wasm module. A name forces that backend, with no fallback. An object (anything with
     * call()/destroy(), e.g. a bridge to a natively linked library) is used as is.
     */
    backend?: BbBackend | IpcClientAsync;
    /** Threads the service may use: a process reads them from HARDWARE_CONCURRENCY/RAYON_NUM_THREADS; wasm runs that many. */
    threads?: number;
    logger?: (msg: string) => void;
    /** Let node exit while the backend is alive (a process that watches its parent, or the wasm workers). */
    unref?: boolean;
    /**
     * The Init command sent before the service is handed out (calling anything before it is
     * undefined). Unset sends it with its defaults; `false` skips it, for a caller that sends it later.
     */
    init?: false | Init;
    wasm?: Omit<BbWasmOptions, 'threads' | 'logger'>;
}
/** Options for BbServiceSync.create / createBackendSync. */
export interface BbCreateSyncOptions {
    /** As for the asynchronous form; the synchronous wasm module runs on the calling thread, single-threaded. */
    backend?: BbBackend | IpcClientSync;
    /** Threads a spawned process may use (the synchronous wasm module always has one). */
    threads?: number;
    logger?: (msg: string) => void;
    unref?: boolean;
    /**
     * The Init command sent before the service is handed out (calling anything before it is
     * undefined). Unset sends it with its defaults; `false` skips it, for a caller that sends it later.
     */
    init?: false | Init;
    wasm?: Omit<BbWasmOptions, 'threads' | 'worker' | 'logger'>;
}
/**
 * The backend `BbService.create` would use for `options`, for facades that wrap the
 * generated API themselves. Unset backend: the wasm module.
 */
export declare function createBackend(options?: BbCreateOptions): Promise<IpcClientAsync>;
/** The synchronous counterpart of createBackendthe single-threaded wasm module. */
export declare function createBackendSync(options?: BbCreateSyncOptions): Promise<IpcClientSync>;
/**
 * The Bb service: the generated API over whichever backend `create` chose, forced, or was
 * given.
 */
export declare class BbService extends AsyncApi {
    private constructor();
    static create(options?: BbCreateOptions): Promise<BbService>;
    private static started;
    /** The service over the in-process wasm module (no fallback). */
    static wasm(options?: BbWasmOptions & {
        init?: false | Init;
    }): Promise<BbService>;
}
/** The synchronous Bb service: every call blocks the calling thread until the service answers. */
export declare class BbServiceSync extends SyncApi {
    private constructor();
    static create(options?: BbCreateSyncOptions): Promise<BbServiceSync>;
    private static started;
    /** The service over the single-threaded in-process wasm module (no fallback). */
    static wasm(options?: BbWasmOptions & {
        init?: false | Init;
    }): Promise<BbServiceSync>;
}
//# sourceMappingURL=index.d.ts.map