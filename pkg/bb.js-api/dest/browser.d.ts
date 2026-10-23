import type { IpcClientAsync, IpcClientSync } from '@aztec-foundation/ipc-runtime';
import { AsyncApi } from './generated/async.js';
import { SyncApi } from './generated/sync.js';
import type { Init } from './generated/api_types.js';
import { type BbWasmOptions } from './wasm.js';
export * from './generated/api_types.js';
export { AsyncApi } from './generated/async.js';
export { SyncApi } from './generated/sync.js';
export * from './wasm.js';
export type BbBackend = 'wasm';
/** Options for BbService.create / createBackend (browser: the wasm module, or a backend object). */
export interface BbCreateOptions {
    backend?: BbBackend | IpcClientAsync;
    /** Worker threads to run with; more than one needs a cross-origin isolated page (COOP/COEP). */
    threads?: number;
    logger?: (msg: string) => void;
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
    backend?: BbBackend | IpcClientSync;
    logger?: (msg: string) => void;
    unref?: boolean;
    /**
     * The Init command sent before the service is handed out (calling anything before it is
     * undefined). Unset sends it with its defaults; `false` skips it, for a caller that sends it later.
     */
    init?: false | Init;
    wasm?: Omit<BbWasmOptions, 'threads' | 'worker' | 'logger'>;
}
export declare function createBackend(options?: BbCreateOptions): Promise<IpcClientAsync>;
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
//# sourceMappingURL=browser.d.ts.map