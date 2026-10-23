import type { WasmPlatform, WorkerHandle, WorkerSide } from "./platform.js";
export interface MainWorkerOptions {
    /** Spawns the thread pool's workers (see `WasmFfiBinding` for why this is a factory). */
    createThreadWorker: () => WorkerHandle;
}
/**
 * Body of the worker hosting a module's main instance: create the engine on `init`, serve `call`
 * requests, tear down on `destroy`. Calls run to completion on this worker's thread; the parent's
 * event loop stays free.
 */
export declare function runMainWorker(side: WorkerSide, platform: WasmPlatform, opts: MainWorkerOptions): void;
