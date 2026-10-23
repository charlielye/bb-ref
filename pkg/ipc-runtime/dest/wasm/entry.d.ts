import { type WasmFfiBackendOptions, type WasmFfiBinding, type WasmFfiOptions, WasmFfiBackend, WasmFfiBackendSync } from "./backend.js";
export type { WasmModuleSource } from "./module_source.js";
export type { WasmPlatform, WorkerHandle, WorkerSide } from "./platform.js";
export type { WasmFfiBackendOptions, WasmFfiBinding, WasmFfiOptions };
export { MAX_THREADS, WasmFfiBackend, WasmFfiBackendSync, WasmFfiEngine, } from "./backend.js";
export { compileWasmModule } from "./module_source.js";
export { WasmExitError } from "./wasi_shim.js";
export { runMainWorker } from "./main_worker.js";
export { runThreadWorker } from "./thread_worker.js";
export { chooseWasmModule, resolveWasmThreads } from "./service.js";
export { type RegisteredBackends, registerBackend, registeredBackend, } from "../backend_registry.js";
export interface WasmEntry {
    createWasmFfiBackend(opts: WasmFfiBackendOptions): Promise<WasmFfiBackend>;
    createWasmFfiBackendSync(opts: WasmFfiOptions): Promise<WasmFfiBackendSync>;
    /** Whether this platform can run a module's threads build (a shared memory is available). */
    sharedMemoryAvailable(): boolean;
}
/** The entry points a platform offers, over the workers and platform it binds. */
export declare function bindEntry(binding: WasmFfiBinding): WasmEntry;
