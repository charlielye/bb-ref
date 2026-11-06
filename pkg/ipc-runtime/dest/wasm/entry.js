// What both platform entries (`index.node.ts`, `index.browser.ts`) share. They differ only in the
// platform they bind and in how they spawn a worker, so everything else lives here.
import { WasmFfiBackend, WasmFfiBackendSync, } from "./backend.js";
export { MAX_THREADS, WasmFfiBackend, WasmFfiBackendSync, WasmFfiEngine, } from "./backend.js";
export { compileWasmModule } from "./module_source.js";
export { WasmExitError } from "./wasi_shim.js";
export { runMainWorker } from "./main_worker.js";
export { runThreadWorker } from "./thread_worker.js";
export { chooseWasmModule, resolveWasmThreads } from "./service.js";
export { registerBackend, registeredBackend, } from "../backend_registry.js";
/** The entry points a platform offers, over the workers and platform it binds. */
export function bindEntry(binding) {
    return {
        createWasmFfiBackend: (opts) => WasmFfiBackend.create(opts, binding),
        createWasmFfiBackendSync: (opts) => WasmFfiBackendSync.create(opts, binding),
        sharedMemoryAvailable: () => binding.platform.sharedMemoryAvailable(),
    };
}
