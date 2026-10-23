import { type WasmFfiBinding } from "../entry.js";
import { browserPlatform, browserWorkerHandle, browserWorkerSide } from "./platform.js";
export * from "../entry.js";
export { browserPlatform as platform, browserWorkerHandle as workerHandle, browserWorkerSide as workerSide, };
/**
 * The worker scripts spawned for the main instance and each wasi thread, with the literal
 * expression bundlers detect so they are emitted as worker chunks of the consuming application.
 */
export declare const binding: WasmFfiBinding;
export declare const createWasmFfiBackend: (opts: import("./index.js").WasmFfiBackendOptions) => Promise<import("./index.js").WasmFfiBackend>, createWasmFfiBackendSync: (opts: import("./index.js").WasmFfiOptions) => Promise<import("./index.js").WasmFfiBackendSync>, sharedMemoryAvailable: () => boolean;
