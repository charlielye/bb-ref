import { type WasmFfiBinding } from "../entry.js";
import { nodePlatform, nodeWorkerHandle, nodeWorkerSide } from "./platform.js";
export * from "../entry.js";
export { nodePlatform as platform, nodeWorkerHandle as workerHandle, nodeWorkerSide as workerSide, };
/** The worker scripts the node entry spawns for the main instance and each wasi thread. */
export declare const binding: WasmFfiBinding;
export declare const createWasmFfiBackend: (opts: import("./index.js").WasmFfiBackendOptions) => Promise<import("./index.js").WasmFfiBackend>, createWasmFfiBackendSync: (opts: import("./index.js").WasmFfiOptions) => Promise<import("./index.js").WasmFfiBackendSync>, sharedMemoryAvailable: () => boolean;
