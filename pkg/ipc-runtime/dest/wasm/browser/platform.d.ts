import type { WasmPlatform, WorkerHandle, WorkerSide } from "../platform.js";
/** The parent's handle on a browser `Worker`. */
export declare function browserWorkerHandle(worker: Worker): WorkerHandle;
export declare const browserPlatform: WasmPlatform;
/** The worker's side of a browser `Worker` channel. */
export declare function browserWorkerSide(): WorkerSide;
