import { Worker, type MessagePort } from "node:worker_threads";
import type { WasmPlatform, WorkerHandle, WorkerSide } from "../platform.js";
/** The parent's handle on a `worker_threads` worker. */
export declare function nodeWorkerHandle(worker: Worker): WorkerHandle;
export declare const nodePlatform: WasmPlatform;
/** The worker's side of a node `worker_threads` channel. */
export declare function nodeWorkerSide(port?: MessagePort | null): WorkerSide;
