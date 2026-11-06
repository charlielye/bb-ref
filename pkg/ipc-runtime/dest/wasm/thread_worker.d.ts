import type { WorkerSide } from "./platform.js";
/**
 * Body of a wasi-threads worker: instantiate the module over the shared memory on `init`, then run
 * the module's thread entry on `start`. A thread runs to completion inside `wasi_thread_start`, so
 * this worker serves that one thread and is done; the parent creates one worker per thread the
 * module spawns.
 */
export declare function runThreadWorker(side: WorkerSide): void;
