import type { WasmPlatform } from "./platform.js";
/**
 * How many threads to run a module with: the platform's parallelism when the caller named none,
 * else the number asked for, checked against what this host can actually give. More than one
 * thread needs a shared memory, which browsers only allow on a cross-origin isolated page, and
 * asking for it where it cannot be had is an error rather than a silent downgrade.
 */
export declare function resolveWasmThreads(platform: WasmPlatform, label: string, threads?: number): number;
/**
 * Which of a package's own modules to run: the threads build for more than one thread, otherwise
 * the single-thread build. Each stands in for the other when a package ships only one, and a
 * wide-arithmetic build replaces its counterpart where the engine supports the proposal.
 */
export declare function chooseWasmModule(modules: {
    single?: URL;
    threads?: URL;
    wideSingle?: URL;
    wideThreads?: URL;
}, label: string, threads: number): URL;
