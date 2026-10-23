/**
 * The slice of WASI preview1 an in-process service needs: clocks, randomness, environ/args,
 * stdout/stderr, exit. Every other WASI function the module imports is answered with `ENOSYS`,
 * so linking never fails on a syscall the module carries but never calls (file I/O in a module
 * that gets its inputs over the FFI entry, for instance).
 */
export declare const WASI_NAMESPACE = "wasi_snapshot_preview1";
/** Raised when the module calls `proc_exit`; the process must not actually exit. */
export declare class WasmExitError extends Error {
    readonly code: number;
    constructor(code: number);
}
export interface WasiShimOptions {
    /** Environment visible to the module through `environ_get` (e.g. `HARDWARE_CONCURRENCY`). */
    env?: Record<string, string>;
    /** Program arguments visible through `args_get`. */
    args?: string[];
    /** Receives complete lines written to fd 1 / fd 2. */
    onStdout?: (line: string) => void;
    onStderr?: (line: string) => void;
}
/**
 * Build the WASI import object for `module`. `memory` is read lazily on every call because the
 * module's memory may grow (and its `buffer` be detached) between calls.
 */
export declare function createWasiImports(module: WebAssembly.Module, memory: () => WebAssembly.Memory, opts?: WasiShimOptions): Record<string, (...args: number[]) => number>;
