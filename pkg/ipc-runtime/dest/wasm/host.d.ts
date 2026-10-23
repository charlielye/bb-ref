export interface InstanceOptions {
    module: WebAssembly.Module;
    memory: WebAssembly.Memory;
    /** WASI environ for the module (e.g. `HARDWARE_CONCURRENCY`). */
    env?: Record<string, string>;
    logger?: (msg: string) => void;
    /**
     * wasi-threads `thread-spawn`: start the module's thread entry on another instance and return
     * its tid, or a negative errno when no thread can be started.
     */
    spawnThread?: (startArg: number) => number;
    /**
     * Export taking `(input, input_len, output_out, output_len_out)`. Default: the module's one
     * export named `<service>_ipc_ffi_entry` (or bare `ipc_ffi_entry`).
     */
    entry?: string;
    /** Call the reactor's `_initialize` after instantiation (main instances only). Default true. */
    runInitialize?: boolean;
    /** Threads this instance may use, for the WASI environ the module reads. Default 1. */
    threads?: number;
}
/** Every FFI entry export ends with this; the generated ones are prefixed by their service. */
export declare const ENTRY_SUFFIX = "ipc_ffi_entry";
/** Allocator pairs tried after the entry's own `<service>_ipc_ffi_alloc`/`_free`. */
export declare const FALLBACK_ALLOCATOR_EXPORTS: Array<[string, string]>;
export declare class WasmInstanceHost {
    readonly instance: WebAssembly.Instance;
    readonly memory: WebAssembly.Memory;
    private readonly entry;
    private readonly alloc;
    private readonly free;
    readonly logger: (msg: string) => void;
    private readonly stderr;
    private constructor();
    static instantiate(opts: InstanceOptions): Promise<WasmInstanceHost>;
    /** Call an arbitrary numeric export (used by thread workers for `wasi_thread_start`). */
    callExport(name: string, ...args: number[]): number;
    /** Views over module memory, rebuilt only when a call grows it and detaches the old buffer. */
    private viewed?;
    private bytes;
    private words;
    private refreshViews;
    /**
     * A buffer held across calls for the request and the two response slots, so a round trip costs
     * no allocator traffic of its own. It only ever grows, and calls are serialized (the entry is
     * synchronous and single-threaded), so one buffer is enough.
     */
    private scratch;
    private scratchCapacity;
    private reserveScratch;
    /**
     * One FFI round trip: request bytes in, a copy of the response bytes out. The request is placed
     * in module memory, and the response is read from where the module left it and released with the
     * module's own free, as the FFI contract requires.
     */
    call(input: Uint8Array): Uint8Array;
}
