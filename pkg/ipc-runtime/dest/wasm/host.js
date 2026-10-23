import { WASI_NAMESPACE, createWasiImports } from "./wasi_shim.js";
/** Every FFI entry export ends with this; the generated ones are prefixed by their service. */
export const ENTRY_SUFFIX = "ipc_ffi_entry";
/** Allocator pairs tried after the entry's own `<service>_ipc_ffi_alloc`/`_free`. */
export const FALLBACK_ALLOCATOR_EXPORTS = [
    ["malloc", "free"],
    ["bbmalloc", "bbfree"],
];
/** The response pointer and length the entry writes back, ahead of the request in the scratch. */
const SLOTS_BYTES = 8;
/** Starting size of the request scratch; it grows to fit and never shrinks. */
const MIN_SCRATCH_BYTES = 64 * 1024;
/** The entry export to use and the service prefix it carries (`bb_` for `bb_ipc_ffi_entry`). */
function findEntry(exports, wanted) {
    const prefixOf = (name) => name.endsWith(ENTRY_SUFFIX) ? name.slice(0, -ENTRY_SUFFIX.length) : "";
    if (wanted) {
        if (typeof exports[wanted] !== "function") {
            throw new Error(`wasm module does not export ${wanted}`);
        }
        return { entry: wanted, prefix: prefixOf(wanted) };
    }
    const candidates = Object.keys(exports).filter((name) => typeof exports[name] === "function" &&
        (name === ENTRY_SUFFIX || name.endsWith(`_${ENTRY_SUFFIX}`)));
    if (candidates.length === 0) {
        throw new Error(`wasm module exports no FFI entry (*_${ENTRY_SUFFIX})`);
    }
    if (candidates.length > 1) {
        throw new Error(`wasm module exports several FFI entries (${candidates.join(", ")}); pass \`entry\``);
    }
    return { entry: candidates[0], prefix: prefixOf(candidates[0]) };
}
/**
 * One instance of an FFI-contract module: imports resolved (WASI shim, wasi-threads, module
 * specific host imports), `_initialize` run, and the `<service>_ipc_ffi_entry` call protocol
 * implemented over the module's own allocator.
 */
/**
 * The tail of what the module wrote to stderr during the current call. A module compiled without
 * exceptions cannot return a message when it gives up: it writes one out and exits. Keeping the
 * text is what turns the bare `proc_exit` or trap the caller would otherwise see into an error
 * that says what went wrong.
 */
class StderrTail {
    static MAX_LINES = 8;
    lines = [];
    record(line) {
        this.lines.push(line);
        if (this.lines.length > StderrTail.MAX_LINES) {
            this.lines.shift();
        }
    }
    reset() {
        this.lines.length = 0;
    }
    text() {
        return this.lines.join("\n").trim();
    }
}
export class WasmInstanceHost {
    instance;
    memory;
    entry;
    alloc;
    free;
    logger;
    stderr;
    constructor(instance, memory, entry, alloc, free, logger, stderr) {
        this.instance = instance;
        this.memory = memory;
        this.entry = entry;
        this.alloc = alloc;
        this.free = free;
        this.logger = logger;
        this.stderr = stderr;
    }
    static async instantiate(opts) {
        // A module either imports its memory, and is handed the one the caller made, or defines and
        // exports its own — the default for a Rust cdylib. Which it is is only settled below, after
        // instantiation, so everything reading memory goes through this.
        let memory = opts.memory;
        const logger = opts.logger ?? (() => { });
        const stderr = new StderrTail();
        const imports = {
            env: { memory },
            [WASI_NAMESPACE]: createWasiImports(opts.module, () => memory, {
                env: opts.env,
                onStderr: (line) => {
                    stderr.record(line);
                    logger(line);
                },
                onStdout: logger,
            }),
            wasi: {
                "thread-spawn": (startArg) => opts.spawnThread ? opts.spawnThread(startArg >>> 0) : -1,
            },
        };
        const missing = [];
        for (const imp of WebAssembly.Module.imports(opts.module)) {
            if (imports[imp.module]?.[imp.name] !== undefined) {
                continue;
            }
            missing.push(`${imp.module}.${imp.name} (${imp.kind})`);
        }
        if (missing.length > 0) {
            throw new Error(`wasm module imports what this host does not provide; it must be a WASI reactor: ${missing.join(", ")}`);
        }
        const instance = await WebAssembly.instantiate(opts.module, imports);
        const exports = instance.exports;
        if (exports.memory instanceof WebAssembly.Memory) {
            // The module defined its own; the one passed in (if any) is not what it reads and writes.
            memory = exports.memory;
        }
        if (opts.runInitialize !== false &&
            typeof exports._initialize === "function") {
            exports._initialize();
        }
        const { entry, prefix } = findEntry(exports, opts.entry);
        const allocatorExports = [
            [`${prefix}ipc_ffi_alloc`, `${prefix}ipc_ffi_free`],
            ...FALLBACK_ALLOCATOR_EXPORTS,
        ];
        const pair = allocatorExports.find(([a, f]) => typeof exports[a] === "function" && typeof exports[f] === "function");
        if (!pair) {
            throw new Error(`wasm module exports no allocator pair (looked for ${allocatorExports
                .map(([a, f]) => `${a}/${f}`)
                .join(", ")})`);
        }
        return new WasmInstanceHost(instance, memory, exports[entry], exports[pair[0]], exports[pair[1]], logger, stderr);
    }
    /** Call an arbitrary numeric export (used by thread workers for `wasi_thread_start`). */
    callExport(name, ...args) {
        const fn = this.instance.exports[name];
        if (typeof fn !== "function") {
            throw new Error(`wasm module does not export ${name}`);
        }
        return fn(...args);
    }
    /** Views over module memory, rebuilt only when a call grows it and detaches the old buffer. */
    viewed;
    bytes;
    words;
    refreshViews() {
        if (this.viewed !== this.memory.buffer) {
            this.viewed = this.memory.buffer;
            this.bytes = new Uint8Array(this.memory.buffer);
            this.words = new DataView(this.memory.buffer);
        }
    }
    /**
     * A buffer held across calls for the request and the two response slots, so a round trip costs
     * no allocator traffic of its own. It only ever grows, and calls are serialized (the entry is
     * synchronous and single-threaded), so one buffer is enough.
     */
    scratch = 0;
    scratchCapacity = 0;
    reserveScratch(size) {
        if (size <= this.scratchCapacity) {
            return this.scratch;
        }
        const capacity = Math.max(size, this.scratchCapacity * 2, MIN_SCRATCH_BYTES);
        const scratch = this.alloc(capacity) >>> 0;
        if (scratch === 0) {
            throw new Error(`wasm module could not allocate a ${capacity} byte request buffer`);
        }
        if (this.scratch !== 0) {
            this.free(this.scratch);
        }
        this.scratch = scratch;
        this.scratchCapacity = capacity;
        return scratch;
    }
    /**
     * One FFI round trip: request bytes in, a copy of the response bytes out. The request is placed
     * in module memory, and the response is read from where the module left it and released with the
     * module's own free, as the FFI contract requires.
     */
    call(input) {
        const slots = this.reserveScratch(SLOTS_BYTES + input.length);
        const inPtr = slots + SLOTS_BYTES;
        let outPtr = 0;
        this.stderr.reset();
        try {
            this.refreshViews();
            this.bytes.set(input, inPtr);
            this.words.setUint32(slots, 0, true);
            this.words.setUint32(slots + 4, 0, true);
            try {
                this.entry(inPtr, input.length, slots, slots + 4);
            }
            catch (cause) {
                const reported = this.stderr.text();
                if (!reported) {
                    throw cause;
                }
                throw new Error(reported, { cause });
            }
            // The call may have grown memory, detaching the buffer the views were built over.
            this.refreshViews();
            outPtr = this.words.getUint32(slots, true);
            const outLen = this.words.getUint32(slots + 4, true);
            return this.bytes.slice(outPtr, outPtr + outLen);
        }
        finally {
            if (outPtr !== 0) {
                this.free(outPtr);
            }
        }
    }
}
