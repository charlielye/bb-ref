import { pickServiceBackend, } from '@aztec-foundation/ipc-runtime';
import { AsyncApi } from './generated/async.js';
import { SyncApi } from './generated/sync.js';
import { createWasmBackend, createWasmBackendSync } from './wasm.js';
export * from './generated/api_types.js';
export { AsyncApi } from './generated/async.js';
export { SyncApi } from './generated/sync.js';
export * from './wasm.js';
export { findBbBinary } from './platform.js';
/**
 * The backend `BbService.create` would use for `options`, for facades that wrap the
 * generated API themselves. Unset backend: the wasm module.
 */
export async function createBackend(options = {}) {
    const common = { threads: options.threads, logger: options.logger, unref: options.unref };
    return pickServiceBackend(options.backend, {
        label: 'bb-ref.js',
        logger: options.logger,
        wasm: { create: () => createWasmBackend({ ...common, ...options.wasm }) },
    });
}
/** The synchronous counterpart of createBackendthe single-threaded wasm module. */
export async function createBackendSync(options = {}) {
    const common = { threads: options.threads, logger: options.logger, unref: options.unref };
    return pickServiceBackend(options.backend, {
        label: 'bb-ref.js',
        logger: options.logger,
        wasm: { create: () => createWasmBackendSync({ logger: options.logger, unref: options.unref, ...options.wasm }) },
    });
}
/**
 * The Bb service: the generated API over whichever backend `create` chose, forced, or was
 * given.
 */
export class BbService extends AsyncApi {
    constructor(backend) {
        super(backend);
    }
    static async create(options = {}) {
        return BbService.started(new BbService(await createBackend(options)), options.init);
    }
    static async started(svc, init) {
        if (init !== false) {
            // Every field of an init command is optional (TypeScriptCodegen.initCommand), so none is a valid command.
            await svc.init(init ?? {});
        }
        return svc;
    }
    /** The service over the in-process wasm module (no fallback). */
    static async wasm(options = {}) {
        return BbService.started(new BbService(await createWasmBackend(options)), options.init);
    }
}
/** The synchronous Bb service: every call blocks the calling thread until the service answers. */
export class BbServiceSync extends SyncApi {
    constructor(backend) {
        super(backend);
    }
    static async create(options = {}) {
        return BbServiceSync.started(new BbServiceSync(await createBackendSync(options)), options.init);
    }
    static async started(svc, init) {
        if (init !== false) {
            // Every field of an init command is optional (TypeScriptCodegen.initCommand), so none is a valid command.
            svc.init(init ?? {});
        }
        return svc;
    }
    /** The service over the single-threaded in-process wasm module (no fallback). */
    static async wasm(options = {}) {
        return BbServiceSync.started(new BbServiceSync(await createWasmBackendSync(options)), options.init);
    }
}
