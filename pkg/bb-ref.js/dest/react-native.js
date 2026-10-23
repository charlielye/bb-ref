import { registerBackend as register, registeredBackend } from '@aztec-foundation/ipc-runtime/registry';
import { AsyncApi } from './generated/async.js';
import { SyncApi } from './generated/sync.js';
export * from './generated/api_types.js';
export { AsyncApi } from './generated/async.js';
export { SyncApi } from './generated/sync.js';
/** Make these the backends for Bb in this app; a native backend package calls it on import. */
export function registerBackend(factories) {
    register('Bb', factories);
}
export async function createBackend(options = {}) {
    return options.backend ?? (await registeredBackend('Bb', 'async', 'bb-ref.js')());
}
export async function createBackendSync(options = {}) {
    return options.backend ?? (await registeredBackend('Bb', 'sync', 'bb-ref.js')());
}
export class BbService extends AsyncApi {
    constructor(backend) {
        super(backend);
    }
    static async create(options = {}) {
        return new BbService(await createBackend(options));
    }
}
export class BbServiceSync extends SyncApi {
    constructor(backend) {
        super(backend);
    }
    static async create(options = {}) {
        return new BbServiceSync(await createBackendSync(options));
    }
}
