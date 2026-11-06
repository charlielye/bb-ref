import type { IpcClientAsync, IpcClientSync } from '@aztec-foundation/ipc-runtime/registry';
import { registerBackend as register } from '@aztec-foundation/ipc-runtime/registry';
import { AsyncApi } from './generated/async.js';
import { SyncApi } from './generated/sync.js';
export * from './generated/api_types.js';
export { AsyncApi } from './generated/async.js';
export { SyncApi } from './generated/sync.js';
export type { RegisteredBackends } from '@aztec-foundation/ipc-runtime/registry';
/** Make these the backends for Bb in this app; a native backend package calls it on import. */
export declare function registerBackend(factories: Parameters<typeof register>[1]): void;
export interface BbCreateOptions {
    /** A backend object (anything with call()/destroy()); default: the one a native package registered. */
    backend?: IpcClientAsync;
}
export interface BbCreateSyncOptions {
    backend?: IpcClientSync;
}
export declare function createBackend(options?: BbCreateOptions): Promise<IpcClientAsync>;
export declare function createBackendSync(options?: BbCreateSyncOptions): Promise<IpcClientSync>;
export declare class BbService extends AsyncApi {
    private constructor();
    static create(options?: BbCreateOptions): Promise<BbService>;
}
export declare class BbServiceSync extends SyncApi {
    private constructor();
    static create(options?: BbCreateSyncOptions): Promise<BbServiceSync>;
}
//# sourceMappingURL=react-native.d.ts.map