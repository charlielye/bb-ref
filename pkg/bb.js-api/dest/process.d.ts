import { type ServiceProcessOptions, type SpawnedProcessBackend, type SpawnedProcessBackendSync } from '@aztec-foundation/ipc-runtime';
export type BbTransport = 'uds' | 'shm';
/**
 * Options for running 'bb' as a spawned process (node only). See ServiceProcessOptions
 * in ipc-runtime for the rest: binaryPath, threads, logger, env, extraArgs, respawn and unref.
 */
export interface BbProcessOptions extends ServiceProcessOptions {
    transport?: BbTransport;
}
/** The name this package's first version used for the spawn options. */
export type BbServiceOptions = BbProcessOptions;
/**
 * Spawn 'bb' and connect to it over uds or shm. Process
 * lifecycle — connectivity, death detection, optional respawn, teardown — is owned by the backend
 * and never leaks onto the caller's API.
 */
export declare function spawnProcessBackend(options?: BbProcessOptions): Promise<SpawnedProcessBackend>;
/** The synchronous form: shared memory is the one transport with a synchronous client. */
export declare function spawnProcessBackendSync(options?: BbProcessOptions): Promise<SpawnedProcessBackendSync>;
//# sourceMappingURL=process.d.ts.map