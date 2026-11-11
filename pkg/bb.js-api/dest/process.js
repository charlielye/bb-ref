import { spawnServiceBackendSync, spawnServiceBackend, } from '@aztec-foundation/ipc-runtime';
import { BINARY } from './platform.js';
/**
 * Spawn 'bb' and connect to it over uds or shm. Process
 * lifecycle — connectivity, death detection, optional respawn, teardown — is owned by the backend
 * and never leaks onto the caller's API.
 */
export function spawnProcessBackend(options = {}) {
    return spawnServiceBackend(BINARY, 'uds', options);
}
/** The synchronous form: shared memory is the one transport with a synchronous client. */
export function spawnProcessBackendSync(options = {}) {
    return spawnServiceBackendSync(BINARY, options);
}
