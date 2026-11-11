import type { IpcClientAsync, IpcClientSync } from "./types.js";
export type { IpcClientAsync, IpcClientSync };
/**
 * Backends a native package registers for a service, so an app that installs it needs no wiring.
 * This is how a host with no backend of its own is served — React Native, where Hermes has no
 * WebAssembly and no workers, and the service is reached through a linked library instead.
 */
export interface RegisteredBackends {
    async?: () => Promise<IpcClientAsync> | IpcClientAsync;
    sync?: () => Promise<IpcClientSync> | IpcClientSync;
}
/** Make `factories` the backends for `service`; a native backend package calls this when imported. */
export declare function registerBackend(service: string, factories: RegisteredBackends): void;
/**
 * The registered backend for a service, or a message naming what to install. `hint` is the
 * package a caller should be told about.
 */
export declare function registeredBackend<K extends keyof RegisteredBackends>(service: string, kind: K, hint: string): NonNullable<RegisteredBackends[K]>;
