import { SpawnedProcessBackend, SpawnedProcessBackendSync } from "./spawned_backend.js";
import type { IpcClientAsync, IpcClientSync } from "./types.js";
/**
 * How a generated client package reaches its service as a spawned process. Everything here is
 * fixed at generation time from the schema and the flags: the package supplies it, this module
 * does the work, so the same logic is not regenerated into every package.
 */
export interface ServiceBinary {
    /** Binary name, used for the arch-package lookup, log labels and errors. */
    name: string;
    /** Environment variable that overrides the binary's path. */
    envVar: string;
    /** npm package holding the binary, per platform (`process.arch`-`process.platform`). */
    archPackages: Record<string, string>;
    /** Argv template; each '{path}' is replaced with the backend's ipc path. */
    ipcPathArgs: string[];
    /** Prefix for the per-instance ipc path. */
    instancePrefix: string;
    /** Directory of the package that owns the arch packages, for the sibling fallback. */
    packageDir: string;
}
/** Options a caller may give when the service runs as a spawned process. */
export interface ServiceProcessOptions {
    binaryPath?: string;
    transport?: "uds" | "shm";
    /** Threads the service may use, exported to it as HARDWARE_CONCURRENCY and RAYON_NUM_THREADS. */
    threads?: number;
    logger?: (msg: string) => void;
    connectTimeoutMs?: number;
    env?: NodeJS.ProcessEnv;
    extraArgs?: string[];
    respawn?: boolean;
    /** When true, an idle backend does not keep the process alive; see SpawnedProcessBackendOptions. */
    unref?: boolean;
    clientId?: number;
    napiPath?: string;
}
/**
 * The binary to run: `customPath` if given, else the package's environment variable, else the
 * installed arch package for this platform. Null when none of those yields an existing file.
 */
export declare function findServiceBinary(binary: ServiceBinary, customPath?: string): string | null;
/** The child's environment: the caller's, plus the thread count under both names services read. */
export declare function serviceProcessEnv(options: Pick<ServiceProcessOptions, "threads" | "env">): NodeJS.ProcessEnv | undefined;
/**
 * Spawn the service and connect to it. Process lifecycle — connectivity, death detection,
 * optional respawn, teardown — is owned by the backend and never leaks onto the caller's API.
 */
export declare function spawnServiceBackend(binary: ServiceBinary, defaultTransport: "uds" | "shm", options?: ServiceProcessOptions): Promise<SpawnedProcessBackend>;
/** The synchronous form: shared memory is the one transport with a synchronous client. */
export declare function spawnServiceBackendSync(binary: ServiceBinary, options?: ServiceProcessOptions): Promise<SpawnedProcessBackendSync>;
/** Run the service binary as a CLI, forwarding argv and exit status. Backs a package's `bin`. */
export declare function runServiceBinary(binary: ServiceBinary, packageName: string, argv: string[]): never;
/**
 * Which backend to use, given what this host can offer. Unset: the process when its binary
 * resolves, else wasm. A name forces one, with no fallback to the other.
 */
export declare function pickServiceBackend<T extends IpcClientAsync | IpcClientSync>(wanted: "process" | "wasm" | T | undefined, choices: {
    label: string;
    process?: {
        available: () => boolean;
        create: () => Promise<T>;
    };
    wasm?: {
        create: () => Promise<T>;
    };
    logger?: (msg: string) => void;
}): Promise<T>;
