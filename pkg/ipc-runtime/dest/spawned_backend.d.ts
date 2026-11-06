import { IpcClientAsync, IpcClientSync } from "./types.js";
export type SpawnedTransport = "uds" | "shm";
export interface SpawnedProcessBackendOptions {
    /** Absolute path of the server binary to spawn. Callers resolve it (and fail with retry=false if missing). */
    binaryPath: string;
    /** Binary name used in error messages and log labels. */
    binaryName: string;
    /** Prefix for the per-instance ipc path (socket / shm name). */
    instancePrefix: string;
    /** Argv template; each '{path}' is replaced with the backend's ipc path. */
    ipcPathArgs: string[];
    transport: SpawnedTransport;
    /** Receives the child's stdout/stderr lines. Without it, output is captured to a temp log file. */
    logger?: (msg: string) => void;
    connectTimeoutMs?: number;
    env?: NodeJS.ProcessEnv;
    extraArgs?: string[];
    /**
     * Respawn the server on the next call() after it dies, instead of failing all
     * subsequent calls. Only safe for stateless servers: a respawned process
     * remembers nothing, so any server-side session state (forks, cursors) held
     * by callers would silently dangle. In-flight calls at the time of death
     * still reject (with retry=true); only later calls see the fresh process.
     */
    respawn?: boolean;
    /**
     * When true, an idle backend does not keep the caller's process alive: you never have to
     * destroy() it for node to exit. Work in progress still holds the loop — the connect while
     * the server starts, and each call until its response arrives — so nothing exits early.
     *
     * The one thing given up is trailing output: the child's stdout/stderr pipes, which exist
     * only when `logger` is set, stop holding the loop too, so a process that exits while the
     * child is mid-line loses it.
     */
    unref?: boolean;
    /** SHM only: fixed client slot id. When unset the client self-allocates a free slot. */
    clientId?: number;
    /** SHM only: override the native addon path. */
    napiPath?: string;
}
/**
 * An IpcClientAsync backed by a spawned server process. Owns the process
 * lifecycle end to end: spawn, connect (raced against child death, with a
 * kill-on-expiry backstop), death detection, optional lazy respawn, and
 * teardown with SIGTERM→SIGKILL escalation. Failures surface as IpcError
 * subclasses whose `retry` property tells callers whether the operation may
 * be retried; no process or transport state is exposed on the API.
 */
export declare class SpawnedProcessBackend implements IpcClientAsync {
    private readonly options;
    private current?;
    private starting?;
    private destroying;
    /** Set when the process died and respawn is disabled; fails all later calls. */
    private exitError?;
    private readonly respawn;
    private readonly ipcPath;
    private readonly logPath?;
    private constructor();
    static spawn(options: SpawnedProcessBackendOptions): Promise<SpawnedProcessBackend>;
    getIpcPath(): string;
    call(input: Uint8Array): Promise<Uint8Array>;
    private callWithRespawn;
    sendProcessSignal(signal: NodeJS.Signals): void;
    destroy(): Promise<void>;
    /** Return the live incarnation, lazily respawning one when allowed. */
    private ensureUp;
    /**
     * Convert a failed call into the death of the process when that is what
     * actually happened: the socket breaks before the child's 'exit' event
     * lands, so wait a short grace for exit attribution before giving up and
     * rethrowing the transport error as-is.
     *
     * A broken connection to a process that is still running is retired by
     * killing that process. The client cannot reconnect, so otherwise the
     * backend would keep the dead connection, failing every later call, never
     * respawning, and leaving the server running for the life of the caller.
     * Killing it routes the failure through the ordinary death path instead.
     */
    private attributeCallError;
    /** Spawn the server process and connect to it; kills the child on any failure. */
    private spawnIncarnation;
    /** Handles an incarnation's death: reject/replace state so later calls behave per the respawn policy. */
    private onIncarnationExit;
    private connectClient;
    /** Wrap a spawn/connect failure as IpcSpawnError and point at the captured log. */
    private asSpawnError;
    private cleanupIpcPath;
}
/**
 * A synchronous IpcClientSync backed by a spawned server process, for callers
 * whose API cannot await (BarretenbergSync and friends). Shares process setup,
 * stale-path removal and the connect backstop with SpawnedProcessBackend; only
 * the request path differs, blocking in the NAPI client instead of returning a
 * promise.
 *
 * SHM only: a synchronous request needs the shared-memory client, as a socket
 * round trip cannot block the event loop without deadlocking it. Construction
 * is still async — the server has to come up before the first call — so only
 * call() and destroy() are synchronous.
 */
export declare class SpawnedProcessBackendSync implements IpcClientSync {
    private readonly options;
    private readonly child;
    private readonly client;
    private readonly ipcPath;
    private readonly logPath?;
    private destroyed;
    private constructor();
    static spawn(options: SpawnedProcessBackendOptions): Promise<SpawnedProcessBackendSync>;
    call(input: Uint8Array): Uint8Array;
    destroy(): void;
}
