import { spawn } from "node:child_process";
import { open, rm } from "node:fs/promises";
import { constants as osConstants, tmpdir } from "node:os";
import { join } from "node:path";
import { threadId } from "node:worker_threads";
import { IpcError, IpcProcessExitedError, IpcSpawnError, IpcTransportError, } from "./errors.js";
import { createNapiShmAsyncClient, createNapiShmSyncClient, } from "./shm_client.js";
import { UdsIpcClient } from "./uds_client.js";
// Backstop for a spawned server that is alive but never reaches listen().
// This is a broken-process detector, not a performance expectation: servers
// create their socket before any heavy initialization, so the timed window
// covers only exec + linking + minimal init, and requests issued before the
// server is fully initialized simply wait in the socket buffer. When the
// backstop fires, the wedged process is killed rather than orphaned.
const DEFAULT_CONNECT_TIMEOUT_MS = 60_000;
// After destroy() sends SIGTERM, how long to wait before escalating to
// SIGKILL so teardown cannot hang on a server that is stuck before its signal
// handlers were installed (or is wedged inside them).
const SIGTERM_GRACE_MS = 5_000;
// How long a failed call() waits for the child's 'exit' event before deciding
// the process is still alive. The socket usually breaks before 'exit' lands,
// so without this grace a death would be misreported as a bare transport error.
const EXIT_ATTRIBUTION_GRACE_MS = 250;
/** POSIX shm segment names an shm server creates for `<name>.shm`. */
function shmSegmentPaths(ipcPath) {
    const shmName = ipcPath.replace(/\.shm$/, "");
    return ["_request", "_response"].map((suffix) => `/dev/shm/${shmName}${suffix}`);
}
/**
 * Remove any ipc path left behind by a previous occupant of this name.
 *
 * Run before spawning as well as after teardown: a server killed outright
 * (SIGKILL, OOM) never reaches its own cleanup, and shm segments are created
 * with O_EXCL, so a leftover segment makes the next server fail at startup
 * with a bare "File exists". Instance names embed the pid, so this only bites
 * once pids recycle — which is routine in containers and CI.
 */
async function removeStaleIpcPath(transport, ipcPath) {
    try {
        const paths = transport === "shm" ? shmSegmentPaths(ipcPath) : [ipcPath];
        await Promise.all(paths.map((p) => rm(p, { force: true })));
    }
    catch {
        // Best effort: a stale path we cannot remove surfaces as the server's own
        // startup error, which carries more context than anything we could throw.
    }
}
/**
 * Spawn the server process with the caller's argv/env, wiring stdio to the
 * live logger when there is one and to `logFd` otherwise. Shared by the async
 * and sync backends so process setup has exactly one implementation.
 */
/**
 * Stop the child and its output pipes holding the caller's event loop. Called once the backend is
 * connected, never before: until then the child is the only thing keeping the process alive while
 * the server starts, and unref'ing it lets node exit mid-startup. After it, each transport refs
 * itself for the duration of a call (see UdsIpcClient's idle unref and the shm client's TSFN
 * acquire/release), so only a genuinely idle backend is invisible to the loop.
 */
function unrefWhenIdle(child) {
    child.unref();
    // The stdio pipes are net.Sockets at runtime but typed as Readable.
    child.stdout?.unref?.();
    child.stderr?.unref?.();
}
function spawnServerProcess(options, ipcPath, logFd) {
    const child = spawn(options.binaryPath, [
        ...options.ipcPathArgs.map((arg) => (arg === "{path}" ? ipcPath : arg)),
        ...(options.extraArgs ?? []),
    ], {
        stdio: [
            "ignore",
            options.logger ? "pipe" : logFd,
            options.logger ? "pipe" : logFd,
        ],
        env: { ...process.env, ...(options.env ?? {}) },
    });
    if (options.logger) {
        child.stdout?.on("data", (data) => options.logger?.(`[${options.binaryName} stdout] ${data.toString().trimEnd()}`));
        child.stderr?.on("data", (data) => options.logger?.(`[${options.binaryName} stderr] ${data.toString().trimEnd()}`));
    }
    return child;
}
/**
 * A promise that rejects if the child fails to spawn or dies before its IPC
 * endpoint is ready, for racing against the connect. Already observed, since
 * it can reject before the caller attaches a handler (spawn failures land on
 * nextTick) and would otherwise count as an unhandled rejection.
 */
function childReadyFailurePromise(child, binaryName) {
    const failure = new Promise((_, reject) => {
        // Spawn syscall failures are the one place errno distinguishes a
        // configuration error (missing/non-executable binary → retrying cannot
        // help) from an environmental one.
        child.once("error", (err) => {
            const code = err.code;
            const retry = code !== "ENOENT" && code !== "EACCES";
            reject(new IpcSpawnError(`Failed to spawn ${binaryName}: ${err.message}`, retry, {
                cause: err,
            }));
        });
        child.once("exit", (code, signal) => {
            reject(new IpcSpawnError(`${binaryName} exited before IPC connection was ready (code=${code}, signal=${signal})`, 
            /*retry=*/ true));
        });
    });
    failure.catch(() => { });
    return failure;
}
let instanceCounter = 0;
/**
 * An IpcClientAsync backed by a spawned server process. Owns the process
 * lifecycle end to end: spawn, connect (raced against child death, with a
 * kill-on-expiry backstop), death detection, optional lazy respawn, and
 * teardown with SIGTERM→SIGKILL escalation. Failures surface as IpcError
 * subclasses whose `retry` property tells callers whether the operation may
 * be retried; no process or transport state is exposed on the API.
 */
export class SpawnedProcessBackend {
    options;
    current;
    starting;
    destroying = false;
    /** Set when the process died and respawn is disabled; fails all later calls. */
    exitError;
    respawn;
    ipcPath;
    logPath;
    constructor(options) {
        this.options = options;
        this.respawn = options.respawn ?? false;
        const instanceId = `${options.instancePrefix}-${process.pid}-${threadId}-${instanceCounter++}`;
        // The ipc path is per-backend, not per-incarnation, so getIpcPath() stays
        // stable across respawns for anyone who was handed the path.
        this.ipcPath =
            options.transport === "shm"
                ? `${instanceId}.shm`
                : join(tmpdir(), `${instanceId}.sock`);
        // Same for the log file: respawns append, preserving the death's last words.
        this.logPath = options.logger
            ? undefined
            : join(tmpdir(), `${instanceId}.log`);
    }
    static async spawn(options) {
        if (options.respawn && options.transport === "shm") {
            throw new IpcError(`respawn is not supported over the shm transport`, 
            /*retry=*/ false);
        }
        const backend = new SpawnedProcessBackend(options);
        backend.current = await backend.spawnIncarnation();
        return backend;
    }
    getIpcPath() {
        return this.ipcPath;
    }
    call(input) {
        // Fast path for a live process: no async frame, no await on ensureUp(),
        // and no extra promise. This runs once per call, and a pipelined caller
        // issuing thousands of calls feels every extra promise hop. Errors are
        // attributed by the client itself (see connectClient's mapError).
        const incarnation = this.current;
        if (incarnation !== undefined && !this.destroying) {
            return incarnation.client.call(input);
        }
        return this.callWithRespawn(input);
    }
    async callWithRespawn(input) {
        const incarnation = await this.ensureUp();
        return await incarnation.client.call(input);
    }
    sendProcessSignal(signal) {
        const child = this.current?.child;
        if (child && child.exitCode === null && child.signalCode === null) {
            child.kill(signal);
        }
    }
    async destroy() {
        // Mark intentional teardown so the exit handler doesn't report it as an
        // unexpected death (or trigger a respawn).
        this.destroying = true;
        // A respawn may be mid-flight; let it settle so its child can't leak.
        await this.starting?.then((incarnation) => {
            this.current = incarnation;
        }, () => { });
        const incarnation = this.current;
        this.current = undefined;
        if (!incarnation) {
            return;
        }
        await incarnation.client.destroy();
        const { child } = incarnation;
        let killTimer;
        if (child.exitCode === null && child.signalCode === null) {
            child.kill("SIGTERM");
            killTimer = setTimeout(() => {
                if (child.exitCode === null && child.signalCode === null) {
                    child.kill("SIGKILL");
                }
            }, SIGTERM_GRACE_MS);
        }
        await incarnation.exitPromise;
        if (killTimer !== undefined) {
            clearTimeout(killTimer);
        }
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.removeAllListeners();
        await this.cleanupIpcPath();
    }
    /** Return the live incarnation, lazily respawning one when allowed. */
    async ensureUp() {
        if (this.destroying) {
            throw new IpcError(`${this.options.binaryName} backend destroyed`, 
            /*retry=*/ false);
        }
        if (this.current) {
            return this.current;
        }
        if (this.exitError) {
            throw this.exitError;
        }
        // Lazy, shared respawn: the first caller after a death starts it, everyone
        // else awaits the same attempt. Lazy (rather than eager-on-exit) so a
        // crashing binary cannot respawn-loop with no one asking for it.
        this.starting ??= this.spawnIncarnation()
            .then((incarnation) => {
            if (this.destroying) {
                // destroy() raced us and already awaited this promise; it owns teardown.
                return incarnation;
            }
            this.current = incarnation;
            return incarnation;
        })
            .finally(() => {
            this.starting = undefined;
        });
        return await this.starting;
    }
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
    async attributeCallError(incarnation, err) {
        if (!incarnation.exitInfo && !this.destroying) {
            await Promise.race([
                incarnation.exitPromise,
                new Promise((resolve) => setTimeout(resolve, EXIT_ATTRIBUTION_GRACE_MS)),
            ]);
        }
        if (incarnation.exitInfo && !this.destroying) {
            const { code, signal } = incarnation.exitInfo;
            return new IpcProcessExitedError(`${this.options.binaryName} exited unexpectedly (code=${code}, signal=${signal})` +
                (this.logPath !== undefined ? `; see logs: ${this.logPath}` : ""), code, signal, this.logPath);
        }
        if (err instanceof IpcTransportError &&
            !this.destroying &&
            this.current === incarnation) {
            incarnation.child.kill("SIGKILL");
            await incarnation.exitPromise;
        }
        return err;
    }
    /** Spawn the server process and connect to it; kills the child on any failure. */
    async spawnIncarnation() {
        const { options } = this;
        await removeStaleIpcPath(options.transport, this.ipcPath);
        // Without a live logger, capture the child's stdout/stderr to the backend's
        // log file (a plain fd, not a pipe — a pipe would keep the libuv loop
        // referenced and break clean process exit). The path is surfaced on
        // failures so the child's errors are recoverable instead of vanishing.
        // Async fs throughout: this runs on respawn under exactly the machine
        // conditions where a sync open against a struggling disk could stall the
        // whole event loop.
        const logFile = this.logPath !== undefined ? await open(this.logPath, "a") : undefined;
        const child = spawnServerProcess(options, this.ipcPath, logFile?.fd);
        const incarnation = {
            child,
        };
        const exitPromise = new Promise((resolve) => {
            child.on("exit", (code, signal) => {
                incarnation.exitInfo = { code, signal };
                this.onIncarnationExit(incarnation, code, signal);
                resolve();
            });
        });
        incarnation.exitPromise = exitPromise;
        const childReadyFailure = childReadyFailurePromise(child, options.binaryName);
        if (logFile !== undefined) {
            // spawn() dups the fd synchronously; the parent's handle isn't needed.
            // Closed only now, after the 'error'/'exit' listeners are attached: spawn
            // failures are emitted on nextTick, so an await between spawn() and the
            // listeners would let them fire unhandled.
            await logFile.close();
        }
        // Liveness-based startup: wait on the connect for as long as the process
        // is alive (the connect path retries socket-not-ready errors internally),
        // and fail immediately with the real cause if the process dies first. On
        // any failure, reap the child and its ipc path so a failed spawn cannot
        // leak an orphan process still holding sockets or database locks.
        // The connect retries on a timer until its budget expires. When the child
        // dies first the race rejects, but nothing stops that loop — so abort it,
        // or it keeps dialling a dead server and holds the event loop open.
        const connectAbort = new AbortController();
        try {
            incarnation.client = await Promise.race([
                this.connectClient(connectAbort.signal, (err) => this.attributeCallError(incarnation, err)),
                childReadyFailure,
            ]);
        }
        catch (err) {
            connectAbort.abort();
            if (child.pid !== undefined) {
                // SIGKILL, not SIGTERM: the process never became ready, so it has no
                // state to flush, and a wedged process may not honour SIGTERM.
                if (child.exitCode === null && child.signalCode === null) {
                    child.kill("SIGKILL");
                }
                await exitPromise;
            }
            child.stdout?.destroy();
            child.stderr?.destroy();
            child.removeAllListeners();
            await this.cleanupIpcPath();
            throw this.asSpawnError(err);
        }
        if (options.unref) {
            unrefWhenIdle(child);
        }
        return incarnation;
    }
    /** Handles an incarnation's death: reject/replace state so later calls behave per the respawn policy. */
    onIncarnationExit(incarnation, code, signal) {
        // Break the connection so in-flight calls reject rather than wait forever
        // (matters over SHM, where there is no socket to break).
        void incarnation.client?.destroy();
        if (this.destroying || this.current !== incarnation) {
            return;
        }
        this.current = undefined;
        if (!this.respawn) {
            this.exitError = new IpcProcessExitedError(`${this.options.binaryName} exited unexpectedly (code=${code}, signal=${signal})` +
                (this.logPath !== undefined ? `; see logs: ${this.logPath}` : ""), code, signal, this.logPath);
            console.error(this.exitError.message);
        }
        else {
            console.error(`${this.options.binaryName} exited unexpectedly (code=${code}, signal=${signal}); will respawn on next call`);
        }
    }
    async connectClient(signal, mapError) {
        const { options } = this;
        const timeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
        if (options.transport === "uds") {
            // UdsIpcClient.connect retries socket-not-ready errors (path not yet
            // created, server not yet accepting, backlog momentarily full) until the
            // budget expires, and fails immediately on hard errors. Process death is
            // raced against this by the caller, so a dead server short-circuits the
            // wait with its real exit cause.
            return await UdsIpcClient.connect(this.ipcPath, {
                connectTimeoutMs: timeoutMs,
                unref: options.unref,
                signal,
                mapError,
            });
        }
        // The SHM client attaches to server-created rings, so creation can race
        // server startup; retry until the backstop expires.
        const deadline = Date.now() + timeoutMs;
        let lastError;
        while (Date.now() <= deadline && !signal?.aborted) {
            try {
                return createNapiShmAsyncClient(this.ipcPath.replace(/\.shm$/, ""), {
                    clientId: options.clientId,
                    customAddonPath: options.napiPath,
                    mapError,
                });
            }
            catch (err) {
                lastError = err;
                await new Promise((resolve) => setTimeout(resolve, 50));
            }
        }
        const message = lastError instanceof Error ? lastError.message : String(lastError);
        throw new IpcSpawnError(`Timed out connecting to ${this.options.binaryName}: ${message}`, 
        /*retry=*/ true, { cause: lastError });
    }
    /** Wrap a spawn/connect failure as IpcSpawnError and point at the captured log. */
    asSpawnError(err) {
        const logHint = this.logPath !== undefined ? `; see logs: ${this.logPath}` : "";
        if (err instanceof IpcSpawnError) {
            // Already classified at its source (child spawn 'error', exit-before-ready).
            return new IpcSpawnError(err.message + logHint, err.retry, {
                cause: err.cause ?? err,
            });
        }
        // Everything else reaching here (connect backstop expiry, transient
        // transport errors) is environmental.
        const message = err instanceof Error ? err.message : String(err);
        return new IpcSpawnError(`Failed to start ${this.options.binaryName}: ${message}${logHint}`, 
        /*retry=*/ true, { cause: err });
    }
    async cleanupIpcPath() {
        await removeStaleIpcPath(this.options.transport, this.ipcPath);
    }
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
export class SpawnedProcessBackendSync {
    options;
    child;
    client;
    ipcPath;
    logPath;
    destroyed = false;
    constructor(options, child, client, ipcPath, logPath) {
        this.options = options;
        this.child = child;
        this.client = client;
        this.ipcPath = ipcPath;
        this.logPath = logPath;
    }
    static async spawn(options) {
        if (options.transport !== "shm") {
            throw new IpcError(`SpawnedProcessBackendSync requires the shm transport (got ${options.transport})`, 
            /*retry=*/ false);
        }
        const instanceId = `${options.instancePrefix}-${process.pid}-${threadId}-${instanceCounter++}`;
        const ipcPath = `${instanceId}.shm`;
        const logPath = options.logger
            ? undefined
            : join(tmpdir(), `${instanceId}.log`);
        await removeStaleIpcPath("shm", ipcPath);
        const logFile = logPath !== undefined ? await open(logPath, "a") : undefined;
        const child = spawnServerProcess(options, ipcPath, logFile?.fd);
        const childReadyFailure = childReadyFailurePromise(child, options.binaryName);
        await logFile?.close();
        try {
            const client = await Promise.race([
                connectShmSyncClient(options, ipcPath, child.pid),
                childReadyFailure,
            ]);
            if (options.unref) {
                unrefWhenIdle(child);
            }
            return new SpawnedProcessBackendSync(options, child, client, ipcPath, logPath);
        }
        catch (err) {
            if (child.exitCode === null && child.signalCode === null) {
                child.kill("SIGKILL");
            }
            child.removeAllListeners();
            await removeStaleIpcPath("shm", ipcPath);
            throw err instanceof IpcError
                ? err
                : new IpcSpawnError(`Failed to start ${options.binaryName}: ${String(err)}`, 
                /*retry=*/ true, { cause: err });
        }
    }
    call(input) {
        if (this.destroyed) {
            throw new IpcError(`${this.options.binaryName} backend destroyed`, 
            /*retry=*/ false);
        }
        try {
            return this.client.call(input);
        }
        catch (err) {
            // The call holds the main thread, so the child's exit event hasn't run:
            // the native client reports the death itself. Report it with the log
            // path rather than as an opaque transport error.
            const exit = nativeServerExit(err) ??
                (this.child.exitCode !== null || this.child.signalCode !== null
                    ? { code: this.child.exitCode, signal: this.child.signalCode }
                    : undefined);
            if (exit) {
                throw new IpcProcessExitedError(`${this.options.binaryName} exited unexpectedly (code=${exit.code}, signal=${exit.signal})` +
                    (this.logPath !== undefined ? `; see logs: ${this.logPath}` : ""), exit.code, exit.signal, this.logPath);
            }
            throw err;
        }
    }
    destroy() {
        if (this.destroyed) {
            return;
        }
        this.destroyed = true;
        this.client.destroy();
        if (this.child.exitCode === null && this.child.signalCode === null) {
            this.child.kill("SIGTERM");
        }
        this.child.removeAllListeners();
        // Teardown is synchronous by contract, so the segments are reaped in the
        // background; the pre-spawn removal is what actually guarantees a clean
        // start for the next occupant.
        void removeStaleIpcPath("shm", this.ipcPath);
    }
}
/** The server exit a native sync shm call reported, if that is why it failed. */
function nativeServerExit(err) {
    const e = err;
    if (!e || e.serverExited !== true) {
        return undefined;
    }
    const signal = e.signal == null
        ? null
        : (Object.entries(osConstants.signals).find(([, n]) => n === e.signal)?.[0] ?? null);
    return { code: e.exitCode ?? null, signal };
}
/** Retry attaching the sync shm client until the server has created its rings. */
async function connectShmSyncClient(options, ipcPath, serverPid) {
    const deadline = Date.now() + (options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS);
    let lastError;
    while (Date.now() <= deadline) {
        try {
            return createNapiShmSyncClient(ipcPath.replace(/\.shm$/, ""), {
                clientId: options.clientId,
                customAddonPath: options.napiPath,
                serverPid,
            });
        }
        catch (err) {
            lastError = err;
            await new Promise((resolve) => setTimeout(resolve, 50));
        }
    }
    const message = lastError instanceof Error ? lastError.message : String(lastError);
    throw new IpcSpawnError(`Timed out connecting to ${options.binaryName}: ${message}`, 
    /*retry=*/ true, { cause: lastError });
}
