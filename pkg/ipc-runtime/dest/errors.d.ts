/**
 * Errors thrown by the ipc-runtime transports and process backends.
 *
 * The cross-layer contract is the bare `retry` property, not these classes:
 * an error with `retry === true` failed for environmental reasons (process
 * death, machine load, a broken connection) and the operation may be retried;
 * `retry === false` (or no `retry` property at all) means retrying cannot
 * help. Consumers should feature-detect the property rather than import
 * these types, so the convention survives package boundaries.
 */
export declare class IpcError extends Error {
    readonly retry: boolean;
    constructor(message: string, retry: boolean, options?: {
        cause?: unknown;
    });
}
/** The connection to the server broke while calls were in flight or before they could be sent. */
export declare class IpcTransportError extends IpcError {
    constructor(message: string, options?: {
        cause?: unknown;
    });
}
/** The spawned server process exited; carries the exit cause and, when captured, the log path. */
export declare class IpcProcessExitedError extends IpcError {
    readonly code: number | null;
    readonly signal: NodeJS.Signals | null;
    readonly logPath?: string | undefined;
    constructor(message: string, code: number | null, signal: NodeJS.Signals | null, logPath?: string | undefined);
}
/**
 * The server process could not be started. Environmental failures (spawn
 * raced a loaded machine, a wedged process hit the connect backstop) are
 * retryable; configuration failures (binary not found) are not.
 */
export declare class IpcSpawnError extends IpcError {
}
