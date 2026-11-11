import * as net from "node:net";
import { IpcClientAsync, IpcErrorMapper } from "./types.js";
export interface UdsIpcClientConnectOptions {
    /**
     * Unref the socket while idle so it doesn't keep the Node event loop
     * alive; it is re-ref'd while calls are in flight so a response can never
     * be lost to an early process exit.
     */
    unref?: boolean;
    /**
     * Retry budget (ms) for the initial connect when the server has bound the
     * path but not yet called listen(). Set to 0 to fail immediately on
     * ECONNREFUSED. Default CONNECT_RETRY_BUDGET_MS (5000).
     */
    connectTimeoutMs?: number;
    /**
     * Abandons the connect. Callers that race the connect against something
     * else (a spawned server dying, say) must abort the loser: otherwise it
     * keeps retrying on a timer until its budget expires, holding the event
     * loop open long after the caller gave up.
     */
    signal?: AbortSignal;
    /** Applied to every rejected call's error. */
    mapError?: IpcErrorMapper;
}
/**
 * Async IPC client over a Unix Domain Socket. Wire format matches the C++
 * ipc::IpcServer/IpcClient socket transport: 4-byte little-endian length
 * prefix, 8-byte little-endian request id, then the msgpack payload (the
 * length counts the id plus the payload), per direction.
 *
 * Supports pipelining: each call carries a unique request id which the
 * server echoes on the response, so responses are paired to callers by id
 * and the server may complete requests in any order (see PendingQueue).
 */
export declare class UdsIpcClient implements IpcClientAsync {
    private conn;
    private readonly idleUnref;
    private readonly mapError?;
    private frames;
    private readonly pending;
    private destroyed;
    /** Set once the socket has errored/closed; new calls fail fast. */
    private closed;
    private constructor();
    static connect(socketPath: string, opts?: UdsIpcClientConnectOptions): Promise<UdsIpcClient>;
    /** Number of in-flight calls awaiting a response. */
    get inflight(): number;
    /** Underlying socket — exposed for ref/unref control (event-loop tuning). */
    get socket(): net.Socket;
    call(input: Uint8Array): Promise<Uint8Array>;
    destroy(): Promise<void>;
    private onData;
    private failAll;
    private mapped;
}
