import { IpcClientAsync, IpcClientSync, IpcErrorMapper } from "./types.js";
/**
 * Minimum surface a NAPI msgpack client must expose. Satisfied by the
 * `MsgpackClient` / `MsgpackClientAsync` classes exported from this
 * package's own `ipc_runtime_napi.node` addon (see ipc-runtime/cpp/napi/),
 * which wraps the C++ ipc::IpcClient.
 *
 * The interface is exposed for tests / consumers that want to inject a
 * mock or alternative implementation; the standard production path is the
 * `createNapiShm{Sync,Async}Client` factories below, which load the
 * prebuilt addon shipped in this package's `build/<arch>-<os>/` directory.
 *
 * Note on the async contract: `MsgpackClientAsync.call` is *fire and
 * forget*. Responses arrive via `setResponseCallback` in COMPLETION order on
 * a background-thread → main-thread bridge (Napi::ThreadSafeFunction), each
 * carrying its echoed request id. The TS wrapper below owns the pending map
 * and pairs responses to callers by id.
 */
export interface NapiMsgpackClientSync {
    call(input: Buffer): Buffer;
    close(): void;
}
export interface NapiMsgpackClientAsync {
    setResponseCallback(cb: (requestId: number, response: Buffer) => void): void;
    call(requestId: number, input: Buffer): void;
    acquire(): void;
    release(): void;
    /** Stop the native poll thread, release any held TSFN ref, close the client. */
    close(): void;
}
/** Wraps a sync NAPI msgpack client behind the IpcClientSync interface. */
export declare class NapiShmSyncClient implements IpcClientSync {
    private inner;
    constructor(inner: NapiMsgpackClientSync);
    call(input: Uint8Array): Uint8Array;
    destroy(): void;
}
/**
 * Wraps the fire-and-forget async NAPI msgpack client behind the
 * `IpcClientAsync` interface. The C++ background polling thread invokes
 * `setResponseCallback` once per response (in completion order), and this
 * wrapper pairs it to its caller by the echoed id (see PendingQueue).
 *
 * `acquire` / `release` are reference-count hooks the NAPI exposes so the
 * libuv loop is kept alive only while requests are outstanding — without
 * them a `node script.js` would never exit naturally.
 */
export declare class NapiShmAsyncClient implements IpcClientAsync {
    private inner;
    private readonly mapError?;
    private readonly pending;
    private destroyed;
    constructor(inner: NapiMsgpackClientAsync, mapError?: IpcErrorMapper | undefined);
    call(input: Uint8Array): Promise<Uint8Array>;
    private fail;
    destroy(): Promise<void>;
}
export interface CreateNapiShmOptions {
    /** MPSC client slot id (default 0). Distinct clients on the same shmName must use distinct slots. */
    clientId?: number;
    /** Override addon path lookup. Rarely needed; useful for tests / unusual deployments. */
    customAddonPath?: string;
    /** Applied to every rejected call's error. */
    mapError?: IpcErrorMapper;
    /**
     * Sync client only: the server's pid. A sync call holds the main thread, so
     * nothing else can notice the server dying; with the pid, a call to a dead
     * server throws (with `serverExited`, `exitCode` and `signal` set) instead
     * of waiting forever. Calls have no deadline either way.
     */
    serverPid?: number;
}
/**
 * Factories that load the bundled `ipc_runtime_napi.node` addon and
 * construct an MPSC-SHM client wrapped behind the `IpcClient*` interface.
 * Matches the transport used by `ipc::make_server` on the C++ side, so any
 * server started via that helper accepts these clients directly.
 */
export declare function createNapiShmSyncClient(shmName: string, options?: CreateNapiShmOptions): NapiShmSyncClient;
export declare function createNapiShmAsyncClient(shmName: string, options?: CreateNapiShmOptions): NapiShmAsyncClient;
