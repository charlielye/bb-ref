/**
 * Handler signature mirrors the C++ ipc::IpcServer::Handler: receive raw
 * bytes, return raw bytes. msgpack decode/encode and command dispatch are
 * the caller's responsibility (or the codegen's, when a generated dispatcher
 * is wired in).
 */
export type IpcServerHandler = (clientId: number, request: Uint8Array) => Promise<Uint8Array> | Uint8Array;
/**
 * UDS server with the same wire format as UdsIpcClient and the C++
 * ipc::IpcServer socket transport: 4-byte LE length prefix, 8-byte LE request
 * id (echoed on the response), then the payload; the length counts the id
 * plus the payload. Accepts multiple concurrent connections; handler
 * invocations are serialised per-connection.
 *
 * Signal handling is the caller's responsibility (unlike the C++ server's
 * install_default_signal_handlers); the socket file is unlinked on close()
 * and best-effort on process exit.
 */
export declare class UdsIpcServer {
    private socketPath;
    private server;
    private nextClientId;
    private connections;
    private readonly unlinkOnExit;
    private constructor();
    static listen(socketPath: string, handler: IpcServerHandler): Promise<UdsIpcServer>;
    close(): Promise<void>;
    private handleConnection;
}
