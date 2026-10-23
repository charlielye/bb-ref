export type Platform = "x86_64-linux" | "x86_64-darwin" | "aarch64-linux" | "aarch64-darwin";
/**
 * Resolve the path of `ipc_runtime_napi.node` for the current platform.
 * Returns null if either the platform is unsupported or the artifact is
 * absent (typical reason: ipc-runtime/bootstrap.sh hasn't run yet).
 */
export declare function findIpcRuntimeNapi(customPath?: string): string | null;
/**
 * Load `ipc_runtime_napi.node` and return its native exports
 * (`MsgpackClient`, `MsgpackClientAsync`). Throws a descriptive error when
 * the addon cannot be located or fails to dlopen.
 */
export declare function loadIpcRuntimeNapi(customPath?: string): {
    MsgpackClient: new (shmName: string, clientId?: number, serverPid?: number) => any;
    MsgpackClientAsync: new (shmName: string, clientId?: number) => any;
};
