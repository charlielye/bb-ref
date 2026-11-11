// Shared transport constants, mirroring cpp/ipc_runtime/constants.hpp —
// keep the two in sync.
/**
 * Largest frame the wire format can express: the u32 length prefix counts the
 * request id plus the payload, so a payload can be at most MAX_FRAME_SIZE - 8
 * bytes. Stream receivers buffer only what has arrived, so nothing smaller is
 * imposed; SHM is bounded separately by its ring capacity.
 */
export const MAX_FRAME_SIZE = 0xffffffff;
/**
 * Total budget (ms) for connect() retry loops, covering the window where
 * the server process is still starting up.
 */
export const CONNECT_RETRY_BUDGET_MS = 5000;
/** Default ring size for SHM transports (per direction, per client). */
export const DEFAULT_RING_SIZE = 4 * 1024 * 1024; // 4 MiB
/** Default listen backlog for UDS servers. */
export const SOCKET_BACKLOG = 10;
/** Default per-call timeout: 0 = infinite (matches the C++ client APIs). */
export const DEFAULT_CALL_TIMEOUT_NS = 0;
