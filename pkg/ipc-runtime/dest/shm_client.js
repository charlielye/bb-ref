import { loadIpcRuntimeNapi } from "./native_loader.js";
import { PendingQueue } from "./pending_queue.js";
/** Wraps a sync NAPI msgpack client behind the IpcClientSync interface. */
export class NapiShmSyncClient {
    inner;
    constructor(inner) {
        this.inner = inner;
    }
    call(input) {
        const buf = Buffer.isBuffer(input)
            ? input
            : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
        const resp = this.inner.call(buf);
        return new Uint8Array(resp.buffer, resp.byteOffset, resp.byteLength);
    }
    destroy() {
        this.inner.close();
    }
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
export class NapiShmAsyncClient {
    inner;
    mapError;
    pending = new PendingQueue();
    destroyed = false;
    constructor(inner, mapError) {
        this.inner = inner;
        this.mapError = mapError;
        this.inner.setResponseCallback((requestId, response) => {
            if (this.destroyed) {
                // Late response delivered after destroy(); the native close already
                // balanced the TSFN reference.
                return;
            }
            const cb = this.pending.take(requestId);
            if (cb) {
                cb.resolve(new Uint8Array(response));
                if (this.pending.length === 0) {
                    this.inner.release();
                }
            }
            else {
                // SHM rings persist across occupants (slot reclaim / reattach), so a
                // frame addressed to a previous occupant's id is an anticipated
                // leftover — discard it and keep serving live calls. Log it so that if
                // a genuinely lost pairing ever hangs a caller, the evidence is in the
                // log rather than silently dropped. Don't release: no acquire was
                // taken for an orphan response.
                console.warn(`NapiShmAsyncClient: discarding response for unknown request id ${requestId} ` +
                    "(stale frame from a previous ring occupant?)");
            }
        });
    }
    call(input) {
        if (this.destroyed) {
            return new Promise((_, reject) => this.fail(reject, new Error("NapiShmAsyncClient: call() after destroy()")));
        }
        const buf = Buffer.isBuffer(input)
            ? input
            : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
        return new Promise((resolve, reject) => {
            if (this.pending.length === 0) {
                this.inner.acquire();
            }
            const requestId = this.pending.push(resolve, reject);
            try {
                this.inner.call(requestId, buf);
            }
            catch (err) {
                // Send failed — unwind the entry we just added.
                this.pending.pop();
                if (this.pending.length === 0) {
                    this.inner.release();
                }
                this.fail(reject, err instanceof Error
                    ? err
                    : new Error(`SHM async call failed: ${String(err)}`));
            }
        });
    }
    fail(reject, err) {
        if (this.mapError) {
            this.mapError(err).then(reject, reject);
        }
        else {
            reject(err);
        }
    }
    async destroy() {
        if (this.destroyed) {
            return;
        }
        this.destroyed = true;
        // Reject anything still in flight.
        const err = new Error("ipc-runtime SHM client destroyed before response");
        for (const cb of this.pending.drain()) {
            this.fail(cb.reject, err);
        }
        // Stops the native poll thread and releases the TSFN reference taken
        // when the queue went 0 → 1 — without this, Node never exits when
        // destroyed with calls in flight.
        this.inner.close();
    }
}
/**
 * Factories that load the bundled `ipc_runtime_napi.node` addon and
 * construct an MPSC-SHM client wrapped behind the `IpcClient*` interface.
 * Matches the transport used by `ipc::make_server` on the C++ side, so any
 * server started via that helper accepts these clients directly.
 */
export function createNapiShmSyncClient(shmName, options = {}) {
    const napi = loadIpcRuntimeNapi(options.customAddonPath);
    return new NapiShmSyncClient(
    // An undefined slot id makes the native side self-allocate a free slot
    // (kAutoClientId) instead of aliasing every client onto slot 0.
    new napi.MsgpackClient(shmName, options.clientId, options.serverPid));
}
export function createNapiShmAsyncClient(shmName, options = {}) {
    const napi = loadIpcRuntimeNapi(options.customAddonPath);
    return new NapiShmAsyncClient(
    // Omit the slot id when not given so the native side self-allocates a free
    // slot (kAutoClientId) instead of aliasing every client onto slot 0.
    options.clientId === undefined
        ? new napi.MsgpackClientAsync(shmName)
        : new napi.MsgpackClientAsync(shmName, options.clientId), options.mapError);
}
