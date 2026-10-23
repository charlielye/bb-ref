/** The parent's handle on a browser `Worker`. */
export function browserWorkerHandle(worker) {
    return {
        postMessage: (message, transfer) => worker.postMessage(message, transfer ?? []),
        onMessage: (handler) => worker.addEventListener("message", (e) => handler(e.data)),
        onError: (handler) => worker.addEventListener("error", (e) => handler(e)),
        terminate: async () => worker.terminate(),
        unref: () => { },
    };
}
export const browserPlatform = {
    // For scripts served as-is. Bundled code must spawn its workers with the literal
    // `new Worker(new URL('./x.js', import.meta.url), { type: 'module' })` and wrap them with
    // `browserWorkerHandle` (see `WasmFfiBinding`).
    createWorker: (url) => browserWorkerHandle(new Worker(url, { type: "module" })),
    hardwareConcurrency: () => navigator.hardwareConcurrency || 1,
    sharedMemoryAvailable: () => typeof SharedArrayBuffer !== "undefined" &&
        globalThis.crossOriginIsolated ===
            true,
    // iOS browsers kill a page well before it reaches the 4 GiB a wasm memory may declare; asking
    // for a 1 GiB maximum keeps the reservation within what they grant.
    maximumMemoryPages: () => typeof navigator !== "undefined" && /iPad|iPhone/.test(navigator.userAgent)
        ? 2 ** 14
        : 2 ** 16,
};
/** The worker's side of a browser `Worker` channel. */
export function browserWorkerSide() {
    const scope = globalThis;
    return {
        onMessage: (handler) => scope.addEventListener("message", (e) => handler(e.data)),
        postMessage: (message, transfer) => scope.postMessage(message, transfer ?? []),
        close: () => scope.close(),
    };
}
