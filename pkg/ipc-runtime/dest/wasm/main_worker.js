import { WasmFfiEngine } from "./backend.js";
/**
 * Body of the worker hosting a module's main instance: create the engine on `init`, serve `call`
 * requests, tear down on `destroy`. Calls run to completion on this worker's thread; the parent's
 * event loop stays free.
 */
export function runMainWorker(side, platform, opts) {
    let engine;
    const log = (message) => side.postMessage({ type: "log", message });
    side.onMessage(async (msg) => {
        switch (msg?.type) {
            case "init": {
                try {
                    const o = msg.options ?? {};
                    const binding = {
                        platform,
                        createThreadWorker: opts.createThreadWorker,
                        // Unused here: this worker is the main worker.
                        createMainWorker: opts.createThreadWorker,
                    };
                    engine = await WasmFfiEngine.create({
                        module: msg.module,
                        threads: o.threads,
                        memory: o.memory,
                        env: o.env,
                        entry: o.entry,
                        logger: log,
                    }, binding);
                    // A shared memory crosses to the caller as the same memory, so it can read the module's
                    // size while a call blocks this worker; an unshared one cannot cross at all.
                    const memory = engine.memory.buffer instanceof SharedArrayBuffer
                        ? engine.memory
                        : undefined;
                    side.postMessage({ type: "ready", memory });
                }
                catch (e) {
                    side.postMessage({
                        type: "init-error",
                        message: e instanceof Error ? (e.stack ?? e.message) : String(e),
                    });
                }
                break;
            }
            case "call": {
                try {
                    const output = engine.call(new Uint8Array(msg.input));
                    side.postMessage({ type: "result", id: msg.id, output }, [
                        output.buffer,
                    ]);
                }
                catch (e) {
                    side.postMessage({
                        type: "error",
                        id: msg.id,
                        message: e instanceof Error ? e.message : String(e),
                    });
                }
                break;
            }
            case "destroy": {
                await engine?.destroy();
                side.postMessage({ type: "destroyed" });
                side.close();
                break;
            }
            default:
                break;
        }
    });
}
