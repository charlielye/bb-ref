// A well-known global rather than an import in either direction, so a native backend package and
// the generated client package need not depend on each other, and two copies of this module in
// one app still agree.
const REGISTRY_KEY = Symbol.for("@aztec-foundation/ipc-runtime/backends");
function registry() {
    const global = globalThis;
    return (global[REGISTRY_KEY] ??= new Map());
}
/** Make `factories` the backends for `service`; a native backend package calls this when imported. */
export function registerBackend(service, factories) {
    registry().set(service, factories);
}
/**
 * The registered backend for a service, or a message naming what to install. `hint` is the
 * package a caller should be told about.
 */
export function registeredBackend(service, kind, hint) {
    const factory = registry().get(service)?.[kind];
    if (!factory) {
        throw new Error(`${hint}: no ${kind === "sync" ? "synchronous " : ""}backend registered for ${service}. ` +
            "Install a native backend package for it (registering itself when imported), or pass one " +
            "as options.backend.");
    }
    return factory;
}
