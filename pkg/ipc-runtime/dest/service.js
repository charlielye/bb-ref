import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import * as fs from "node:fs";
import * as path from "node:path";
import { SpawnedProcessBackend, SpawnedProcessBackendSync, } from "./spawned_backend.js";
import { IpcSpawnError } from "./errors.js";
function platformKey() {
    return `${process.arch}-${process.platform}`;
}
function archPackageDir(binary) {
    const packageName = binary.archPackages[platformKey()];
    if (!packageName) {
        return null;
    }
    try {
        const require = createRequire(import.meta.url);
        return path.dirname(require.resolve(`${packageName}/package.json`));
    }
    catch {
        // Not installed as a dependency: fall back to a copy prepared inside the owning package,
        // which is how a repository checkout runs before anything is published.
        const sibling = path.join(binary.packageDir, "packages", packageName.split("/").pop());
        return fs.existsSync(path.join(sibling, "package.json")) ? sibling : null;
    }
}
/**
 * The binary to run: `customPath` if given, else the package's environment variable, else the
 * installed arch package for this platform. Null when none of those yields an existing file.
 */
export function findServiceBinary(binary, customPath) {
    const explicit = customPath ?? process.env[binary.envVar];
    if (explicit) {
        return fs.existsSync(explicit) ? path.resolve(explicit) : null;
    }
    const dir = archPackageDir(binary);
    if (dir) {
        const candidate = path.join(dir, binary.name);
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }
    return null;
}
/** The child's environment: the caller's, plus the thread count under both names services read. */
export function serviceProcessEnv(options) {
    if (options.threads === undefined) {
        return options.env;
    }
    const threads = String(options.threads);
    return {
        HARDWARE_CONCURRENCY: threads,
        RAYON_NUM_THREADS: threads,
        ...options.env,
    };
}
function resolveOrThrow(binary, binaryPath) {
    const resolved = findServiceBinary(binary, binaryPath);
    if (!resolved) {
        throw new IpcSpawnError(`${binary.name} binary not found`, 
        /*retry=*/ false);
    }
    return resolved;
}
/**
 * Spawn the service and connect to it. Process lifecycle — connectivity, death detection,
 * optional respawn, teardown — is owned by the backend and never leaks onto the caller's API.
 */
export function spawnServiceBackend(binary, defaultTransport, options = {}) {
    return SpawnedProcessBackend.spawn({
        binaryPath: resolveOrThrow(binary, options.binaryPath),
        binaryName: binary.name,
        instancePrefix: binary.instancePrefix,
        ipcPathArgs: binary.ipcPathArgs,
        transport: options.transport ?? defaultTransport,
        logger: options.logger,
        connectTimeoutMs: options.connectTimeoutMs,
        env: serviceProcessEnv(options),
        extraArgs: options.extraArgs,
        respawn: options.respawn,
        unref: options.unref,
        clientId: options.clientId,
        napiPath: options.napiPath,
    });
}
/** The synchronous form: shared memory is the one transport with a synchronous client. */
export function spawnServiceBackendSync(binary, options = {}) {
    if (options.transport !== undefined && options.transport !== "shm") {
        throw new Error(`${binary.name}: the synchronous backend needs the shm transport`);
    }
    return SpawnedProcessBackendSync.spawn({
        binaryPath: resolveOrThrow(binary, options.binaryPath),
        binaryName: binary.name,
        instancePrefix: `${binary.instancePrefix}-sync`,
        ipcPathArgs: binary.ipcPathArgs,
        transport: "shm",
        logger: options.logger,
        connectTimeoutMs: options.connectTimeoutMs,
        env: serviceProcessEnv(options),
        extraArgs: options.extraArgs,
        unref: options.unref,
        clientId: options.clientId ?? 0,
        napiPath: options.napiPath,
    });
}
/** Run the service binary as a CLI, forwarding argv and exit status. Backs a package's `bin`. */
export function runServiceBinary(binary, packageName, argv) {
    const binaryPath = findServiceBinary(binary);
    if (!binaryPath) {
        console.error(`${binary.name}: native binary not found. Install the matching ` +
            `'${packageName}-<platform>' package, set ${binary.envVar}, or pass its path.`);
        process.exit(1);
    }
    const result = spawnSync(binaryPath, argv, { stdio: "inherit" });
    if (result.error) {
        console.error(result.error.message);
        process.exit(1);
    }
    process.exit(result.status ?? 1);
}
/**
 * Which backend to use, given what this host can offer. Unset: the process when its binary
 * resolves, else wasm. A name forces one, with no fallback to the other.
 */
export async function pickServiceBackend(wanted, choices) {
    if (typeof wanted === "object") {
        return wanted;
    }
    const { process: proc, wasm } = choices;
    if (proc &&
        (wanted === "process" ||
            (wanted === undefined && (!wasm || proc.available())))) {
        try {
            return await proc.create();
        }
        catch (err) {
            if (wanted === "process" || !wasm) {
                throw err;
            }
            choices.logger?.(`${choices.label} process unavailable (${err.message}); falling back to wasm`);
        }
    }
    if (wasm && (wanted === undefined || wanted === "wasm")) {
        return wasm.create();
    }
    throw new Error(`${choices.label}: no such backend here: ${String(wanted)}`);
}
