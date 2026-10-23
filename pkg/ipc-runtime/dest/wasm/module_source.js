const GZIP_MAGIC = [0x1f, 0x8b, 0x08];
const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d];
function startsWith(bytes, magic) {
    return magic.every((b, i) => bytes[i] === b);
}
async function gunzip(bytes) {
    const stream = new Blob([bytes])
        .stream()
        .pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function compileBytes(bytes) {
    if (startsWith(bytes, GZIP_MAGIC)) {
        bytes = await gunzip(bytes);
    }
    if (!startsWith(bytes, WASM_MAGIC)) {
        throw new Error("not a wasm module: bad magic bytes");
    }
    // Our bytes never live on a SharedArrayBuffer; the cast only satisfies BufferSource's typing.
    return WebAssembly.compile(bytes);
}
async function compileStreamingOrBuffer(response) {
    if (typeof WebAssembly.compileStreaming === "function") {
        try {
            return await WebAssembly.compileStreaming(response.clone());
        }
        catch {
            // Some hosts reject streaming compilation of synthetic responses; buffer instead.
        }
    }
    return compileBytes(new Uint8Array(await response.arrayBuffer()));
}
async function compileResponse(response, label) {
    if (!response.ok) {
        throw new Error(`fetching wasm module ${label}: HTTP ${response.status}`);
    }
    const type = (response.headers.get("content-type") ?? "").toLowerCase();
    const gzipped = type.includes("gzip") || /\.gz(\?|#|$)/.test(label);
    if (gzipped && response.body) {
        const inflated = new Response(response.body.pipeThrough(new DecompressionStream("gzip")), { headers: { "content-type": "application/wasm" } });
        return compileStreamingOrBuffer(inflated);
    }
    if (type.includes("application/wasm")) {
        return compileStreamingOrBuffer(response);
    }
    // Unknown or missing type (octet-stream, data: URLs): sniff the bytes.
    return compileBytes(new Uint8Array(await response.arrayBuffer()));
}
export async function compileWasmModule(source, platform = {}) {
    if (source instanceof WebAssembly.Module) {
        return source;
    }
    if (source instanceof Uint8Array) {
        return compileBytes(source);
    }
    if (source instanceof ArrayBuffer) {
        return compileBytes(new Uint8Array(source));
    }
    if (source instanceof Response) {
        return compileResponse(source, source.url);
    }
    let url;
    if (source instanceof URL) {
        url = source;
    }
    else {
        try {
            url = new URL(source);
        }
        catch {
            if (!platform.resolvePath) {
                throw new Error(`wasm module source is not a URL: ${source}`);
            }
            url = platform.resolvePath(source);
        }
    }
    if (url.protocol === "file:") {
        if (!platform.readFile) {
            throw new Error(`file: wasm module sources need a platform with readFile: ${url.href}`);
        }
        return compileBytes(await platform.readFile(url));
    }
    return compileResponse(await fetch(url), url.href);
}
