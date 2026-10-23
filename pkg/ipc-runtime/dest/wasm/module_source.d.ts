/**
 * Compile a wasm module from wherever a consumer keeps it: an already compiled `Module`, raw or
 * gzipped bytes, a fetch `Response`, or a URL (`http(s):`, `data:`, `blob:`, `file:`).
 *
 * URLs and responses go through `WebAssembly.compileStreaming`, so compilation overlaps the
 * download and, in browsers that cache compiled wasm (Chrome, Firefox), a repeat visit starts
 * from the optimized code of the previous one. Gzip is recognised from the response headers, the
 * URL, or the magic bytes and inflated with the platform's `DecompressionStream`, so a `.wasm.gz`
 * asset or a `data:application/gzip;base64,…` URL needs no JavaScript inflater.
 */
export type WasmModuleSource = WebAssembly.Module | Uint8Array | ArrayBuffer | Response | URL | string;
export interface ModuleLoadPlatform {
    /** Read a `file:` URL (node). Browsers fetch everything. */
    readFile?(url: URL): Promise<Uint8Array>;
    /** Turn a plain filesystem path into a URL (node). */
    resolvePath?(path: string): URL;
}
export declare function compileWasmModule(source: WasmModuleSource, platform?: ModuleLoadPlatform): Promise<WebAssembly.Module>;
