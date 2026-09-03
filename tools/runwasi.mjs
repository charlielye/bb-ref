import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';
import { argv } from 'node:process';
const wasi = new WASI({ version: 'preview1', args: ['fieldbench', argv[3] ?? '8000000'] });
const wasm = await WebAssembly.compile(await readFile(argv[2]));
const instance = await WebAssembly.instantiate(wasm, wasi.getImportObject());
wasi.start(instance);
