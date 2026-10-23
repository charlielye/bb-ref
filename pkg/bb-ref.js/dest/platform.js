import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findServiceBinary } from '@aztec-foundation/ipc-runtime';
/** This package's native binary, for ipc-runtime's resolver and process backends. */
export const BINARY = {
    name: 'bb-ref',
    envVar: 'BB_REF_BINARY_PATH',
    archPackages: {
        'x64-linux': 'bb-ref.js-linux-x64',
        'x64-darwin': 'bb-ref.js-darwin-x64',
        'arm64-linux': 'bb-ref.js-linux-arm64',
        'arm64-darwin': 'bb-ref.js-darwin-arm64',
    },
    ipcPathArgs: ["--socket", "{path}"],
    instancePrefix: 'bb',
    packageDir: path.join(path.dirname(fileURLToPath(import.meta.url)), '..'),
};
/**
 * The 'bb-ref' binary to run: an explicit path if given, else
 * `BB_REF_BINARY_PATH`, else the installed arch package for this platform. Null when none
 * of those yields an existing file.
 */
export function findBbBinary(customPath) {
    return findServiceBinary(BINARY, customPath);
}
export const ARCH_PACKAGE_STEM = 'bb-ref.js';
