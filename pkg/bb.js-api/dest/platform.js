import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findServiceBinary } from '@aztec-foundation/ipc-runtime';
/** This package's native binary, for ipc-runtime's resolver and process backends. */
export const BINARY = {
    name: 'bb',
    envVar: 'BB_BINARY_PATH',
    archPackages: {
        'x64-linux': '@aztec-foundation/bb.js-api-linux-x64',
        'x64-darwin': '@aztec-foundation/bb.js-api-darwin-x64',
        'arm64-linux': '@aztec-foundation/bb.js-api-linux-arm64',
        'arm64-darwin': '@aztec-foundation/bb.js-api-darwin-arm64',
    },
    ipcPathArgs: ["msgpack", "run", "--input", "{path}"],
    instancePrefix: 'bb',
    packageDir: path.join(path.dirname(fileURLToPath(import.meta.url)), '..'),
};
/**
 * The 'bb' binary to run: an explicit path if given, else
 * `BB_BINARY_PATH`, else the installed arch package for this platform. Null when none
 * of those yields an existing file.
 */
export function findBbBinary(customPath) {
    return findServiceBinary(BINARY, customPath);
}
export const ARCH_PACKAGE_STEM = 'bb.js-api';
