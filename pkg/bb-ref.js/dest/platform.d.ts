import { type ServiceBinary } from '@aztec-foundation/ipc-runtime';
/** This package's native binary, for ipc-runtime's resolver and process backends. */
export declare const BINARY: ServiceBinary;
/**
 * The 'bb-ref' binary to run: an explicit path if given, else
 * `BB_REF_BINARY_PATH`, else the installed arch package for this platform. Null when none
 * of those yields an existing file.
 */
export declare function findBbBinary(customPath?: string): string | null;
export declare const ARCH_PACKAGE_STEM = "bb-ref.js";
//# sourceMappingURL=platform.d.ts.map