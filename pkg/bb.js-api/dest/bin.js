#!/usr/bin/env node
import { runServiceBinary } from '@aztec-foundation/ipc-runtime';
import { BINARY } from './platform.js';
runServiceBinary(BINARY, '@aztec-foundation/bb.js-api', process.argv.slice(2));
