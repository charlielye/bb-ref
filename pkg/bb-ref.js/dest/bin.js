#!/usr/bin/env node
import { runServiceBinary } from '@aztec-foundation/ipc-runtime';
import { BINARY } from './platform.js';
runServiceBinary(BINARY, 'bb-ref.js', process.argv.slice(2));
