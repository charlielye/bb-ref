#!/usr/bin/env bash
# bb's answers to tests/msgpack_server.rs's request frames, recorded under tests/data/<pin7>/wire/
# from the pin's bb (bin/bb): that test with BBREF_RECORD_WIRE=1, every case (BBREF_FULL=1).
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
cd "$ROOT"
BBREF_RECORD_WIRE=1 BBREF_FULL=1 cargo test --release --test msgpack_server msgpack_server_oracle
