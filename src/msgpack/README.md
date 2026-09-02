[◄ bb-ref](../../README.md)

# msgpack — the wire protocol

How the outside world talks to bb-ref: bb's msgpack command protocol, served byte-compatibly, so
a node configured to spawn `bb` can spawn `bb-ref msgpack run` instead and never notice. Frames
are `[u32 len][u64 request_id][payload]` over a file, pipe, socket, or shared memory — the same
framing the conformance corpus records (see [docs/conformance.md](../../docs/conformance.md)).

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

| file | what it is |
|---|---|
| `generated/` | **do not edit** — generated from the pin's `bb_schema.json` by ipc-codegen (`dev/regen_msgpack.sh`). One schema defines bb's wire surface; bb's server and this one are both generated from it, so encodings match by construction |
| `generated/bb_types.rs` | every command/response struct |
| `generated/bb_server.rs`, `bb_client.rs`, `backend.rs`, `error.rs` | dispatch loop, a Rust client (used by tests), transports, error envelope |
| `handler.rs` | the hand-written part: each command mapped onto the modules below — same flavor dispatch, proof splits, self-verification, and error responses as bb's `bbapi_*.cpp` adapters; commands outside the proving surface answer `unsupported command` |

The handler owns the `Srs` (loaded once at server startup and injected — [`base/srs.rs`](../base/srs.rs))
and draws all randomness from the session-global source, so `BB_RNG_SEED` governs reproducibility
exactly as it does for bb.

## What makes this layer delicate

- **This boundary must never panic.** Malformed payloads, wrong-size VKs, non-canonical scalars
  and unknown commands all get error *responses*; the soundness suite's API-boundary tests pin
  this.
- **Response bytes are the conformance contract**: `tools/conformance.sh` compares bb-ref's
  responses byte-for-byte against recorded bb goldens, so even error strings and msgpack field
  order matter.
- **Regeneration follows the pin**: if the pin moves and the schema changed, re-run
  `dev/regen_msgpack.sh` rather than editing `generated/` — hand edits are overwritten.
