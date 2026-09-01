//! The conformance suite: replay a captured corpus against bb and bb-ref and compare responses
//! byte-for-byte, per frame.
//!
//! A corpus is a directory of `<pid>-connN.req` / `.resp` pairs recorded by
//! `tools/lib/bb_capture_proxy.py` from a real proving run: envelope-framed wire traffic,
//! `[u32 len][u64 request_id][payload]`, one strictly serial connection per file pair (the run is
//! captured with one prover agent, so response order is deterministic). Point at it with
//! `BBREF_CORPUS=<dir>`; without it the test skips (the corpus is a multi-GB artifact regenerated
//! by `tools/regen_corpus.sh`, not a committed fixture).
//!
//! Per connection, each request frame is dispatched through bb-ref's generated handler and the
//! response compared against the recording. The captured `.resp` *is* bb's answer, so bb needs no
//! re-run here; `tests/msgpack_server.rs` separately proves live-bb equality on synthesized
//! frames, and the capture run is seeded (`BB_RNG_SEED`) so the recording reproduces.
//!
//! Diagnosis: a mismatch names the connection, frame index, command and first differing byte.
//! `BBREF_EXTRACT=<conn>:<frame>` additionally writes that request frame (with the whole
//! connection's preceding frames, since Chonk sequences are stateful) to `BBREF_EXTRACT_OUT` for
//! a standalone repro via `bb-ref msgpack run --envelopes --input <file>`.

use bb_ref::msgpack::generated::bb_server::handle_request;
use bb_ref::msgpack::handler::BbRefHandler;

fn read_frames(bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 12 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        assert!(len >= 8, "frame shorter than its request id");
        assert!(i + 4 + len <= bytes.len(), "truncated frame (partial capture?)");
        let id = u64::from_le_bytes(bytes[i + 4..i + 12].try_into().unwrap());
        frames.push((id, bytes[i + 12..i + 4 + len].to_vec()));
        i += 4 + len;
    }
    assert_eq!(i, bytes.len(), "trailing bytes after last frame");
    frames
}

/// Command tag of a request payload, for reporting.
fn command_name(payload: &[u8]) -> String {
    rmp_serde::from_slice::<Vec<(String, serde::de::IgnoredAny)>>(payload)
        .ok()
        .and_then(|v| v.into_iter().next().map(|(name, _)| name))
        .unwrap_or_else(|| "<undecodable>".into())
}

#[test]
fn corpus_replay() {
    let Ok(dir) = std::env::var("BBREF_CORPUS") else {
        eprintln!("skipping: set BBREF_CORPUS=<capture dir> (see tools/regen_corpus.sh)");
        return;
    };
    let mut req_files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("corpus dir")
        .filter_map(|e| {
            let p = e.unwrap().path();
            // Proxy-captured bb connections only ("-connN"); hook-captured client streams of
            // other services ("-streamN-...") are not bb's surface.
            (p.extension().is_some_and(|x| x == "req")
                && p.file_stem().is_some_and(|st| st.to_string_lossy().contains("-conn")))
            .then_some(p)
        })
        .collect();
    req_files.sort();
    assert!(!req_files.is_empty(), "no .req files in {dir}");

    let mut total = 0usize;
    let mut skipped = 0usize;
    let mut failures = Vec::new();
    for req_path in &req_files {
        let conn = req_path.file_stem().unwrap().to_string_lossy().into_owned();
        let requests = read_frames(&std::fs::read(req_path).unwrap());
        let golden = read_frames(&std::fs::read(req_path.with_extension("resp")).unwrap());
        assert_eq!(requests.len(), golden.len(), "{conn}: request/response count mismatch");

        // One handler per connection: bb state (the Chonk session) is per-process, and the
        // capture spawns one bb per connection.
        let mut handler = BbRefHandler::new();
        for (idx, ((req_id, payload), (gold_id, gold_payload))) in requests.iter().zip(&golden).enumerate() {
            assert_eq!(req_id, gold_id, "{conn}#{idx}: response id mismatch in the recording");
            let cmd = command_name(payload);
            // The AVM is permanently out of bb-ref's scope; its frames stay in the corpus (they
            // are part of the recorded epoch) but are not replayed.
            if cmd.starts_with("BbAvm") {
                skipped += 1;
                continue;
            }
            if let Ok(extract) = std::env::var("BBREF_EXTRACT") {
                if extract == format!("{conn}:{idx}") {
                    let out = std::env::var("BBREF_EXTRACT_OUT").unwrap_or("extracted.frames".into());
                    let mut buf = Vec::new();
                    for (id, pl) in &requests[..=idx] {
                        buf.extend((8 + pl.len() as u32).to_le_bytes());
                        buf.extend(id.to_le_bytes());
                        buf.extend(pl);
                    }
                    std::fs::write(&out, buf).unwrap();
                    eprintln!("extracted {conn}#0..={idx} -> {out}");
                }
            }
            let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_request(&mut handler, payload)
            })) {
                Ok(r) => r,
                Err(_) => {
                    total += 1;
                    failures.push(format!("{conn}#{idx} {cmd}: PANICKED"));
                    continue;
                }
            };
            total += 1;
            if &response != gold_payload {
                let at = response
                    .iter()
                    .zip(gold_payload.iter())
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| response.len().min(gold_payload.len()));
                failures.push(format!(
                    "{conn}#{idx} {cmd}: differs at byte {at} (ours {} B, bb {} B)",
                    response.len(),
                    gold_payload.len()
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} frames diverged:\n{}",
        failures.len(),
        total,
        failures.join("\n")
    );
    println!(
        "conformance: {total} frames across {} connections byte-identical ({skipped} AVM frames skipped)",
        req_files.len()
    );
}
