//! Shared-memory growth stress for wasm32-wasip1-threads under V8: rayon tasks allocate fresh
//! buffers and immediately `memset` them (`memory.fill`), keeping them alive so the heap keeps
//! growing. Under V8 a thread's bulk-memory bounds check uses its own cached memory size, which
//! another thread's `memory.grow` updates only asynchronously; without bb-ref's wasm allocator
//! (`base/wasm/alloc.rs`) this traps with "memory access out of bounds" within a few runs.
//!
//!   growstress [MB_CAP=1536] [ROUNDS=1]
use rayon::prelude::*;
use std::sync::Mutex;

extern crate bb_ref;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cap_mb: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1536);
    let rounds: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let threads = rayon::current_num_threads();
    let mut fills = 0usize;
    for round in 0..rounds {
        let live: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
        let total = std::sync::atomic::AtomicUsize::new(0);
        let mut step = 0u64;
        while total.load(std::sync::atomic::Ordering::Relaxed) < cap_mb << 20 {
            let n = (0..threads * 8)
                .into_par_iter()
                .map(|t| {
                    // xorshift over (round, step, t): sizes from 1 KB to ~1 MB, skewed small.
                    let mut s = (round as u64 + 1) * 0x9e37_79b9_7f4a_7c15 ^ (step << 20) ^ t as u64;
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    let len = 1024 + (s as usize % (1 << (10 + (s >> 40) as usize % 11)));
                    let mut v: Vec<u8> = Vec::with_capacity(len);
                    unsafe {
                        std::ptr::write_bytes(v.as_mut_ptr(), (t as u8) | 1, len);
                        v.set_len(len);
                    }
                    total.fetch_add(len, std::sync::atomic::Ordering::Relaxed);
                    live.lock().unwrap().push(v);
                    1usize
                })
                .sum::<usize>();
            fills += n;
            step += 1;
        }
        let live = live.into_inner().unwrap();
        assert!(live.iter().all(|v| v[0] & 1 == 1 && v[v.len() - 1] == v[0]));
    }
    println!("growstress ok: threads={threads} fills={fills} cap={cap_mb}MB rounds={rounds}");
}
