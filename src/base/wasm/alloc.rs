//! The global allocator for threaded wasm: the system allocator, plus keeping each thread's view
//! of the shared memory's size current.
//!
//! V8 bounds-checks bulk-memory ops (`memory.fill`/`memory.copy`, i.e. every non-trivial memset
//! and memcpy) against a per-thread cached memory size. When one thread's `malloc` grows the
//! memory, the other threads' caches catch up only asynchronously (an interrupt, measured at
//! ~0.1–1 ms), so another thread that is handed the new pages — by the next `malloc`, or with
//! data — and memsets them inside that window traps with "memory access out of bounds", even
//! though plain loads and stores there succeed (node 24 / V8 13.6; `examples/growstress.rs`
//! reproduces it in most runs). Any `memory.grow` updates the calling thread's cache
//! synchronously, including a grow by zero pages. So: every heap op checks the largest size any
//! thread has published and the end of the block it got back against this thread's view, and
//! refreshes it with `memory.grow(0)` when either is beyond. The check is one relaxed atomic load
//! and one TLS load, kept out of line (inlined into every allocation site it costs ~3% of module
//! size); the refresh happens about once per memory growth per thread.
//!
//! Zeroed allocation is `malloc` + a memset here (after the check) rather than `calloc`, whose
//! own memset would run before it; `realloc`'s internal copy runs after the pre-check only.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

const PAGE: usize = 65536;

/// The largest memory size (bytes) any thread has seen.
static PUBLISHED: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// The memory size (bytes) this thread's bounds checks are known to cover.
    static VIEW: Cell<usize> = const { Cell::new(0) };
}

#[cold]
#[inline(never)]
fn refresh(view: &Cell<usize>) {
    core::arch::wasm32::memory_grow::<0>(0);
    let size = core::arch::wasm32::memory_size::<0>() * PAGE;
    PUBLISHED.fetch_max(size, Relaxed);
    view.set(size);
}

/// Bring this thread's view up to `end` bytes (and to what other threads have published).
fn cover(end: usize) {
    let need = end.max(PUBLISHED.load(Relaxed));
    // `try_with`: TLS is gone during thread teardown; the system allocator alone is no worse.
    let _ = VIEW.try_with(|v| {
        if need > v.get() {
            refresh(v);
        }
    });
}

pub struct GrowSyncAlloc;

unsafe impl GlobalAlloc for GrowSyncAlloc {
    #[inline(never)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        cover(p as usize + layout.size());
        p
    }

    #[inline(never)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = self.alloc(layout);
        if !p.is_null() {
            core::ptr::write_bytes(p, 0, layout.size());
        }
        p
    }

    #[inline(never)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        cover(0);
        System.dealloc(ptr, layout)
    }

    #[inline(never)]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        cover(0);
        let p = System.realloc(ptr, layout, new_size);
        cover(p as usize + new_size);
        p
    }
}

#[global_allocator]
static ALLOC: GrowSyncAlloc = GrowSyncAlloc;

/// `std::alloc::alloc_zeroed`, with blocks of 1 MiB and more memset on the rayon pool: wasi-libc
/// cannot know that recycled linear memory is clean, so every zeroed block is memset, and serially
/// on the calling thread (~0.2 s of main-only time building a large instance's columns). Each
/// worker first brings its own view up to the end of its chunk: the block may lie in pages the
/// allocating thread has just grown.
pub unsafe fn alloc_zeroed_par(layout: Layout) -> *mut u8 {
    use rayon::prelude::*;
    const CHUNK: usize = 1 << 16;
    if layout.size() < 1 << 20 {
        return std::alloc::alloc_zeroed(layout);
    }
    let p = std::alloc::alloc(layout);
    if !p.is_null() {
        let (start, end) = (p as usize, p as usize + layout.size());
        (start..end).into_par_iter().step_by(CHUNK).for_each(|a| {
            let e = (a + CHUNK).min(end);
            cover(e);
            core::ptr::write_bytes(a as *mut u8, 0, e - a);
        });
    }
    p
}
