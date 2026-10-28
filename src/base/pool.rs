//! The native global allocator: glibc for everything under 64 KiB, and one process-wide arena for
//! everything at or above it.
//!
//! The prover streams gigabytes of multi-megabyte buffers (polynomials, folded sumcheck columns,
//! MSM and commitment scratch), many of them freed on rayon workers. glibc either returns such a
//! buffer to the kernel (above its mmap threshold, so the next one refaults every 4 KiB page:
//! ~15M faults on the rollup frames) or keeps it in the freeing thread's arena, where it fragments
//! and is never returned (bb-ref's native peak RSS was 8–31% above bb's on chonk for that reason,
//! with a live heap at or below bb's). The wasm heap (wasi-libc's dlmalloc: one heap, freed ranges
//! coalesced and reused, memory never returned) has neither problem, which is why bb-ref is leaner
//! than bb under V8. This gives native the same reuse for big blocks only; small allocations keep
//! glibc's uncontended per-thread arenas, because sending them through one lock is what made a
//! single glibc arena slow.
//!
//! The arena is one lazily reserved address range, carved best-fit in 64 KiB granules: freed
//! ranges coalesce with their neighbours and with the unallocated top, and keep their pages, so a
//! reused range costs no faults. `trim` (after every msgpack request) hands the pages of every free
//! range back to the kernel. A zeroed allocation memsets only the part that was used before.
//!
//! The arena asks for transparent huge pages while the host can serve them (`adapt`): with them the
//! remaining first-touch faults and TLB misses go too (rollup subset 52.7 -> 43.7 s, Zen 4). Under
//! THP's default `madvise` defrag a huge-page fault the kernel cannot serve from a free 2 MiB block
//! stalls in direct compaction, and on a long-running host with fragmented memory that made the
//! rollup root 4x slower than without huge pages; so only while at least half of the free memory
//! sits in 2 MiB blocks, re-checked after every request. `BBREF_HUGEPAGES=0|1` overrides.

#[cfg(all(
    not(target_family = "wasm"),
    not(feature = "mimalloc"),
    not(feature = "heap-profile")
))]
mod imp {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    use std::sync::Mutex;

    /// Requests at or above this go to the arena.
    const MIN: usize = 1 << 16;
    /// Arena granule and alignment.
    const G: usize = 1 << 16;
    /// Address space reserved for the arena (not memory: pages exist once touched).
    const RESERVE: usize = 1 << 40;
    /// Free ranges tracked; a free that cannot be recorded gives its pages back and drops the range.
    const SLOTS: usize = 4096;

    /// Whether the arena asks for transparent huge pages.
    static HUGE: AtomicBool = AtomicBool::new(false);

    /// Set if the reservation failed: every allocation then goes to glibc (no arena block exists yet).
    static NO_ARENA: AtomicBool = AtomicBool::new(false);

    fn big(size: usize, align: usize) -> bool {
        size >= MIN && align <= G && !NO_ARENA.load(Relaxed)
    }

    fn granules(size: usize) -> usize {
        size.div_ceil(G) * G
    }

    #[derive(Clone, Copy)]
    struct Range {
        off: usize,
        len: usize,
        /// Holds pages from an earlier use (so is not known to be zero).
        dirty: bool,
    }

    struct Arena {
        base: usize,
        /// Everything at and above `top` is unallocated; `[top, hwm)` was used before.
        top: usize,
        hwm: usize,
        /// Free ranges below `top`, sorted by offset, none adjacent to another or to `top`.
        free: [Range; SLOTS],
        n: usize,
    }

    static ARENA: Mutex<Arena> = Mutex::new(Arena {
        base: 0,
        top: 0,
        hwm: 0,
        free: [Range {
            off: 0,
            len: 0,
            dirty: false,
        }; SLOTS],
        n: 0,
    });

    fn lock() -> std::sync::MutexGuard<'static, Arena> {
        ARENA.lock().unwrap_or_else(|e| e.into_inner())
    }

    unsafe fn release(base: usize, off: usize, len: usize) {
        libc::madvise((base + off) as *mut libc::c_void, len, libc::MADV_DONTNEED);
    }

    impl Arena {
        /// A range of `len` bytes: its offset and how many of its leading bytes may be non-zero.
        fn take(&mut self, len: usize) -> Option<(usize, usize)> {
            if self.base == 0 {
                // SAFETY: an anonymous private mapping; NORESERVE so the range costs no commit charge.
                let p = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        RESERVE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                        -1,
                        0,
                    )
                };
                if p == libc::MAP_FAILED {
                    return None;
                }
                self.base = p as usize;
                if HUGE.load(Relaxed) {
                    // SAFETY: advice on our own mapping.
                    unsafe { libc::madvise(p, RESERVE, libc::MADV_HUGEPAGE) };
                }
            }
            let best = (0..self.n)
                .filter(|&i| self.free[i].len >= len)
                .min_by_key(|&i| self.free[i].len);
            if let Some(i) = best {
                let r = self.free[i];
                if r.len == len {
                    self.free.copy_within(i + 1..self.n, i);
                    self.n -= 1;
                } else {
                    self.free[i].off += len;
                    self.free[i].len -= len;
                }
                return Some((r.off, if r.dirty { len } else { 0 }));
            }
            let off = self.top;
            if off + len > RESERVE {
                return None;
            }
            self.top += len;
            let dirty = self.hwm.clamp(off, off + len) - off;
            self.hwm = self.hwm.max(self.top);
            Some((off, dirty))
        }

        fn give(&mut self, off: usize, len: usize) {
            let i = self.free[..self.n].partition_point(|r| r.off < off);
            let joins_prev = i > 0 && self.free[i - 1].off + self.free[i - 1].len == off;
            let joins_next = i < self.n && off + len == self.free[i].off;
            let mut r = Range { off, len, dirty: true };
            let mut at = i;
            if joins_prev {
                at = i - 1;
                r.off = self.free[at].off;
                r.len += self.free[at].len;
            }
            let mut remove = (joins_prev as usize) + (joins_next as usize);
            if joins_next {
                r.len += self.free[i].len;
            }
            if r.off + r.len == self.top {
                // Back into the unallocated top; its pages stay below `hwm`.
                self.top = r.off;
                self.free.copy_within(at + remove..self.n, at);
                self.n -= remove;
                return;
            }
            if remove == 0 {
                if self.n == SLOTS {
                    // SAFETY: the range is ours and now unreachable; only its pages go.
                    unsafe { release(self.base, off, len) };
                    return;
                }
                self.free.copy_within(i..self.n, i + 1);
                self.n += 1;
                remove = 1;
            }
            self.free[at] = r;
            self.free.copy_within(at + remove..self.n, at + 1);
            self.n -= remove - 1;
        }

        /// Grow the block `[off, off+len)` in place to `new_len`, if what follows it is free.
        fn grow(&mut self, off: usize, len: usize, new_len: usize) -> Option<usize> {
            let end = off + len;
            let extra = new_len - len;
            if end == self.top && self.top + extra <= RESERVE {
                self.top += extra;
                let dirty = self.hwm.clamp(end, end + extra) - end;
                self.hwm = self.hwm.max(self.top);
                return Some(dirty);
            }
            let i = self.free[..self.n].partition_point(|r| r.off < end);
            if i < self.n && self.free[i].off == end && self.free[i].len >= extra {
                let r = self.free[i];
                if r.len == extra {
                    self.free.copy_within(i + 1..self.n, i);
                    self.n -= 1;
                } else {
                    self.free[i].off += extra;
                    self.free[i].len -= extra;
                }
                return Some(if r.dirty { extra } else { 0 });
            }
            None
        }
    }

    /// An arena block for `size` bytes and how many of its leading bytes may be non-zero.
    unsafe fn take(size: usize) -> (*mut u8, usize) {
        let mut a = lock();
        match a.take(granules(size)) {
            Some((off, dirty)) => ((a.base + off) as *mut u8, dirty.min(size)),
            None => {
                if a.base == 0 {
                    NO_ARENA.store(true, Relaxed);
                }
                (std::ptr::null_mut(), 0)
            }
        }
    }

    unsafe fn give(ptr: *mut u8, size: usize) {
        let mut a = lock();
        let off = ptr as usize - a.base;
        a.give(off, granules(size));
    }

    pub struct BigBlockArena;

    unsafe impl GlobalAlloc for BigBlockArena {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            if big(l.size(), l.align()) {
                let p = take(l.size()).0;
                if !p.is_null() || !NO_ARENA.load(Relaxed) {
                    return p;
                }
            }
            System.alloc(l)
        }

        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            if big(l.size(), l.align()) {
                let (p, dirty) = take(l.size());
                if !p.is_null() {
                    p.write_bytes(0, dirty);
                }
                if !p.is_null() || !NO_ARENA.load(Relaxed) {
                    return p;
                }
            }
            System.alloc_zeroed(l)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, l: Layout) {
            if big(l.size(), l.align()) {
                give(ptr, l.size())
            } else {
                System.dealloc(ptr, l)
            }
        }

        unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
            match (big(l.size(), l.align()), big(new_size, l.align())) {
                (false, false) => System.realloc(ptr, l, new_size),
                (true, true) => {
                    let (len, new_len) = (granules(l.size()), granules(new_size));
                    let mut a = lock();
                    let off = ptr as usize - a.base;
                    if new_len <= len {
                        if new_len < len {
                            a.give(off + new_len, len - new_len);
                        }
                        return ptr;
                    }
                    if a.grow(off, len, new_len).is_some() {
                        // The grown tail's old contents are unspecified for realloc.
                        return ptr;
                    }
                    drop(a);
                    let new = take(new_size).0;
                    if !new.is_null() {
                        std::ptr::copy_nonoverlapping(ptr, new, l.size());
                        give(ptr, l.size());
                    }
                    new
                }
                _ => {
                    let new = self.alloc(Layout::from_size_align_unchecked(new_size, l.align()));
                    if !new.is_null() {
                        std::ptr::copy_nonoverlapping(ptr, new, l.size().min(new_size));
                        self.dealloc(ptr, l);
                    }
                    new
                }
            }
        }
    }

    #[global_allocator]
    static ALLOC: BigBlockArena = BigBlockArena;

    /// `std::alloc::alloc_zeroed`, with a reused range's memset spread over the rayon pool (fresh
    /// arena pages are already zero, and untouched ones cost nothing).
    pub unsafe fn alloc_zeroed(l: Layout) -> *mut u8 {
        use rayon::prelude::*;
        const CHUNK: usize = 1 << 20;
        if !big(l.size(), l.align()) {
            return std::alloc::alloc_zeroed(l);
        }
        let (p, dirty) = take(l.size());
        if p.is_null() {
            return std::alloc::alloc_zeroed(l);
        }
        let a = p as usize;
        (0..dirty).into_par_iter().step_by(CHUNK).for_each(|o| {
            ((a + o) as *mut u8).write_bytes(0, CHUNK.min(dirty - o));
        });
        p
    }

    /// Give the pages of every free range, and of the used-before top, back to the kernel.
    pub fn trim() {
        let mut a = lock();
        let (base, top, hwm) = (a.base, a.top, a.hwm);
        // SAFETY: free ranges and the top are unallocated; dropping their pages leaves them zero.
        unsafe {
            for i in 0..a.n {
                if a.free[i].dirty {
                    release(base, a.free[i].off, a.free[i].len);
                    a.free[i].dirty = false;
                }
            }
            if hwm > top {
                release(base, top, hwm - top);
            }
        }
        a.hwm = top;
    }

    /// Ask for (or stop asking for) transparent huge pages on the arena.
    pub fn set_huge_pages(on: bool) {
        let a = lock();
        if HUGE.swap(on, Relaxed) != on && a.base != 0 {
            let advice = if on { libc::MADV_HUGEPAGE } else { libc::MADV_NOHUGEPAGE };
            // SAFETY: advice on our own mapping.
            unsafe { libc::madvise(a.base as *mut libc::c_void, RESERVE, advice) };
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn coalesce_reuse_and_zeroing() {
            let mut a = Arena {
                base: 0,
                top: 0,
                hwm: 0,
                free: [Range {
                    off: 0,
                    len: 0,
                    dirty: false,
                }; SLOTS],
                n: 0,
            };
            a.base = 1; // never dereferenced: offsets only
            let x = a.take(4 * G).unwrap();
            let y = a.take(2 * G).unwrap();
            let z = a.take(G).unwrap();
            assert_eq!((x, y, z), ((0, 0), (4 * G, 0), (6 * G, 0)));
            a.give(0, 4 * G);
            a.give(4 * G, 2 * G);
            assert_eq!((a.n, a.free[0].off, a.free[0].len), (1, 0, 6 * G));
            assert_eq!(a.take(5 * G), Some((0, 5 * G)));
            a.give(6 * G, G);
            assert_eq!((a.top, a.n), (5 * G, 0), "frees next to the top fold back into it");
        }

        #[test]
        fn alloc_realloc_dealloc() {
            let l = Layout::from_size_align(3 << 20, 64).unwrap();
            unsafe {
                let p = std::alloc::alloc(l);
                p.write_bytes(0xab, l.size());
                std::alloc::dealloc(p, l);
                let z = alloc_zeroed(l);
                assert!(std::slice::from_raw_parts(z, l.size()).iter().all(|&b| b == 0));
                let g = std::alloc::realloc(z, l, 40 << 20);
                *g.add((40 << 20) - 1) = 1;
                assert_eq!(*g, 0);
                let s = std::alloc::realloc(g, Layout::from_size_align(40 << 20, 64).unwrap(), 100);
                assert_eq!(*s, 0);
                std::alloc::dealloc(s, Layout::from_size_align(100, 64).unwrap());
            }
            trim();
        }
    }
}

#[cfg(all(
    not(target_family = "wasm"),
    not(feature = "mimalloc"),
    not(feature = "heap-profile")
))]
pub use imp::alloc_zeroed;

/// Give the arena's free pages back to the kernel and re-decide its huge pages (`adapt`).
#[cfg(all(
    not(target_family = "wasm"),
    not(feature = "mimalloc"),
    not(feature = "heap-profile")
))]
pub fn trim() {
    imp::trim();
    adapt();
}

/// Ask for huge pages on the arena iff `BBREF_HUGEPAGES` says so, or, unset, iff free memory is
/// mostly unfragmented (`free_memory_unfragmented`).
#[cfg(all(
    not(target_family = "wasm"),
    not(feature = "mimalloc"),
    not(feature = "heap-profile")
))]
pub fn adapt() {
    let on = match std::env::var("BBREF_HUGEPAGES").as_deref() {
        Ok("0") => false,
        Ok("1") => true,
        _ => free_memory_unfragmented(),
    };
    imp::set_huge_pages(on);
}

/// Whether at least half of the free memory in `/proc/buddyinfo` sits in blocks of 2 MiB or more
/// (order 9 and up on 4 KiB pages), the ones a huge-page fault takes without compacting. An
/// unreadable file (not Linux) counts as fragmented.
#[cfg(all(
    not(target_family = "wasm"),
    not(feature = "mimalloc"),
    not(feature = "heap-profile")
))]
fn free_memory_unfragmented() -> bool {
    let Ok(info) = std::fs::read_to_string("/proc/buddyinfo") else {
        return false;
    };
    let (mut free, mut huge) = (0u64, 0u64);
    for line in info.lines() {
        // "Node 0, zone   Normal  <free blocks of order 0> <order 1> ..."
        for (order, count) in line.split_whitespace().skip(4).enumerate() {
            let pages = count.parse::<u64>().unwrap_or(0) << order;
            free += pages;
            if order >= 9 {
                huge += pages;
            }
        }
    }
    free > 0 && 2 * huge >= free
}

/// No arena under the other allocators.
#[cfg(not(all(
    not(target_family = "wasm"),
    not(feature = "mimalloc"),
    not(feature = "heap-profile")
)))]
pub fn trim() {}

#[cfg(not(all(
    not(target_family = "wasm"),
    not(feature = "mimalloc"),
    not(feature = "heap-profile")
)))]
pub fn adapt() {}
