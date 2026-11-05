//! Debug instrumentation, compiled in by the `timing` feature only: [`on`] is constant false
//! without it, so every probe it guards folds away. In a timing build the env vars select output:
//! with `BBREF_TIMING=1`, `phase(label)` prints the time since the previous phase mark; with
//! `BBREF_TIMING_RSS=1` also the process RSS at the mark (on wasm the linear memory's size), for
//! attributing peak memory to a phase.

use std::cell::Cell;

/// The probes' clock: `std::time::Instant` in a `timing` build, else a zero-size stand-in that
/// reads zero, so a timed loop needs no second, untimed copy and its clock reads compile away.
#[cfg(feature = "timing")]
pub use std::time::Instant;
#[cfg(not(feature = "timing"))]
#[derive(Clone, Copy)]
pub struct Instant;
#[cfg(not(feature = "timing"))]
impl Instant {
    #[inline(always)]
    pub fn now() -> Self {
        Instant
    }
    #[inline(always)]
    pub fn elapsed(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}
#[cfg(not(feature = "timing"))]
impl std::ops::Sub for Instant {
    type Output = std::time::Duration;
    #[inline(always)]
    fn sub(self, _: Self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}

thread_local! {
    static LAST: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Whether the probe selected by env var `var` is on: a `timing` build with `var` set.
#[inline(always)]
pub fn on(var: &str) -> bool {
    cfg!(feature = "timing") && std::env::var_os(var).is_some()
}

fn rss_gb() -> Option<(f64, f64)> {
    if !on("BBREF_TIMING_RSS") {
        return None;
    }
    // wasm: linear memory's size, which only grows, so it is both the current figure and the peak.
    #[cfg(target_family = "wasm")]
    {
        let gb = (core::arch::wasm32::memory_size(0) << 16) as f64 / (1u64 << 30) as f64;
        return Some((gb, gb));
    }
    #[allow(unreachable_code)]
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let field = |tag: &str| -> Option<f64> {
        let kb: f64 = status
            .lines()
            .find(|l| l.starts_with(tag))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb / 1048576.0)
    };
    Some((field("VmRSS")?, field("VmHWM")?))
}

#[inline(always)]
pub fn phase(label: &str) {
    if !on("BBREF_TIMING") {
        return;
    }
    let now = Instant::now();
    let rss = rss_gb()
        .map(|(r, h)| format!("  rss={r:.2}GB hwm={h:.2}GB"))
        .unwrap_or_default();
    LAST.with(|last| {
        if let Some(prev) = last.get() {
            eprintln!("[timing] {label}: {:.2}s{rss}", (now - prev).as_secs_f64());
        } else {
            eprintln!("[timing] {label}{rss}");
        }
        last.set(Some(now));
    });
}
