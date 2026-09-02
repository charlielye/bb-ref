//! Opt-in phase timer: with `BBREF_TIMING=1`, `phase(label)` prints the time since the previous
//! phase mark; with `BBREF_TIMING_RSS=1` also the process RSS at the mark, for attributing peak
//! memory to a phase.

use std::cell::Cell;
use std::time::Instant;

thread_local! {
    static LAST: Cell<Option<Instant>> = const { Cell::new(None) };
}

fn rss_gb() -> Option<f64> {
    if std::env::var_os("BBREF_TIMING_RSS").is_none() {
        return None;
    }
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: f64 = status
        .lines()
        .find(|l| l.starts_with("VmRSS"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb / 1048576.0)
}

pub fn phase(label: &str) {
    if std::env::var_os("BBREF_TIMING").is_none() {
        return;
    }
    let now = Instant::now();
    let rss = rss_gb().map(|g| format!("  rss={g:.2}GB")).unwrap_or_default();
    LAST.with(|last| {
        if let Some(prev) = last.get() {
            eprintln!("[timing] {label}: {:.2}s{rss}", (now - prev).as_secs_f64());
        } else {
            eprintln!("[timing] {label}{rss}");
        }
        last.set(Some(now));
    });
}
