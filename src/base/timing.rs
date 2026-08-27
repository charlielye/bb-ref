//! Opt-in phase timer: with `BBREF_TIMING=1`, `phase(label)` prints the time since the previous
//! phase mark.

use std::cell::Cell;
use std::time::Instant;

thread_local! {
    static LAST: Cell<Option<Instant>> = const { Cell::new(None) };
}

pub fn phase(label: &str) {
    if std::env::var_os("BBREF_TIMING").is_none() {
        return;
    }
    let now = Instant::now();
    LAST.with(|last| {
        if let Some(prev) = last.get() {
            eprintln!("[timing] {label}: {:.2}s", (now - prev).as_secs_f64());
        } else {
            eprintln!("[timing] {label}");
        }
        last.set(Some(now));
    });
}
