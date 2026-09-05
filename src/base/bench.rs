//! Hierarchical scope timer matched to bb's `BB_BENCH` (`common/bb_bench.hpp`), so a bb-ref phase
//! table can be diffed line-for-line against bb's `--print_bench` output.
//!
//! Like bb: scopes nest via a thread-local parent pointer, each thread accumulates into its own
//! slot to avoid contention, and results are aggregated over `(name, parent)` pairs. `time` is the
//! summed wall time across threads (so a parallel scope can exceed the wall clock, exactly as in
//! bb's table), `threads` is how many distinct threads entered the scope.
//!
//! Enable with `BBREF_BENCH=1`, then call [`print`] at the end of the run. Disabled builds pay one
//! relaxed atomic load per scope.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static ENABLED: OnceLock<bool> = OnceLock::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether scope timing is on. Reads the env var once, then is a relaxed atomic load.
#[inline]
pub fn enabled() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Turn timing on if `BBREF_BENCH=1`. Idempotent; call once at startup.
pub fn init() {
    let on = *ENABLED.get_or_init(|| std::env::var("BBREF_BENCH").map(|v| v == "1").unwrap_or(false));
    ACTIVE.store(on, Ordering::Relaxed);
}

#[derive(Default, Clone, Copy)]
struct Acc {
    time_ns: u64,
    count: u64,
}

/// Accumulated totals keyed by `(scope, parent, thread)`; parent is `""` at top level. bb keeps
/// one entry per thread for the same reason: its reported `time` is the per-thread maximum, not
/// the cross-thread sum, so the per-thread split has to survive aggregation.
type Table = HashMap<(&'static str, &'static str, u64), Acc>;

static TABLE: OnceLock<Mutex<Table>> = OnceLock::new();

fn table() -> &'static Mutex<Table> {
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn thread_key() -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    h.finish()
}

thread_local! {
    /// Innermost enclosing scope name on this thread, mirroring bb's `thread_local parent`.
    static PARENT: Cell<&'static str> = const { Cell::new("") };
    /// Per-thread accumulation, flushed to the global table when the thread's outermost scope exits.
    static LOCAL: std::cell::RefCell<HashMap<(&'static str, &'static str), Acc>> =
        std::cell::RefCell::new(HashMap::new());
}

/// RAII scope guard. Prefer the [`scope!`](crate::scope) macro.
pub struct Scope {
    name: &'static str,
    parent: &'static str,
    start: Instant,
}

impl Scope {
    #[inline]
    pub fn new(name: &'static str) -> Option<Self> {
        if !enabled() {
            return None;
        }
        let parent = PARENT.with(|p| p.replace(name));
        Some(Scope {
            name,
            parent,
            start: Instant::now(),
        })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let dur = self.start.elapsed().as_nanos() as u64;
        PARENT.with(|p| p.set(self.parent));
        LOCAL.with(|l| {
            let mut l = l.borrow_mut();
            let e = l.entry((self.name, self.parent)).or_default();
            e.time_ns += dur;
            e.count += 1;
            // Outermost scope on this thread: publish and reset, so worker threads that exit
            // before printing still contribute (bb keeps per-thread entries alive for the same
            // reason).
            if self.parent.is_empty() {
                let tid = thread_key();
                let mut g = table().lock().unwrap();
                for ((name, parent), v) in l.drain() {
                    let slot = g.entry((name, parent, tid)).or_default();
                    slot.time_ns += v.time_ns;
                    slot.count += v.count;
                }
            }
        });
    }
}

/// Time the enclosing block as a named scope, nested under whatever scope is already open on
/// this thread. Matches bb's `BB_BENCH_NAME("...")`.
#[macro_export]
macro_rules! scope {
    ($name:expr) => {
        let _bbref_scope = $crate::base::bench::Scope::new($name);
    };
}

/// Flush any scopes still buffered on the calling thread into the global table.
pub fn flush_thread() {
    if !enabled() {
        return;
    }
    LOCAL.with(|l| {
        let mut l = l.borrow_mut();
        if l.is_empty() {
            return;
        }
        let tid = thread_key();
        let mut g = table().lock().unwrap();
        for ((name, parent), v) in l.drain() {
            let slot = g.entry((name, parent, tid)).or_default();
            slot.time_ns += v.time_ns;
            slot.count += v.count;
        }
    });
}

/// Print the aggregate table as an indented tree, in the same shape as bb's
/// `print_aggregate_counts_hierarchical`: each line is `name  time  count  threads`, children
/// nested under their parent and ordered by descending time.
pub fn print() {
    if !enabled() {
        return;
    }
    flush_thread();
    let g = table().lock().unwrap();

    // Per-(scope, parent), collapse the per-thread entries two ways: `max` is the largest single
    // thread's total, which is what bb's aggregate reports as `time`; `sum` is the true
    // cross-thread total. Comparing our table against bb's requires the former; judging how much
    // CPU a phase burns requires the latter.
    let mut edge: HashMap<(&'static str, &'static str), (u64, u64, u64, usize)> = HashMap::new();
    for (&(name, parent, _tid), acc) in g.iter() {
        let e = edge.entry((name, parent)).or_insert((0, 0, 0, 0));
        e.0 = e.0.max(acc.time_ns);
        e.1 += acc.time_ns;
        e.2 += acc.count;
        e.3 += 1;
    }

    // Flat: one row per scope, over every parent.
    let mut flat: HashMap<&'static str, (u64, u64, u64, usize)> = HashMap::new();
    for (&(name, _parent), &(mx, sum, count, threads)) in edge.iter() {
        let e = flat.entry(name).or_insert((0, 0, 0, 0));
        e.0 += mx;
        e.1 += sum;
        e.2 += count;
        e.3 = e.3.max(threads);
    }
    let mut flat: Vec<_> = flat.into_iter().collect();
    flat.sort_by_key(|(_, v)| std::cmp::Reverse(v.0));
    eprintln!(
        "{:<52}{:>11}{:>11}{:>10}{:>9}",
        "scope (flat)", "time_max", "time_sum", "count", "threads"
    );
    for (name, (mx, sum, count, threads)) in &flat {
        eprintln!(
            "{:<52}{:>10.3}s{:>10.3}s{:>10}{:>9}",
            name,
            *mx as f64 / 1e9,
            *sum as f64 / 1e9,
            count,
            threads
        );
    }

    let mut children: HashMap<&'static str, Vec<(&'static str, u64, u64, u64, usize)>> = HashMap::new();
    for (&(name, parent), &(mx, sum, count, threads)) in edge.iter() {
        children.entry(parent).or_default().push((name, mx, sum, count, threads));
    }
    for v in children.values_mut() {
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
    }
    eprintln!();
    eprintln!(
        "{:<52}{:>11}{:>11}{:>10}{:>9}",
        "scope", "time_max", "time_sum", "count", "threads"
    );
    fn walk(
        parent: &'static str,
        depth: usize,
        children: &HashMap<&'static str, Vec<(&'static str, u64, u64, u64, usize)>>,
        ancestors: &mut Vec<&'static str>,
    ) {
        let Some(kids) = children.get(parent) else { return };
        for &(name, mx, sum, count, threads) in kids {
            // The same scope can appear under several parents, so these edges form a graph rather
            // than a tree; descending into a name already on the current path would not terminate.
            if ancestors.contains(&name) {
                continue;
            }
            eprintln!(
                "{:<52}{:>10.3}s{:>10.3}s{:>10}{:>9}",
                format!("{}{}", "  ".repeat(depth), name),
                mx as f64 / 1e9,
                sum as f64 / 1e9,
                count,
                threads
            );
            ancestors.push(name);
            walk(name, depth + 1, children, ancestors);
            ancestors.pop();
        }
    }
    walk("", 0, &children, &mut Vec::new());
}
