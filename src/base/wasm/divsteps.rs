//! The divstep kernel of the Bernstein–Yang safegcd inverse, shared by the x86-64 (`adx.rs`, 62 per
//! matrix) and wasm (`by29.rs`, 58 per matrix) inverses: bb's `bernstein_yang_inverse.hpp` with
//! golf 0007's batched variable-time divsteps.

/// `B` divsteps on the low bits of (f, g): the matrix [u v; q r] (scaled by 2^B), δ updated.
/// Runs of even g are taken at once (count trailing zeros), and consecutive g ← (g + f)/2
/// steps collapse into g ← g + w·f with w = −g/f mod 2^4 (2^6 right after a swap).
pub fn divsteps<const B: u32>(delta: &mut i64, mut f: u64, mut g: u64) -> [i64; 4] {
    let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
    let (mut eta, mut i) = (-*delta, B);
    loop {
        // The sentinel bit at i caps the run at the divsteps left.
        let zeros = (g | (!0u64 << i)).trailing_zeros();
        (g, u, v) = (g >> zeros, u << zeros, v << zeros);
        eta -= zeros as i64;
        i -= zeros;
        if i == 0 {
            break;
        }
        let limit = (eta.unsigned_abs() + 1).min(i as u64) as u32;
        let w = if eta < 0 {
            // δ > 0: (f, g) ← (g, −f), (u, v, q, r) ← (q, r, −u, −v).
            eta = -eta;
            (f, g) = (g, f.wrapping_neg());
            (u, q) = (q, u.wrapping_neg());
            (v, r) = (r, v.wrapping_neg());
            f.wrapping_mul(g).wrapping_mul(f.wrapping_mul(f).wrapping_sub(2)) & (!0u64 >> (64 - limit)) & 63
        } else {
            let w = f.wrapping_add((f.wrapping_add(1) & 4) << 1);
            w.wrapping_mul(g).wrapping_neg() & (!0u64 >> (64 - limit)) & 15
        };
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
    }
    *delta = -eta;
    [u as i64, v as i64, q as i64, r as i64]
}
