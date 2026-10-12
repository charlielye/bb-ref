//! AVX-512 IFMA arithmetic for the bn254 fields (golf 0031): eight elements per vector, each as
//! five 52-bit limbs, multiplied in the Montgomery domain R = 2^256 — arkworks' stored form (and
//! bb's), so an element converts by re-slicing its four 64-bit limbs, with no domain change. Values
//! stay loosely reduced between operations; the bounds (in units of p) rely on p < 0.19·2^256, true
//! for both bn254 fields, for which mont_mul(a, b) < 0.19·a·b/p + p and every intermediate stays far
//! below the 2^260 five limbs hold. Results leave through `canonical`, so stored limbs are ark's.
//!
//! x86-64 only and runtime-dispatched: the build targets a baseline ISA, so every function touching
//! 512-bit registers carries `#[target_feature]` and runs only once [`available`] has confirmed the
//! CPU. `BBREF_NO_IFMA` forces the scalar paths (A/B on one binary). Elsewhere `available` is false.

use crate::base::field::NativeField;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Whether the kernels serve `F` here: an AVX-512 IFMA CPU and a modulus inside the bound analysis.
pub fn available<F: NativeField>() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        static CPU: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
            std::env::var_os("BBREF_NO_IFMA").is_none()
                && is_x86_feature_detected!("avx512f")
                && is_x86_feature_detected!("avx512ifma")
        });
        F::MODULUS.0[3] < 0x30a3_d70a_3d70_a3d7 && *CPU // 0.19·2^64
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

/// Affine chord additions `a + b` queued for one shared inversion (golf's `DrainBuffer`).
#[derive(Default)]
pub struct Chords<F> {
    pub ax: Vec<F>,
    pub ay: Vec<F>,
    bx: Vec<F>,
    by: Vec<F>,
    #[cfg(target_arch = "x86_64")]
    chain: Vec<[V5; 2]>,
}

impl<F: NativeField> Chords<F> {
    pub fn push(&mut self, ax: F, ay: F, bx: F, by: F) {
        self.ax.push(ax);
        self.ay.push(ay);
        self.bx.push(bx);
        self.by.push(by);
    }

    pub fn clear(&mut self) {
        self.ax.clear();
        self.ay.clear();
        self.bx.clear();
        self.by.clear();
    }

    /// Replace every queued `a` by `a + b`, so pair k's sum is `(ax[k], ay[k])`. Needs
    /// `available::<F>()`, canonical inputs and `ax[k] != bx[k]`.
    pub fn run(&mut self) {
        let n = self.ax.len();
        if n == 0 {
            return;
        }
        // Padding pairs (0, 0) + (1, 0) have dx = 1: the chain products are unchanged.
        while self.ax.len() % 8 != 0 {
            self.push(F::ZERO, F::ZERO, F::ONE, F::ZERO);
        }
        assert!(available::<F>());
        #[cfg(target_arch = "x86_64")]
        unsafe {
            add_kernel(&mut self.ax, &mut self.ay, &self.bx, &self.by, &mut self.chain)
        };
        self.ax.truncate(n);
        self.ay.truncate(n);
        self.bx.truncate(n);
        self.by.truncate(n);
    }
}

/// Eight field elements, lane-parallel, as five 52-bit limbs.
#[cfg(target_arch = "x86_64")]
pub(crate) type V5 = [__m512i; 5];

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;

    const M52: u64 = (1 << 52) - 1;

    /// Per-modulus constants: k·p for k = 1, 2, 4 as normalised 52-bit limbs, −p⁻¹ mod 2^52, and
    /// ⌊2^52 / (⌊p / 2^208⌋ + 1)⌋, `canonical`'s quotient estimate.
    pub(crate) struct Consts {
        p: [u64; 5],
        p2: [u64; 5],
        p4: [u64; 5],
        pinv: u64,
        qk: u64,
    }

    impl Consts {
        pub(crate) const fn new(m: [u64; 4]) -> Self {
            const fn times(m: &[u64; 4], k: u64) -> [u64; 5] {
                let p = [
                    m[0] & M52,
                    (m[0] >> 52 | m[1] << 12) & M52,
                    (m[1] >> 40 | m[2] << 24) & M52,
                    (m[2] >> 28 | m[3] << 36) & M52,
                    m[3] >> 16,
                ];
                let (mut r, mut carry, mut i) = ([0u64; 5], 0, 0);
                while i < 5 {
                    let v = p[i] * k + carry;
                    r[i] = if i < 4 { v & M52 } else { v };
                    carry = v >> 52;
                    i += 1;
                }
                r
            }
            let (mut inv, mut i) = (1u64, 0);
            while i < 6 {
                inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
                i += 1;
            }
            let p = times(&m, 1);
            Consts { p, p2: times(&m, 2), p4: times(&m, 4), pinv: inv.wrapping_neg() & M52, qk: (1 << 52) / (p[4] + 1) }
        }
    }

    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn splat(v: u64) -> __m512i {
        _mm512_set1_epi64(v as i64)
    }

    /// a·b / 2^256 mod p, loosely reduced (< 0.19·a·b/p + p). Limbs of a and b below 2^52.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn mont_mul(c: &Consts, a: &V5, b: &V5) -> V5 {
        let z = _mm512_setzero_si512();
        let mut t = [z; 10];
        for i in 0..5 {
            for j in 0..5 {
                t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[i], b[j]);
                t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[i], b[j]);
            }
        }
        // Four 52-bit steps clear t[i]'s low bits and carry it into t[i + 1]; a 48-bit fifth brings
        // the shift to 4·52 + 48 = 256.
        for i in 0..5 {
            let mut m = _mm512_madd52lo_epu64(z, t[i], splat(c.pinv));
            if i == 4 {
                m = _mm512_and_si512(m, splat((1 << 48) - 1));
            }
            for j in 0..5 {
                t[i + j] = _mm512_madd52lo_epu64(t[i + j], m, splat(c.p[j]));
                t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], m, splat(c.p[j]));
            }
            if i < 4 {
                t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64::<52>(t[i]));
            }
        }
        for i in 4..9 {
            t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64::<52>(t[i]));
            t[i] = _mm512_and_si512(t[i], splat(M52));
        }
        let mut r = [z; 5];
        for j in 0..4 {
            r[j] = _mm512_or_si512(
                _mm512_srli_epi64::<48>(t[4 + j]),
                _mm512_and_si512(_mm512_slli_epi64::<4>(t[5 + j]), splat(M52)),
            );
        }
        r[4] = _mm512_or_si512(_mm512_srli_epi64::<48>(t[8]), _mm512_slli_epi64::<4>(t[9]));
        r
    }

    /// Propagate signed limb carries so limbs 0..3 lie in [0, 2^52); the value must be non-negative.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn normalise(mut r: V5) -> V5 {
        for i in 0..4 {
            r[i + 1] = _mm512_add_epi64(r[i + 1], _mm512_srai_epi64::<52>(r[i]));
            r[i] = _mm512_and_si512(r[i], splat(M52));
        }
        r
    }

    /// a + k − b − c for k a constant multiple of p at least b + c.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn sub_plus(a: &V5, b: &V5, c: Option<&V5>, k: &[u64; 5]) -> V5 {
        let mut r = *a;
        for i in 0..5 {
            r[i] = _mm512_sub_epi64(_mm512_add_epi64(a[i], splat(k[i])), b[i]);
            if let Some(c) = c {
                r[i] = _mm512_sub_epi64(r[i], c[i]);
            }
        }
        normalise(r)
    }

    /// Fully reduce a normalised v < 9p into [0, p): q = ⌊v4·qk / 2^52⌋ (v4 = ⌊v / 2^208⌋) is at
    /// most ⌊v / p⌋ and short of it by at most one, so one conditional subtraction finishes.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn canonical(c: &Consts, v: &V5) -> V5 {
        let z = _mm512_setzero_si512();
        let q = _mm512_madd52hi_epu64(z, v[4], splat(c.qk));
        let (mut r, mut hi) = (*v, z);
        for i in 0..5 {
            let pi = splat(c.p[i]);
            r[i] = _mm512_sub_epi64(_mm512_sub_epi64(v[i], _mm512_madd52lo_epu64(z, q, pi)), hi);
            hi = _mm512_madd52hi_epu64(z, q, pi);
        }
        let r = normalise(r);
        let mut t = r;
        for i in 0..5 {
            t[i] = _mm512_sub_epi64(r[i], splat(c.p[i]));
        }
        let mut t = normalise(t);
        let neg = _mm512_cmplt_epi64_mask(t[4], z);
        for i in 0..5 {
            t[i] = _mm512_mask_blend_epi64(neg, t[i], r[i]);
        }
        t
    }

    /// Lane permutes for the 8×4 limb transpose: (a, b) ↦ (permute(a, i, b), permute(a, j, b)).
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn mix(a: __m512i, b: __m512i, i: [i64; 8], j: [i64; 8]) -> (__m512i, __m512i) {
        let i = _mm512_setr_epi64(i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7]);
        let j = _mm512_setr_epi64(j[0], j[1], j[2], j[3], j[4], j[5], j[6], j[7]);
        (_mm512_permutex2var_epi64(a, i, b), _mm512_permutex2var_epi64(a, j, b))
    }
    const A: [i64; 8] = [0, 4, 8, 12, 1, 5, 9, 13];
    const B: [i64; 8] = [2, 6, 10, 14, 3, 7, 11, 15];
    const C: [i64; 8] = [0, 1, 2, 3, 8, 9, 10, 11];
    const D: [i64; 8] = [4, 5, 6, 7, 12, 13, 14, 15];

    /// Elements 8g..8g + 8 of an ark 4×64 slice, transposed to limb-major lanes.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) unsafe fn load8<F>(s: &[F], g: usize) -> V5 {
        debug_assert!(size_of::<F>() == 32 && s.len() >= 8 * g + 8);
        let p = s.as_ptr().add(8 * g) as *const __m512i;
        let (u0, u1) = mix(_mm512_loadu_si512(p), _mm512_loadu_si512(p.add(1)), A, B);
        let (u2, u3) = mix(_mm512_loadu_si512(p.add(2)), _mm512_loadu_si512(p.add(3)), A, B);
        let (a0, a1) = mix(u0, u2, C, D);
        let (a2, a3) = mix(u1, u3, C, D);
        let m = splat(M52);
        [
            _mm512_and_si512(a0, m),
            _mm512_and_si512(_mm512_or_si512(_mm512_srli_epi64::<52>(a0), _mm512_slli_epi64::<12>(a1)), m),
            _mm512_and_si512(_mm512_or_si512(_mm512_srli_epi64::<40>(a1), _mm512_slli_epi64::<24>(a2)), m),
            _mm512_and_si512(_mm512_or_si512(_mm512_srli_epi64::<28>(a2), _mm512_slli_epi64::<36>(a3)), m),
            _mm512_srli_epi64::<16>(a3),
        ]
    }

    /// Inverse of `load8` for values below 2^256.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) unsafe fn store8<F>(s: &mut [F], g: usize, v: &V5) {
        debug_assert!(size_of::<F>() == 32 && s.len() >= 8 * g + 8);
        let a0 = _mm512_or_si512(v[0], _mm512_slli_epi64::<52>(v[1]));
        let a1 = _mm512_or_si512(_mm512_srli_epi64::<12>(v[1]), _mm512_slli_epi64::<40>(v[2]));
        let a2 = _mm512_or_si512(_mm512_srli_epi64::<24>(v[2]), _mm512_slli_epi64::<28>(v[3]));
        let a3 = _mm512_or_si512(_mm512_srli_epi64::<36>(v[3]), _mm512_slli_epi64::<16>(v[4]));
        let (u0, u2) = mix(a0, a1, C, D);
        let (u1, u3) = mix(a2, a3, C, D);
        let p = s.as_mut_ptr().add(8 * g) as *mut __m512i;
        let (x0, x1) = mix(u0, u1, A, B);
        let (x2, x3) = mix(u2, u3, A, B);
        _mm512_storeu_si512(p, x0);
        _mm512_storeu_si512(p.add(1), x1);
        _mm512_storeu_si512(p.add(2), x2);
        _mm512_storeu_si512(p.add(3), x3);
    }

    /// (ax, ay)[k] ← (ax, ay)[k] + (bx, by)[k] over a multiple of 8 pairs with one field inversion
    /// (golf's `drain_vector`): pair k runs in lane k % 8 of eight Montgomery prefix chains, the
    /// eight chain products are inverted together on the scalar side, and the backward pass peels
    /// off each 1/dx and finishes the addition. Bounds (units of p): dx < 3, prefixes ~4.1, slope
    /// ~4.2, slope² ~4.3, x3 before reduction < 8.3, y3 < 5.4.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn add_kernel<F: NativeField>(
        ax: &mut [F],
        ay: &mut [F],
        bx: &[F],
        by: &[F],
        chain: &mut Vec<[V5; 2]>,
    ) {
        let c = &const { Consts::new(F::MODULUS.0) };
        let groups = ax.len() / 8;
        chain.clear();
        let mut lanes = [F::one(); 8];
        let mut acc = load8(&lanes, 0);
        for g in 0..groups {
            let dx = sub_plus(&load8(bx, g), &load8(ax, g), None, &c.p2);
            chain.push([dx, acc]);
            acc = mont_mul(c, &acc, &dx);
        }
        store8(&mut lanes, 0, &canonical(c, &acc));
        crate::base::msm::batch_invert_nonzero(&mut lanes, &mut Vec::with_capacity(8));
        acc = load8(&lanes, 0);
        for g in (0..groups).rev() {
            let [dx, pre] = chain[g];
            let inv = mont_mul(c, &acc, &pre);
            acc = mont_mul(c, &acc, &dx);
            let (x1, y1, x2) = (load8(ax, g), load8(ay, g), load8(bx, g));
            let slope = mont_mul(c, &sub_plus(&load8(by, g), &y1, None, &c.p2), &inv);
            let x3 = canonical(c, &sub_plus(&mont_mul(c, &slope, &slope), &x1, Some(&x2), &c.p4));
            let y3 = mont_mul(c, &slope, &sub_plus(&x1, &x3, None, &c.p));
            store8(ay, g, &canonical(c, &sub_plus(&y3, &y1, None, &c.p2)));
            store8(ax, g, &x3);
        }
    }
}
#[cfg(target_arch = "x86_64")]
use x86::add_kernel;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
    use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
    use ark_ff::UniformRand;

    /// golf 0038: random pairs, consecutive generator multiples, negated points (y near p) and
    /// P + (−2P), across partial lane groups and long chains, against ark's projective sum.
    fn chords_match_ark<P: SWCurveConfig>()
    where
        P::BaseField: NativeField,
    {
        if !available::<P::BaseField>() {
            eprintln!("no AVX-512 IFMA: skipped");
            return;
        }
        let mut rng = ark_std::test_rng();
        let g = Affine::<P>::generator();
        let mut rand = || Projective::<P>::rand(&mut rng).into_affine();
        let mut q = Chords::<P::BaseField>::default();
        for n in [1usize, 6, 7, 8, 9, 31, 64, 129, 256, 1000] {
            let mut acc = g.into_group().double(); // (k + 2)·G: no doubling, no cancellation
            let pairs: Vec<(Affine<P>, Affine<P>)> = (0..n)
                .map(|k| {
                    let p = acc.into_affine();
                    acc += g;
                    match k % 5 {
                        0 => (p, g),
                        1 => (-p, g),
                        2 => (p, (-p.into_group().double()).into_affine()),
                        3 => (p, rand()),
                        _ => (rand(), rand()),
                    }
                })
                .collect();
            q.clear();
            for (a, b) in &pairs {
                q.push(a.x, a.y, b.x, b.y);
            }
            q.run();
            for (k, (a, b)) in pairs.iter().enumerate() {
                let sum = Affine::<P>::new_unchecked(q.ax[k], q.ay[k]);
                assert_eq!(sum, (*a + *b).into_affine(), "n={n} k={k}");
            }
        }
    }

    #[test]
    fn chords_bn254() {
        chords_match_ark::<crate::base::G1Config>();
    }

    #[test]
    fn chords_grumpkin() {
        chords_match_ark::<crate::base::GrumpkinConfig>();
    }
}
