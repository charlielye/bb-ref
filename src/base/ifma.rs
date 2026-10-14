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

// Off x86-64 the kernel calls compile out (`available` is false), leaving their inputs unused.
#![cfg_attr(not(target_arch = "x86_64"), allow(unused))]

use crate::base::field::NativeField;
use crate::base::{Fq, Fr};
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
    /// `available::<F>()`, canonical inputs and `ax[k] != bx[k]`; with `double`, every pair is
    /// `(a, a)` with `ay[k] != 0` and the tangent is used.
    pub fn run(&mut self, double: bool) {
        let n = self.ax.len();
        if n == 0 {
            return;
        }
        // Padding pairs (0, 1) + (1, 1) have dx = 1 (dy = 2 doubled): nonzero denominators.
        while self.ax.len() % 8 != 0 {
            self.push(F::ZERO, F::ONE, F::ONE, F::ONE);
        }
        assert!(available::<F>());
        #[cfg(target_arch = "x86_64")]
        unsafe {
            add_kernel(&mut self.ax, &mut self.ay, &self.bx, &self.by, &mut self.chain, double)
        };
        self.ax.truncate(n);
        self.ay.truncate(n);
        self.bx.truncate(n);
        self.by.truncate(n);
    }
}

/// `Some(true)` for bn254 Fr, `Some(false)` for Fq, when `F` is one of them and the kernels serve
/// it; the hooks below then reinterpret `F` as that type.
fn bn254<F: 'static>() -> Option<bool> {
    use core::any::TypeId;
    let (fr, fq) = (TypeId::of::<F>() == TypeId::of::<Fr>(), TypeId::of::<F>() == TypeId::of::<Fq>());
    (fr && available::<Fr>() || fq && available::<Fq>()).then_some(fr)
}

macro_rules! on_bn254 {
    ($F:ty, |$G:ident| $body:expr) => {
        match bn254::<$F>() {
            Some(true) => {
                type $G = Fr;
                $body
            }
            Some(false) => {
                type $G = Fq;
                $body
            }
            None => return Default::default(),
        }
    };
}

/// In-place sumcheck fold `v[k] = v[2k] + u·(v[2k + 1] − v[2k])`, halving `v`; false if `F` has no
/// kernel here.
pub fn try_fold_halve<F: 'static>(v: &mut Vec<F>, u: &F) -> bool {
    on_bn254!(F, |G| fold_halve::<G>(unsafe { &mut *(v as *mut Vec<F> as *mut Vec<G>) }, unsafe {
        &*(u as *const F as *const G)
    }));
    true
}

/// The fold of `src` zero-extended to `len`, as a new vector; None if `F` has no kernel here.
pub fn try_fold_from<F: 'static>(src: &[F], len: usize, u: &F) -> Option<Vec<F>> {
    on_bn254!(F, |G| {
        let out = fold_from::<G>(unsafe { &*(src as *const [F] as *const [G]) }, len, unsafe {
            &*(u as *const F as *const G)
        });
        Some(unsafe { core::mem::transmute::<Vec<G>, Vec<F>>(out) })
    })
}

/// The fold of `src` (even length) into `dst` (half its length); false if `F` has no kernel here.
pub fn try_fold_into<F: 'static>(src: &[F], dst: &mut [core::mem::MaybeUninit<F>], u: &F) -> bool {
    assert_eq!(src.len(), 2 * dst.len());
    on_bn254!(F, |G| {
        let (src, u) = unsafe { (&*(src as *const [F] as *const [G]), &*(u as *const F as *const G)) };
        let blocks = src.len() / 16;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            fold_kernel(src.as_ptr(), dst.as_mut_ptr().cast::<G>(), blocks, u)
        };
        for k in 8 * blocks..dst.len() {
            let (a, b) = (src[2 * k], src[2 * k + 1]);
            dst[k].write(unsafe { core::mem::transmute_copy::<G, F>(&(a + *u * (b - a))) });
        }
    });
    true
}

/// `dst[i] += Σ s·src[i]` over `terms` (sources shorter than `dst` are zero-extended); false if
/// `F` has no kernel here.
pub fn try_axpy_batch<F: 'static>(dst: &mut [F], terms: &[(&[F], F)]) -> bool {
    on_bn254!(F, |G| axpy_batch::<G>(unsafe { &mut *(dst as *mut [F] as *mut [G]) }, unsafe {
        &*(terms as *const [(&[F], F)] as *const [(&[G], G)])
    }));
    true
}

fn fold_halve<G: NativeField>(v: &mut Vec<G>, u: &G) {
    let (len, half) = (v.len(), v.len().div_ceil(2));
    let blocks = len / 16;
    let p = v.as_mut_ptr();
    #[cfg(target_arch = "x86_64")]
    unsafe {
        fold_kernel(p, p, blocks, u)
    };
    for k in 8 * blocks..half {
        let a = v[2 * k];
        let b = if 2 * k + 1 < len { v[2 * k + 1] } else { G::ZERO };
        v[k] = if a == b { a } else { a + *u * (b - a) };
    }
    v.truncate(half);
}

fn fold_from<G: NativeField>(src: &[G], len: usize, u: &G) -> Vec<G> {
    let n = len.min(src.len());
    let blocks = n / 16;
    let mut out = Vec::with_capacity(len.div_ceil(2));
    #[cfg(target_arch = "x86_64")]
    unsafe {
        fold_kernel(src.as_ptr(), out.as_mut_ptr(), blocks, u);
        out.set_len(8 * blocks);
    }
    let at = |i: usize| if i < n { src[i] } else { G::ZERO };
    out.extend((8 * blocks..len.div_ceil(2)).map(|k| {
        let (a, b) = (at(2 * k), at(2 * k + 1));
        if a == b { a } else { a + *u * (b - a) }
    }));
    out
}

fn axpy_batch<G: NativeField>(dst: &mut [G], terms: &[(&[G], G)]) {
    let blocks = dst.len() / 8;
    for t in (0..blocks).step_by(32) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            axpy_tile(dst.as_mut_ptr().add(8 * t), (blocks - t).min(32), terms, 8 * t)
        };
    }
    for (src, s) in terms {
        for i in 8 * blocks..dst.len().min(src.len()) {
            dst[i] += *s * src[i];
        }
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

    /// Four registers of two ark 4×64 elements each (eight elements, in order), transposed to
    /// limb-major lanes and re-limbed to 52 bits.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn from_rows(x0: __m512i, x1: __m512i, x2: __m512i, x3: __m512i) -> V5 {
        let (u0, u1) = mix(x0, x1, A, B);
        let (u2, u3) = mix(x2, x3, A, B);
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

    /// The eight elements at `p` (ark 4×64 limbs), as lanes.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) unsafe fn load8<F>(p: *const F) -> V5 {
        debug_assert!(size_of::<F>() == 32);
        let p = p as *const __m512i;
        from_rows(_mm512_loadu_si512(p), _mm512_loadu_si512(p.add(1)), _mm512_loadu_si512(p.add(2)), _mm512_loadu_si512(p.add(3)))
    }

    /// The even- and odd-indexed elements of the sixteen at `p`, as lanes.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) unsafe fn load8_pairs<F>(p: *const F) -> (V5, V5) {
        let p = p as *const __m512i;
        let mut z = [_mm512_setzero_si512(); 8];
        for i in 0..8 {
            z[i] = _mm512_loadu_si512(p.add(i));
        }
        // z[i] holds elements 2i and 2i + 1; regroup the 256-bit halves.
        let even = from_rows(
            _mm512_shuffle_i64x2::<0x44>(z[0], z[1]),
            _mm512_shuffle_i64x2::<0x44>(z[2], z[3]),
            _mm512_shuffle_i64x2::<0x44>(z[4], z[5]),
            _mm512_shuffle_i64x2::<0x44>(z[6], z[7]),
        );
        let odd = from_rows(
            _mm512_shuffle_i64x2::<0xee>(z[0], z[1]),
            _mm512_shuffle_i64x2::<0xee>(z[2], z[3]),
            _mm512_shuffle_i64x2::<0xee>(z[4], z[5]),
            _mm512_shuffle_i64x2::<0xee>(z[6], z[7]),
        );
        (even, odd)
    }

    /// Inverse of `load8` for values below 2^256.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) unsafe fn store8<F>(p: *mut F, v: &V5) {
        let a0 = _mm512_or_si512(v[0], _mm512_slli_epi64::<52>(v[1]));
        let a1 = _mm512_or_si512(_mm512_srli_epi64::<12>(v[1]), _mm512_slli_epi64::<40>(v[2]));
        let a2 = _mm512_or_si512(_mm512_srli_epi64::<24>(v[2]), _mm512_slli_epi64::<28>(v[3]));
        let a3 = _mm512_or_si512(_mm512_srli_epi64::<36>(v[3]), _mm512_slli_epi64::<16>(v[4]));
        let (u0, u2) = mix(a0, a1, C, D);
        let (u1, u3) = mix(a2, a3, C, D);
        let p = p as *mut __m512i;
        let (x0, x1) = mix(u0, u1, A, B);
        let (x2, x3) = mix(u2, u3, A, B);
        _mm512_storeu_si512(p, x0);
        _mm512_storeu_si512(p.add(1), x1);
        _mm512_storeu_si512(p.add(2), x2);
        _mm512_storeu_si512(p.add(3), x3);
    }

    /// a + b, normalised.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn add(a: &V5, b: &V5) -> V5 {
        let mut r = *a;
        for i in 0..5 {
            r[i] = _mm512_add_epi64(a[i], b[i]);
        }
        normalise(r)
    }

    /// Whether every lane of a equals b's (bit-identical limbs).
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn same(a: &V5, b: &V5) -> bool {
        let mut d = _mm512_setzero_si512();
        for i in 0..5 {
            d = _mm512_or_si512(d, _mm512_xor_si512(a[i], b[i]));
        }
        _mm512_test_epi64_mask(d, d) == 0
    }

    /// dst[k] = src[2k] + u·(src[2k + 1] − src[2k]) for k < 8·blocks (golf 0061); dst may alias
    /// src, as each block reads its sixteen inputs before writing. A block of eight bit-identical
    /// pairs is copied (golf 0053). Bounds: (odd − even + 2p)·u + even < 2.6p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn fold_kernel<F: NativeField>(src: *const F, dst: *mut F, blocks: usize, u: &F) {
        let c = &const { Consts::new(F::MODULUS.0) };
        let uv = load8([*u; 8].as_ptr());
        for g in 0..blocks {
            let (even, odd) = load8_pairs(src.add(16 * g));
            let r = if same(&even, &odd) {
                even
            } else {
                canonical(c, &add(&mont_mul(c, &sub_plus(&odd, &even, None, &c.p2), &uv), &even))
            };
            store8(dst.add(8 * g), &r);
        }
    }

    /// dst[i] += Σ s·src[i] over `terms` for i < 8·blocks (golf 0062): the tile stays in 52-bit
    /// lanes across all terms, all-zero source blocks are skipped, unit scalars add without a
    /// multiply, and the tail of a source shorter than the tile is read with masked loads. Each
    /// block is reduced after every sixth term (p + 6·1.19p < 9p).
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn axpy_tile<F: NativeField>(dst: *mut F, blocks: usize, terms: &[(&[F], F)], at: usize) {
        const TILE: usize = 32;
        debug_assert!(blocks <= TILE);
        let c = &const { Consts::new(F::MODULUS.0) };
        let mut acc = [[_mm512_setzero_si512(); 5]; TILE];
        let mut count = [0u8; TILE];
        for b in 0..blocks {
            acc[b] = load8(dst.add(8 * b));
        }
        for (src, s) in terms {
            let src = &src[at.min(src.len())..];
            let unit = *s == F::ONE;
            let sv = load8([*s; 8].as_ptr());
            for b in 0..blocks.min(src.len().div_ceil(8)) {
                let live = (src.len() - 8 * b).min(8);
                let p = src.as_ptr().add(8 * b) as *const i64;
                let mut z = [_mm512_setzero_si512(); 4];
                let mut any = _mm512_setzero_si512();
                for j in 0..4 {
                    // Words of elements 2j and 2j + 1 that lie inside the source.
                    let words = (if 2 * j < live { 0x0f } else { 0 }) | (if 2 * j + 1 < live { 0xf0 } else { 0 });
                    z[j] = _mm512_maskz_loadu_epi64(words, p.add(8 * j));
                    any = _mm512_or_si512(any, z[j]);
                }
                if _mm512_test_epi64_mask(any, any) == 0 {
                    continue;
                }
                let mut v = from_rows(z[0], z[1], z[2], z[3]);
                if !unit {
                    v = mont_mul(c, &v, &sv);
                }
                acc[b] = add(&acc[b], &v);
                count[b] += 1;
                if count[b] == 6 {
                    acc[b] = canonical(c, &acc[b]);
                    count[b] = 0;
                }
            }
        }
        for b in 0..blocks {
            store8(dst.add(8 * b), &canonical(c, &acc[b]));
        }
    }

    /// (ax, ay)[k] ← (ax, ay)[k] + (bx, by)[k] over a multiple of 8 pairs with one field inversion
    /// (golf's `drain_vector`): pair k runs in lane k % 8 of eight Montgomery prefix chains, the
    /// eight chain products are inverted together on the scalar side, and the backward pass peels
    /// off each 1/dx and finishes the addition; `double` takes the tangent (dx = 2y, dy = 3x²).
    /// Bounds (units of p): dx < 3, dy < 3.6, prefixes ~4.1, slope ~4.2, slope² ~4.3, x3 before
    /// reduction < 8.3, y3 < 5.4.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn add_kernel<F: NativeField>(
        ax: &mut [F],
        ay: &mut [F],
        bx: &[F],
        by: &[F],
        chain: &mut Vec<[V5; 2]>,
        double: bool,
    ) {
        let c = &const { Consts::new(F::MODULUS.0) };
        let groups = ax.len() / 8;
        chain.clear();
        let mut lanes = [F::one(); 8];
        let mut acc = load8(lanes.as_ptr());
        for g in 0..groups {
            let dx = if double {
                let y = load8(&ay[8 * g]);
                add(&y, &y)
            } else {
                sub_plus(&load8(&bx[8 * g]), &load8(&ax[8 * g]), None, &c.p2)
            };
            chain.push([dx, acc]);
            acc = mont_mul(c, &acc, &dx);
        }
        store8(lanes.as_mut_ptr(), &canonical(c, &acc));
        crate::base::msm::batch_invert_nonzero(&mut lanes, &mut Vec::with_capacity(8));
        acc = load8(lanes.as_ptr());
        for g in (0..groups).rev() {
            let [dx, pre] = chain[g];
            let inv = mont_mul(c, &acc, &pre);
            acc = mont_mul(c, &acc, &dx);
            let (x1, y1, x2) = (load8(&ax[8 * g]), load8(&ay[8 * g]), load8(&bx[8 * g]));
            let dy = if double {
                let xx = mont_mul(c, &x1, &x1);
                add(&add(&xx, &xx), &xx)
            } else {
                sub_plus(&load8(&by[8 * g]), &y1, None, &c.p2)
            };
            let slope = mont_mul(c, &dy, &inv);
            let x3 = canonical(c, &sub_plus(&mont_mul(c, &slope, &slope), &x1, Some(&x2), &c.p4));
            let y3 = mont_mul(c, &slope, &sub_plus(&x1, &x3, None, &c.p));
            store8(&mut ay[8 * g], &canonical(c, &sub_plus(&y3, &y1, None, &c.p2)));
            store8(&mut ax[8 * g], &x3);
        }
    }

    /// The sumcheck permutation identity on eight edges (`super::PermLanes`). Bounds, in units of
    /// p for canonical inputs: a factor `w + γ + β·x` is below 3.19p and its slope below 2.19p; its
    /// points are reduced at X = 2 and 4, so none exceeds 5.38p; a pair product is below 6.5p and
    /// reduced; the four-factor products are below 1.19p, z at X ≤ 5 below 6p, so z·num − z'·den
    /// stays below 6.36p with 4p added, and the accumulator is reduced after every add.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn perm8(
        stage: &[[Fr; 8]; PERM_INPUTS],
        acc: &mut [V5; PERM_POINTS],
        beta: &V5,
        gamma: &V5,
    ) {
        let c = &const { Consts::new(<Fr as ark_ff::PrimeField>::MODULUS.0) };
        let at = |k: usize| load8(stage[k].as_ptr());
        let sc = at(PERM_INPUTS - 1);
        let points = |mut a: V5, mut da: V5, scaled: bool| -> [V5; PERM_POINTS] {
            if scaled {
                (a, da) = (mont_mul(c, &a, &sc), mont_mul(c, &da, &sc));
            }
            let mut t = [a; PERM_POINTS];
            for x in 1..PERM_POINTS {
                t[x] = add(&t[x - 1], &da);
                if x % 2 == 0 {
                    t[x] = canonical(c, &t[x]);
                }
            }
            t
        };
        let mut num = [[*gamma; PERM_POINTS]; 4];
        let mut den = num;
        for i in 0..4 {
            let (w0, dw) = (at(6 * i), at(6 * i + 1));
            let wg = add(&w0, gamma);
            let factor = |k: usize| (add(&wg, &mont_mul(c, &at(k), beta)), add(&dw, &mont_mul(c, &at(k + 1), beta)));
            let ((na, nd), (da, dd)) = (factor(6 * i + 2), factor(6 * i + 4));
            num[i] = points(na, nd, i == 0);
            den[i] = points(da, dd, i == 0);
        }
        let (z0, dz, s0, ds) = (at(24), at(25), at(26), at(27));
        let (mut z, mut s) = (z0, s0);
        for x in 0..PERM_POINTS {
            if x > 0 {
                z = add(&z, &dz);
                s = add(&s, &ds);
            }
            let pair = |f: &[[V5; PERM_POINTS]; 4], i: usize| canonical(c, &mont_mul(c, &f[i][x], &f[i + 1][x]));
            let n = mont_mul(c, &pair(&num, 0), &pair(&num, 2));
            let d = mont_mul(c, &pair(&den, 0), &pair(&den, 2));
            let t = sub_plus(&mont_mul(c, &z, &n), &mont_mul(c, &s, &d), None, &c.p4);
            acc[x] = canonical(c, &add(&acc[x], &t));
        }
    }
}
#[cfg(target_arch = "x86_64")]
use x86::{add_kernel, axpy_tile, fold_kernel, perm8};

/// Inputs per edge of the sumcheck's permutation lane kernel: for each wire `i`: `w₀, Δw, id₀,
/// Δid, σ₀, Δσ`; then `z₀, Δz, z_shift₀, Δz_shift` and the separator weight.
pub const PERM_INPUTS: usize = 29;
/// Points of the identity's univariate (degree 5).
pub const PERM_POINTS: usize = 6;

/// The sumcheck permutation identity on eight edges at once (the native counterpart of the wasm
/// `perm4.rs`, same contract): `push` stages an edge, `finish` returns the sum over the pushed
/// edges at the points `0..PERM_POINTS`.
#[cfg(target_arch = "x86_64")]
pub struct PermLanes {
    stage: [[Fr; 8]; PERM_INPUTS],
    lanes: usize,
    pushed: bool,
    acc: [V5; PERM_POINTS],
    beta: V5,
    gamma: V5,
}

#[cfg(target_arch = "x86_64")]
impl PermLanes {
    /// `None` unless `F` is bn254 Fr on an IFMA CPU.
    pub fn new<F: 'static>(beta: &F, gamma: &F) -> Option<Box<Self>> {
        if core::any::TypeId::of::<F>() != core::any::TypeId::of::<Fr>() || !available::<Fr>() {
            return None;
        }
        let as_fr = |v: &F| unsafe { core::mem::transmute_copy::<F, Fr>(v) };
        let (b, g) = (as_fr(beta), as_fr(gamma));
        unsafe {
            Some(Box::new(PermLanes {
                stage: [[<Fr as ark_ff::AdditiveGroup>::ZERO; 8]; PERM_INPUTS],
                lanes: 0,
                pushed: false,
                acc: [x86::load8([<Fr as ark_ff::AdditiveGroup>::ZERO; 8].as_ptr()); PERM_POINTS],
                beta: x86::load8([b; 8].as_ptr()),
                gamma: x86::load8([g; 8].as_ptr()),
            }))
        }
    }

    #[inline]
    pub fn push<F: 'static>(&mut self, v: &[F; PERM_INPUTS]) {
        for (k, x) in v.iter().enumerate() {
            self.stage[k][self.lanes] = unsafe { core::mem::transmute_copy::<F, Fr>(x) };
        }
        self.lanes += 1;
        self.pushed = true;
        if self.lanes == 8 {
            unsafe { perm8(&self.stage, &mut self.acc, &self.beta, &self.gamma) };
            self.lanes = 0;
        }
    }

    pub fn finish<F: 'static>(&mut self) -> Option<[F; PERM_POINTS]> {
        if !self.pushed {
            return None;
        }
        if self.lanes > 0 {
            // A zero weight zeroes both scaled factors, so the idle lanes contribute 0.
            self.stage[PERM_INPUTS - 1][self.lanes..].fill(<Fr as ark_ff::AdditiveGroup>::ZERO);
            unsafe { perm8(&self.stage, &mut self.acc, &self.beta, &self.gamma) };
            self.lanes = 0;
        }
        self.pushed = false;
        let out = core::array::from_fn(|x| {
            let mut lanes = [<Fr as ark_ff::AdditiveGroup>::ZERO; 8];
            unsafe { x86::store8(lanes.as_mut_ptr(), &self.acc[x]) };
            let t: Fr = lanes.iter().sum();
            unsafe { core::mem::transmute_copy::<Fr, F>(&t) }
        });
        self.acc = [unsafe { x86::load8([<Fr as ark_ff::AdditiveGroup>::ZERO; 8].as_ptr()) }; PERM_POINTS];
        Some(out)
    }
}

/// No lane kernel off x86-64 (simd128 wasm has its own): the sumcheck keeps its scalar body.
#[cfg(not(target_arch = "x86_64"))]
pub enum PermLanes {}

#[cfg(not(target_arch = "x86_64"))]
impl PermLanes {
    pub fn new<F: 'static>(_beta: &F, _gamma: &F) -> Option<Box<Self>> {
        None
    }
    pub fn push<F: 'static>(&mut self, _v: &[F; PERM_INPUTS]) {
        match *self {}
    }
    pub fn finish<F: 'static>(&mut self) -> Option<[F; PERM_POINTS]> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
    use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
    use ark_ff::UniformRand;

    /// golf 0038: random pairs, consecutive generator multiples, negated points (y near p) and
    /// P + (−2P), across partial lane groups and long chains, against ark's projective sum; and
    /// the doubling mode on the same points.
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
            q.run(false);
            for (k, (a, b)) in pairs.iter().enumerate() {
                let sum = Affine::<P>::new_unchecked(q.ax[k], q.ay[k]);
                assert_eq!(sum, (*a + *b).into_affine(), "n={n} k={k}");
            }
            q.clear();
            for (a, _) in &pairs {
                q.push(a.x, a.y, a.x, a.y);
            }
            q.run(true);
            for (k, (a, _)) in pairs.iter().enumerate() {
                let dbl = Affine::<P>::new_unchecked(q.ax[k], q.ay[k]);
                assert_eq!(dbl, a.into_group().double().into_affine(), "double n={n} k={k}");
            }
        }
    }

    /// Random values, edge values (0, 1, p − 1) and runs of identical neighbours.
    fn sample<F: NativeField>(n: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<F> {
        (0..n)
            .map(|i| match (i / 16) % 4 {
                0 => F::rand(rng),
                1 => [F::ZERO, F::ONE, -F::ONE][i % 3],
                2 => F::from((i / 2) as u64),
                _ => F::from(7u64),
            })
            .collect()
    }

    fn folds_and_axpy_match<F: NativeField>() {
        if !available::<F>() {
            eprintln!("no AVX-512 IFMA: skipped");
            return;
        }
        let mut rng = ark_std::test_rng();
        let u = F::rand(&mut rng);
        let fold = |v: &[F], len: usize| -> Vec<F> {
            let at = |i: usize| if i < v.len().min(len) { v[i] } else { F::ZERO };
            (0..len.div_ceil(2)).map(|k| at(2 * k) + u * (at(2 * k + 1) - at(2 * k))).collect()
        };
        for n in [0usize, 1, 15, 16, 17, 33, 255, 256, 1000, 4099] {
            let v = sample::<F>(n, &mut rng);
            let mut w = v.clone();
            assert!(try_fold_halve(&mut w, &u));
            assert_eq!(w, fold(&v, n), "halve n={n}");
            assert_eq!(try_fold_from(&v, n, &u).unwrap(), fold(&v, n), "from n={n}");
            assert_eq!(try_fold_from(&v, n + 37, &u).unwrap(), fold(&v, n + 37), "from n={n}+37");
            let mut into = Vec::with_capacity(n / 2);
            assert!(try_fold_into(&v[..n / 2 * 2], &mut into.spare_capacity_mut()[..n / 2], &u));
            unsafe { into.set_len(n / 2) };
            assert_eq!(into, fold(&v, n / 2 * 2), "into n={n}");
            // Thirteen terms: unit and random scalars, zero stretches, sources shorter and longer.
            let srcs: Vec<Vec<F>> = (0..13).map(|t| sample::<F>((n * (t + 3)) / 8 + t, &mut rng)).collect();
            let terms: Vec<(&[F], F)> =
                srcs.iter().enumerate().map(|(t, s)| (&s[..], if t % 4 == 0 { F::ONE } else { F::rand(&mut rng) })).collect();
            let mut dst = sample::<F>(n, &mut rng);
            let mut expect = dst.clone();
            for (s, x) in &terms {
                for i in 0..n.min(s.len()) {
                    expect[i] += *x * s[i];
                }
            }
            assert!(try_axpy_batch(&mut dst, &terms));
            assert_eq!(dst, expect, "axpy n={n}");
        }
    }

    #[test]
    fn folds_and_axpy_fr() {
        folds_and_axpy_match::<crate::base::Fr>();
    }

    #[test]
    fn folds_and_axpy_fq() {
        folds_and_axpy_match::<crate::base::Fq>();
    }

    #[test]
    fn chords_bn254() {
        chords_match_ark::<crate::base::G1Config>();
    }

    #[test]
    fn chords_grumpkin() {
        chords_match_ark::<crate::base::GrumpkinConfig>();
    }

    /// The permutation lane kernel against the identity evaluated per edge, over partial lane
    /// groups and edge values (0, ±1, p − 1 at the extremes of the bound analysis).
    #[test]
    fn perm_lanes_match_scalar() {
        use crate::base::Fr;
        let mut rng = ark_std::test_rng();
        let (beta, gamma) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let Some(mut lanes) = PermLanes::new(&beta, &gamma) else {
            eprintln!("no AVX-512 IFMA: skipped");
            return;
        };
        for n in [1usize, 7, 8, 9, 16, 61] {
            let edges: Vec<[Fr; PERM_INPUTS]> = (0..n)
                .map(|e| core::array::from_fn(|k| sample::<Fr>(64, &mut rng)[(e * 7 + k * 13) % 64]))
                .collect();
            let mut expect = [Fr::ZERO; PERM_POINTS];
            for v in &edges {
                lanes.push(v);
                let at = |k: usize, x: u64| v[k] + Fr::from(x) * v[k + 1];
                for x in 0..PERM_POINTS as u64 {
                    let (mut num, mut den) = (v[28], v[28]);
                    for i in 0..4 {
                        num *= at(6 * i, x) + gamma + beta * at(6 * i + 2, x);
                        den *= at(6 * i, x) + gamma + beta * at(6 * i + 4, x);
                    }
                    expect[x as usize] += at(24, x) * num - at(26, x) * den;
                }
            }
            assert_eq!(lanes.finish::<Fr>(), Some(expect), "n={n}");
        }
    }
}
