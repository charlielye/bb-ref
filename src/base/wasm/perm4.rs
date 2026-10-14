//! The permutation relation's grand-product identity on four sumcheck edges at once (bb runs its
//! wasm sumcheck on `VectorField` lanes; this is the same idea for the one relation that owns most
//! of the folding sumcheck's multiplies). Per edge, with the edge entries `v(X) = v₀ + X·Δv`:
//!
//!   `z(X)·∏ᵢ (wᵢ + β·idᵢ + γ) − z_shift(X)·∏ᵢ (wᵢ + β·σᵢ + γ)`, the first factor of each product
//!   scaled by the edge's gate-separator weight,
//!
//! which is subrelation 0 on every edge where `lagrange_first` and `lagrange_last` vanish (the
//! caller routes the others through the scalar path). Each factor is linear in X; the pairs
//! multiply by Karatsuba in coefficient form (bb's degree-1 trick), the pair products are stepped
//! to the points `0..6` by finite differences, and the rest is pointwise — 14 four-lane multiplies
//! per edge where the scalar coefficient-basis body takes 64 scalar ones. The caller receives the
//! sum over all pushed edges at the points `0..6` and interpolates once, so the round univariate is
//! the same field values.

use super::packed::QuadConsts;
use super::quad261::{add, mont_mul, sub, QuadFp};
use crate::base::Fr;
use core::any::TypeId;

/// Inputs per edge: for each wire `i`: `w₀, Δw, id₀, Δid, σ₀, Δσ`; then `z₀, Δz, z_shift₀,
/// Δz_shift` and the separator weight.
pub const PERM_INPUTS: usize = 29;
/// Points of the identity's univariate (degree 5).
pub const PERM_POINTS: usize = 6;

pub struct PermLanes {
    stage: [[[u64; 4]; 4]; PERM_INPUTS],
    lanes: usize,
    pushed: bool,
    acc: [QuadFp; PERM_POINTS],
    beta: QuadFp,
    gamma: QuadFp,
}

#[inline(always)]
fn stored<F>(x: &F) -> [u64; 4] {
    unsafe { core::mem::transmute_copy::<F, [u64; 4]>(x) }
}

impl PermLanes {
    /// `None` unless `F` is bn254 Fr (the only field with the kernel).
    pub fn new<F: 'static>(beta: &F, gamma: &F) -> Option<Box<Self>> {
        if TypeId::of::<F>() != TypeId::of::<Fr>() {
            return None;
        }
        let zero = QuadFp::pack(&[[0; 4]; 4]);
        Some(Box::new(PermLanes {
            stage: [[[0; 4]; 4]; PERM_INPUTS],
            lanes: 0,
            pushed: false,
            acc: [zero; PERM_POINTS],
            beta: QuadFp::pack(&[stored(beta); 4]),
            gamma: QuadFp::pack(&[stored(gamma); 4]),
        }))
    }

    /// Stage one edge (`v` in the `PERM_INPUTS` order); every fourth edge runs the kernel.
    #[inline]
    pub fn push<F: 'static>(&mut self, v: &[F; PERM_INPUTS]) {
        debug_assert_eq!(TypeId::of::<F>(), TypeId::of::<Fr>());
        for (k, x) in v.iter().enumerate() {
            self.stage[k][self.lanes] = stored(x);
        }
        self.lanes += 1;
        self.pushed = true;
        if self.lanes == 4 {
            self.run();
        }
    }

    /// The sum over the pushed edges at the points `0..PERM_POINTS` (`None` if nothing was
    /// pushed); resets the accumulators.
    pub fn finish<F: 'static>(&mut self) -> Option<[F; PERM_POINTS]> {
        if !self.pushed {
            return None;
        }
        if self.lanes > 0 {
            // A zero weight zeroes both scaled factors, so the idle lanes contribute 0.
            for l in self.lanes..4 {
                self.stage[PERM_INPUTS - 1][l] = [0; 4];
            }
            self.run();
        }
        let kc = Fr::kc();
        let out = core::array::from_fn(|x| {
            let s = self.acc[x].unpack(&kc.modulus);
            let mut t = Fr::from(0u64);
            for l in s {
                t += unsafe { core::mem::transmute_copy::<[u64; 4], Fr>(&l) };
            }
            unsafe { core::mem::transmute_copy::<Fr, F>(&t) }
        });
        let zero = QuadFp::pack(&[[0; 4]; 4]);
        self.acc = [zero; PERM_POINTS];
        self.pushed = false;
        Some(out)
    }

    #[inline(never)]
    fn run(&mut self) {
        let c = &Fr::kc().c;
        let at = |k: usize| QuadFp::pack(&self.stage[k]);
        let (beta, gamma) = (&self.beta, &self.gamma);
        let scaling = at(PERM_INPUTS - 1);
        // Factor i: (w₀ + γ + β·x₀) + X·(Δw + β·Δx), x = id (numerator) or σ (denominator).
        let mut num = [[*gamma; 2]; 4];
        let mut den = num;
        for i in 0..4 {
            let (w0, dw) = (at(6 * i), at(6 * i + 1));
            let wg = add(&w0, gamma, c);
            num[i] = [add(&wg, &mont_mul(&at(6 * i + 2), beta, c), c), add(&dw, &mont_mul(&at(6 * i + 3), beta, c), c)];
            den[i] = [add(&wg, &mont_mul(&at(6 * i + 4), beta, c), c), add(&dw, &mont_mul(&at(6 * i + 5), beta, c), c)];
        }
        for f in [&mut num[0], &mut den[0]] {
            *f = [mont_mul(&f[0], &scaling, c), mont_mul(&f[1], &scaling, c)];
        }
        let n01 = pair_points(&num[0], &num[1], c);
        let n23 = pair_points(&num[2], &num[3], c);
        let d01 = pair_points(&den[0], &den[1], c);
        let d23 = pair_points(&den[2], &den[3], c);
        let (z0, dz, s0, ds) = (at(24), at(25), at(26), at(27));
        let (mut z, mut s) = (z0, s0);
        for x in 0..PERM_POINTS {
            if x > 0 {
                z = add(&z, &dz, c);
                s = add(&s, &ds, c);
            }
            let n = mont_mul(&n01[x], &n23[x], c);
            let d = mont_mul(&d01[x], &d23[x], c);
            let t = sub(&mont_mul(&z, &n, c), &mont_mul(&s, &d, c), c);
            self.acc[x] = add(&self.acc[x], &t, c);
        }
        self.lanes = 0;
    }
}

/// `(a₀ + X·a₁)(b₀ + X·b₁)` at the points `0..PERM_POINTS`: Karatsuba coefficients `c₀, c₁, c₂`,
/// then forward differences `Δ(x) = c₁ + c₂(2x + 1)`.
#[inline(always)]
fn pair_points(a: &[QuadFp; 2], b: &[QuadFp; 2], c: &super::quad261::Consts) -> [QuadFp; PERM_POINTS] {
    let c0 = mont_mul(&a[0], &b[0], c);
    let c2 = mont_mul(&a[1], &b[1], c);
    let m = mont_mul(&add(&a[0], &a[1], c), &add(&b[0], &b[1], c), c);
    let c1 = sub(&sub(&m, &c0, c), &c2, c);
    let two_c2 = add(&c2, &c2, c);
    let mut out = [c0; PERM_POINTS];
    let mut d = add(&c1, &c2, c);
    for x in 1..PERM_POINTS {
        out[x] = add(&out[x - 1], &d, c);
        d = add(&d, &two_c2, c);
    }
    out
}
