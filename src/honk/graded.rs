//! Degree-tracked coefficient-basis univariates for relation evaluation on a sumcheck edge
//! (bb `UnivariateCoefficientBasis`). A row entry is the linear polynomial `row0 + X·Δ` in the
//! round variable; running the (FieldLike-generic) relation bodies on these makes every ring
//! operation cost its true degree — a product of two linear terms is 4 multiplications — where the
//! evaluation-basis path pays the full batched univariate length at every operation. The results
//! are polynomial identities over the field, so the round univariates are bit-identical to the
//! pointwise path.

use super::relations::RelationParams;
use crate::base::field::{FieldLike, NativeField};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// Coefficient capacity: covers every Ultra/Mega/Translator subrelation degree (the edge loop
/// falls back to pointwise evaluation for relation sets that exceed it, e.g. the ECCVM's).
pub const MAX_LEN: usize = 8;
/// Capacity of the wide variant used for the ECCVM's degree-21/8 relations (`Set`, `Lookup`).
pub const WIDE_LEN: usize = 24;
pub type GradedWide<F> = Graded<F, WIDE_LEN>;

#[derive(Clone, Copy, Debug)]
pub struct Graded<F, const N: usize = MAX_LEN> {
    /// Coefficients in the round variable; entries at `len..` are unspecified (every operation
    /// reads and writes only within the operands' lengths).
    c: [F; N],
    len: u8,
}

impl<F: NativeField, const N: usize> Graded<F, N> {
    pub fn constant(v: F) -> Self {
        let mut c = [F::ZERO; N];
        c[0] = v;
        Self { c, len: 1 }
    }

    /// The edge entry `row0 + X·delta`; a constant edge (Δ = 0) stays degree 0, which is what
    /// makes products against locally-constant selectors cheap.
    pub fn linear(row0: F, delta: F) -> Self {
        let mut c = [F::ZERO; N];
        c[0] = row0;
        c[1] = delta;
        Self {
            c,
            len: if delta.is_zero() { 1 } else { 2 },
        }
    }
    /// `row0 + X·delta` written into a reused buffer entry: only the two low coefficients move —
    /// the entry's high slots are zero from allocation and row entries are never written by ring
    /// ops, so the zero-padding invariant holds without touching them.
    pub fn set_linear(&mut self, row0: F, delta: F) {
        self.c[0] = row0;
        self.c[1] = delta;
        self.len = if delta.is_zero() { 1 } else { 2 };
    }
    /// The coefficients in the round variable, low to high (`len` entries).
    pub fn coeffs(&self) -> &[F] {
        &self.c[..self.len as usize]
    }
    /// Evaluation at the point `k` (Horner).
    pub fn eval_at(&self, k: F) -> F {
        let l = self.len as usize;
        let mut acc = self.c[l - 1];
        for i in (0..l - 1).rev() {
            acc = acc * k + self.c[i];
        }
        acc
    }
}

impl<F: NativeField, const N: usize> PartialEq for Graded<F, N> {
    fn eq(&self, other: &Self) -> bool {
        let at = |g: &Self, i: usize| if i < g.len as usize { g.c[i] } else { F::ZERO };
        (0..N.max(1)).all(|i| at(self, i) == at(other, i))
    }
}

impl<F: NativeField, const N: usize> Add<&Graded<F, N>> for Graded<F, N> {
    type Output = Graded<F, N>;
    fn add(mut self, rhs: &Graded<F, N>) -> Graded<F, N> {
        self += rhs;
        self
    }
}
impl<F: NativeField, const N: usize> Add for Graded<F, N> {
    type Output = Graded<F, N>;
    fn add(mut self, rhs: Graded<F, N>) -> Graded<F, N> {
        self += &rhs;
        self
    }
}
impl<F: NativeField, const N: usize> Sub<&Graded<F, N>> for Graded<F, N> {
    type Output = Graded<F, N>;
    fn sub(mut self, rhs: &Graded<F, N>) -> Graded<F, N> {
        self -= rhs;
        self
    }
}
impl<F: NativeField, const N: usize> Sub for Graded<F, N> {
    type Output = Graded<F, N>;
    fn sub(mut self, rhs: Graded<F, N>) -> Graded<F, N> {
        self -= &rhs;
        self
    }
}
impl<F: NativeField, const N: usize> Mul<&Graded<F, N>> for Graded<F, N> {
    type Output = Graded<F, N>;
    fn mul(self, rhs: &Graded<F, N>) -> Graded<F, N> {
        let (l1, l2) = (self.len as usize, rhs.len as usize);
        let out_len = l1 + l2 - 1;
        assert!(out_len <= N, "graded univariate degree overflow");
        let mut c = self.c;
        for k in 0..out_len {
            c[k] = F::ZERO;
        }
        for i in 0..l1 {
            let a = self.c[i];
            if a.is_zero() {
                continue;
            }
            for j in 0..l2 {
                c[i + j] += a * rhs.c[j];
            }
        }
        Graded { c, len: out_len as u8 }
    }
}
impl<F: NativeField, const N: usize> Mul for Graded<F, N> {
    type Output = Graded<F, N>;
    fn mul(self, rhs: Graded<F, N>) -> Graded<F, N> {
        self * &rhs
    }
}
impl<F: NativeField, const N: usize> Neg for Graded<F, N> {
    type Output = Graded<F, N>;
    fn neg(mut self) -> Graded<F, N> {
        for i in 0..self.len as usize {
            self.c[i] = -self.c[i];
        }
        self
    }
}
impl<F: NativeField, const N: usize> AddAssign<&Graded<F, N>> for Graded<F, N> {
    fn add_assign(&mut self, rhs: &Graded<F, N>) {
        let common = (self.len as usize).min(rhs.len as usize);
        for i in 0..common {
            self.c[i] += rhs.c[i];
        }
        for i in common..rhs.len as usize {
            self.c[i] = rhs.c[i];
        }
        self.len = self.len.max(rhs.len);
    }
}
impl<F: NativeField, const N: usize> AddAssign for Graded<F, N> {
    fn add_assign(&mut self, rhs: Graded<F, N>) {
        *self += &rhs;
    }
}
impl<F: NativeField, const N: usize> SubAssign<&Graded<F, N>> for Graded<F, N> {
    fn sub_assign(&mut self, rhs: &Graded<F, N>) {
        let common = (self.len as usize).min(rhs.len as usize);
        for i in 0..common {
            self.c[i] -= rhs.c[i];
        }
        for i in common..rhs.len as usize {
            self.c[i] = -rhs.c[i];
        }
        self.len = self.len.max(rhs.len);
    }
}
impl<F: NativeField, const N: usize> SubAssign for Graded<F, N> {
    fn sub_assign(&mut self, rhs: Graded<F, N>) {
        *self -= &rhs;
    }
}
impl<F: NativeField, const N: usize> MulAssign<&Graded<F, N>> for Graded<F, N> {
    fn mul_assign(&mut self, rhs: &Graded<F, N>) {
        *self = *self * rhs;
    }
}
impl<F: NativeField, const N: usize> MulAssign for Graded<F, N> {
    fn mul_assign(&mut self, rhs: Graded<F, N>) {
        *self = *self * &rhs;
    }
}

impl<F: NativeField, const N: usize> FieldLike for Graded<F, N> {
    type Native = F;
    type Ctx = ();

    fn ctx(&self) -> Option<()> {
        None
    }
    fn constant(v: F) -> Self {
        Graded::constant(v)
    }
    fn from_witness(_ctx: &(), _v: F) -> Self {
        unreachable!("graded univariates are a native prover representation")
    }
    fn value(&self) -> F {
        assert_eq!(self.len, 1, "value() of a non-constant graded univariate");
        self.c[0]
    }
    fn invert(&self) -> Self {
        assert_eq!(self.len, 1, "invert() of a non-constant graded univariate");
        Graded::constant(self.c[0].inverse().unwrap_or(F::ZERO))
    }
    fn assert_equal(&self, _other: &Self) {}
}

/// The relation parameters lifted to constants in the round variable.
pub fn lift_params_n<F: NativeField, const N: usize>(p: &RelationParams<F>) -> RelationParams<Graded<F, N>> {
    let c = |v: &F| Graded::<F, N>::constant(*v);
    RelationParams {
        eta: c(&p.eta),
        eta_two: c(&p.eta_two),
        eta_three: c(&p.eta_three),
        rom_logup_gamma: c(&p.rom_logup_gamma),
        beta: c(&p.beta),
        gamma: c(&p.gamma),
        public_input_delta: c(&p.public_input_delta),
        beta_sqr: c(&p.beta_sqr),
        beta_cube: c(&p.beta_cube),
        beta_quartic: c(&p.beta_quartic),
        eccvm_set_permutation_delta: c(&p.eccvm_set_permutation_delta),
        evaluation_input_x: std::array::from_fn(|i| c(&p.evaluation_input_x[i])),
        batching_challenge_v: std::array::from_fn(|i| std::array::from_fn(|j| c(&p.batching_challenge_v[i][j]))),
        accumulated_result: std::array::from_fn(|i| c(&p.accumulated_result[i])),
    }
}

pub fn lift_params<F: NativeField>(p: &RelationParams<F>) -> RelationParams<Graded<F>> {
    lift_params_n::<F, MAX_LEN>(p)
}
pub fn lift_params_wide<F: NativeField>(p: &RelationParams<F>) -> RelationParams<GradedWide<F>> {
    lift_params_n::<F, WIDE_LEN>(p)
}
