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

#[derive(Clone, Copy, Debug)]
pub struct Graded<F> {
    /// Coefficients in the round variable; entries at `len..` are zero.
    c: [F; MAX_LEN],
    len: u8,
}

impl<F: NativeField> Graded<F> {
    pub fn constant(v: F) -> Self {
        let mut c = [F::ZERO; MAX_LEN];
        c[0] = v;
        Self { c, len: 1 }
    }
    /// The edge entry `row0 + X·delta`; a constant edge (Δ = 0) stays degree 0, which is what
    /// makes products against locally-constant selectors cheap.
    pub fn linear(row0: F, delta: F) -> Self {
        let mut c = [F::ZERO; MAX_LEN];
        c[0] = row0;
        c[1] = delta;
        Self {
            c,
            len: if delta.is_zero() { 1 } else { 2 },
        }
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

impl<F: NativeField> PartialEq for Graded<F> {
    fn eq(&self, other: &Self) -> bool {
        self.c == other.c
    }
}

impl<F: NativeField> Add<&Graded<F>> for Graded<F> {
    type Output = Graded<F>;
    fn add(mut self, rhs: &Graded<F>) -> Graded<F> {
        self += rhs;
        self
    }
}
impl<F: NativeField> Add for Graded<F> {
    type Output = Graded<F>;
    fn add(mut self, rhs: Graded<F>) -> Graded<F> {
        self += &rhs;
        self
    }
}
impl<F: NativeField> Sub<&Graded<F>> for Graded<F> {
    type Output = Graded<F>;
    fn sub(mut self, rhs: &Graded<F>) -> Graded<F> {
        self -= rhs;
        self
    }
}
impl<F: NativeField> Sub for Graded<F> {
    type Output = Graded<F>;
    fn sub(mut self, rhs: Graded<F>) -> Graded<F> {
        self -= &rhs;
        self
    }
}
impl<F: NativeField> Mul<&Graded<F>> for Graded<F> {
    type Output = Graded<F>;
    fn mul(self, rhs: &Graded<F>) -> Graded<F> {
        let (l1, l2) = (self.len as usize, rhs.len as usize);
        let out_len = l1 + l2 - 1;
        assert!(out_len <= MAX_LEN, "graded univariate degree overflow");
        let mut c = [F::ZERO; MAX_LEN];
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
impl<F: NativeField> Mul for Graded<F> {
    type Output = Graded<F>;
    fn mul(self, rhs: Graded<F>) -> Graded<F> {
        self * &rhs
    }
}
impl<F: NativeField> Neg for Graded<F> {
    type Output = Graded<F>;
    fn neg(mut self) -> Graded<F> {
        for i in 0..self.len as usize {
            self.c[i] = -self.c[i];
        }
        self
    }
}
impl<F: NativeField> AddAssign<&Graded<F>> for Graded<F> {
    fn add_assign(&mut self, rhs: &Graded<F>) {
        for i in 0..rhs.len as usize {
            self.c[i] += rhs.c[i];
        }
        self.len = self.len.max(rhs.len);
    }
}
impl<F: NativeField> AddAssign for Graded<F> {
    fn add_assign(&mut self, rhs: Graded<F>) {
        *self += &rhs;
    }
}
impl<F: NativeField> SubAssign<&Graded<F>> for Graded<F> {
    fn sub_assign(&mut self, rhs: &Graded<F>) {
        for i in 0..rhs.len as usize {
            self.c[i] -= rhs.c[i];
        }
        self.len = self.len.max(rhs.len);
    }
}
impl<F: NativeField> SubAssign for Graded<F> {
    fn sub_assign(&mut self, rhs: Graded<F>) {
        *self -= &rhs;
    }
}
impl<F: NativeField> MulAssign<&Graded<F>> for Graded<F> {
    fn mul_assign(&mut self, rhs: &Graded<F>) {
        *self = *self * rhs;
    }
}
impl<F: NativeField> MulAssign for Graded<F> {
    fn mul_assign(&mut self, rhs: Graded<F>) {
        *self = *self * &rhs;
    }
}

impl<F: NativeField> FieldLike for Graded<F> {
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
pub fn lift_params<F: NativeField>(p: &RelationParams<F>) -> RelationParams<Graded<F>> {
    let c = |v: &F| Graded::constant(*v);
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
