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
        // A product with an edge-constant zero (an absent gate type's selector) is a constant zero.
        if (l1 == 1 && self.c[0].is_zero()) || (l2 == 1 && rhs.c[0].is_zero()) {
            return Graded::constant(F::ZERO);
        }
        // An edge-constant ±1 (most selector values) multiplies for free.
        if l1 == 1 || l2 == 1 {
            let (k, other) = if l1 == 1 { (self.c[0], rhs) } else { (rhs.c[0], &self) };
            if k == F::ONE {
                return *other;
            }
            if (k + F::ONE).is_zero() {
                return -*other;
            }
        }
        let out_len = l1 + l2 - 1;
        assert!(out_len <= N, "graded univariate degree overflow");
        // Karatsuba for the two shapes the relation bodies produce most — a product of two edge
        // entries and a product of two such products (bb's coefficient-basis univariates exist only
        // at lengths 2 and 3 and do exactly this): 3 and 6 multiplications instead of 4 and 9.
        if l1 == 2 && l2 == 2 {
            let (a0, a1, b0, b1) = (self.c[0], self.c[1], rhs.c[0], rhs.c[1]);
            let p0 = a0 * b0;
            let p2 = a1 * b1;
            let mut c = self.c;
            c[0] = p0;
            c[1] = (a0 + a1) * (b0 + b1) - p0 - p2;
            c[2] = p2;
            return Graded { c, len: 3 };
        }
        if l1 == 3 && l2 == 3 {
            let (a0, a1, a2, b0, b1, b2) = (self.c[0], self.c[1], self.c[2], rhs.c[0], rhs.c[1], rhs.c[2]);
            let p0 = a0 * b0;
            let p1 = a1 * b1;
            let p2 = a2 * b2;
            let m01 = (a0 + a1) * (b0 + b1);
            let m02 = (a0 + a2) * (b0 + b2);
            let m12 = (a1 + a2) * (b1 + b2);
            let mut c = self.c;
            c[0] = p0;
            c[1] = m01 - p0 - p1;
            c[2] = m02 - p0 - p2 + p1;
            c[3] = m12 - p1 - p2;
            c[4] = p2;
            return Graded { c, len: 5 };
        }
        let mut c = self.c;
        for k in 0..out_len {
            c[k] = F::ZERO;
        }
        // A linear factor times a longer one: Karatsuba over pairs of the longer one's
        // coefficients, 3 multiplications per pair instead of 4 (2×5: 8 instead of 10).
        if (l1 == 2) != (l2 == 2) && l1.min(l2) == 2 {
            let (a, b, lb) = if l1 == 2 { (&self.c, &rhs.c, l2) } else { (&rhs.c, &self.c, l1) };
            let (a0, a1) = (a[0], a[1]);
            let s = a0 + a1;
            let mut j = 0;
            while j + 1 < lb {
                let p0 = a0 * b[j];
                let p2 = a1 * b[j + 1];
                c[j] += p0;
                c[j + 1] += s * (b[j] + b[j + 1]) - p0 - p2;
                c[j + 2] = p2;
                j += 2;
            }
            if j < lb {
                c[j] += a0 * b[j];
                c[j + 1] = a1 * b[j];
            }
            return Graded { c, len: out_len as u8 };
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
    fn as_const(&self) -> Option<F> {
        (self.len == 1).then_some(self.c[0])
    }
    /// A linear entry's fifth power by the binomial expansion, `Σ C(5,k) a^(5-k) b^k X^k`: 12
    /// multiplications (the binomials by doubling) where `(x²)²·x` costs 3 + 6 + 10.
    fn pow5(&self) -> Self {
        if self.len != 2 {
            return self.sqr().sqr() * self;
        }
        let (a, b) = (self.c[0], self.c[1]);
        let (a2, b2) = (a * a, b * b);
        let (a4, b4) = (a2 * a2, b2 * b2);
        let five = |t: F| t.double().double() + t;
        let mut c = self.c;
        c[0] = a4 * a;
        c[1] = five(a4 * b);
        c[2] = five(a2 * a * b2).double();
        c[3] = five(a2 * b2 * b).double();
        c[4] = five(a * b4);
        c[5] = b4 * b;
        Graded { c, len: 6 }
    }
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
        quad_batching: p.quad_batching.iter().map(|v| v.iter().map(c).collect()).collect(),
    }
}

pub fn lift_params<F: NativeField>(p: &RelationParams<F>) -> RelationParams<Graded<F>> {
    lift_params_n::<F, MAX_LEN>(p)
}
pub fn lift_params_wide<F: NativeField>(p: &RelationParams<F>) -> RelationParams<GradedWide<F>> {
    lift_params_n::<F, WIDE_LEN>(p)
}
