//! Dense univariate/multilinear polynomials (bb `Polynomial<Fr>` without the shifted-virtual-zero
//! window: a plain coefficient vector of the dyadic size).

use super::field::{FieldLike, Fr};

#[derive(Clone, Debug, PartialEq)]
pub struct Poly {
    pub coeffs: Vec<Fr>,
}

impl Poly {
    pub fn zero(size: usize) -> Self {
        Self { coeffs: vec![Fr::zero(); size] }
    }
    pub fn from_coeffs(coeffs: Vec<Fr>) -> Self {
        Self { coeffs }
    }
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }
    /// Index of the last non-zero coefficient plus one.
    pub fn end_index(&self) -> usize {
        self.coeffs.iter().rposition(|c| !c.is_zero()).map_or(0, |i| i + 1)
    }
    /// The left shift `p(X) / X`, valid only when `coeffs[0] == 0` (bb "shiftable" polynomials).
    pub fn shifted(&self) -> Self {
        assert!(self.coeffs.first().map_or(true, FieldLike::is_zero), "shifting a polynomial with non-zero constant term");
        let mut c = self.coeffs[1..].to_vec();
        c.push(Fr::zero());
        Self { coeffs: c }
    }
    /// Horner evaluation of the univariate `sum_i coeffs[i] X^i`.
    pub fn evaluate(&self, z: &Fr) -> Fr {
        let mut acc = Fr::zero();
        for c in self.coeffs.iter().rev() {
            acc = acc * z + c;
        }
        acc
    }
    /// `self += scalar * other` (other may be shorter).
    pub fn add_scaled(&mut self, other: &Poly, scalar: &Fr) {
        assert!(other.len() <= self.len(), "add_scaled: other is longer");
        for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
            *a += *scalar * b;
        }
    }
    /// In-place division by `(X - root)`, assuming `root` is a root (bb `factor_roots`).
    pub fn factor_root(&mut self, root: &Fr) {
        let n = self.coeffs.len();
        if n == 0 {
            return;
        }
        // p(X) = (X - r) q(X): q_{n-2} = p_{n-1}, q_{i-1} = p_i + r q_i, remainder p_0 + r q_0 = 0.
        let mut q = vec![Fr::zero(); n];
        let mut carry = Fr::zero();
        for i in (1..n).rev() {
            carry = self.coeffs[i] + *root * carry;
            q[i - 1] = carry;
        }
        assert!((self.coeffs[0] + *root * carry).is_zero(), "factor_root: not a root");
        self.coeffs = q;
    }

    /// Lagrange interpolation of `evals` at `points` (O(n^2)).
    pub fn interpolate(points: &[Fr], evals: &[Fr]) -> Self {
        let n = points.len();
        assert_eq!(n, evals.len());
        let mut result = vec![Fr::zero(); n];
        for i in 0..n {
            let mut num = vec![Fr::zero(); n];
            num[0] = Fr::one();
            let mut deg = 0;
            let mut denom = Fr::one();
            for j in 0..n {
                if j == i {
                    continue;
                }
                for k in (0..=deg).rev() {
                    let v = num[k];
                    num[k + 1] += v;
                    num[k] = v * (-points[j]);
                }
                deg += 1;
                denom *= points[i] - points[j];
            }
            let scale = evals[i] * denom.invert();
            for k in 0..n {
                result[k] += num[k] * scale;
            }
        }
        Self { coeffs: result }
    }
}

/// Barycentric evaluation of a univariate given by its values on `{0, 1, ..., n-1}`
/// (bb `Univariate::evaluate`).
pub fn evaluate_univariate<F: FieldLike>(vals: &[F], u: &F) -> F {
    let n = vals.len();
    let mut full_numerator = F::one();
    for i in 0..n {
        full_numerator *= &(u.clone() - &F::from_u64(i as u64));
    }
    let mut result = F::zero();
    for (i, v) in vals.iter().enumerate() {
        let mut denom = F::one();
        for j in 0..n {
            if j != i {
                denom *= &(F::from_u64(i as u64) - &F::from_u64(j as u64));
            }
        }
        denom *= &(u.clone() - &F::from_u64(i as u64));
        result += &(v.clone() * &denom.invert());
    }
    result * &full_numerator
}

/// Extend values on `{0..n-1}` to `{0..new_len-1}` (bb `Univariate::extend_to`).
pub fn extend_univariate(vals: &[Fr], new_len: usize) -> Vec<Fr> {
    let mut out = vals.to_vec();
    for k in vals.len()..new_len {
        out.push(evaluate_univariate(vals, &Fr::from(k as u64)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_root_divides() {
        let r = Fr::from(7u64);
        // p = (X - 7)(3X^2 + 5X + 11)
        let q = Poly::from_coeffs(vec![Fr::from(11u64), Fr::from(5u64), Fr::from(3u64)]);
        let mut p = Poly::zero(4);
        for i in 0..3 {
            p.coeffs[i + 1] += q.coeffs[i];
            p.coeffs[i] -= r * q.coeffs[i];
        }
        p.factor_root(&r);
        assert_eq!(p.coeffs[..3], q.coeffs[..]);
        assert!(p.coeffs[3].is_zero());
    }

    #[test]
    fn extension_matches_evaluation() {
        let vals: Vec<Fr> = (0..4).map(|i| Fr::from((i * i + 3) as u64)).collect();
        let ext = extend_univariate(&vals, 7);
        assert_eq!(ext[5], evaluate_univariate(&vals, &Fr::from(5u64)));
        // interpolation round trip
        let pts: Vec<Fr> = (0..4).map(|i| Fr::from(i as u64)).collect();
        let p = Poly::interpolate(&pts, &vals);
        assert_eq!(p.evaluate(&Fr::from(6u64)), ext[6]);
    }
}
