//! Dense univariate/multilinear polynomials (bb `Polynomial<Fr>` without the shifted-virtual-zero
//! window: a plain coefficient vector of the dyadic size).

use super::field::{FieldLike, Fr};
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial<F: FieldLike> {
    pub coeffs: Vec<F>,
}

/// Polynomials over bn254 Fr, the field of every Honk flavor but the ECCVM's.
pub type Poly = Polynomial<Fr>;

impl<F: FieldLike + Send + Sync> Polynomial<F> {
    /// `evaluate` for large polynomials (the Gemini batched polynomial and its folds are
    /// 2^16-2^17): chunk-wise Horner on the pool, recombined with z^L. Exact — the same polynomial.
    pub fn evaluate_par(&self, z: &F) -> F {
        const CHUNK: usize = 8192;
        if self.coeffs.len() <= 2 * CHUNK {
            return horner(&self.coeffs, z);
        }
        let partials: Vec<F> = self.coeffs.par_chunks(CHUNK).map(|c| horner(c, z)).collect();
        horner(&partials, &z.pow_u64(CHUNK as u64))
    }
}

impl<F: FieldLike> Polynomial<F> {
    pub fn zero(size: usize) -> Self {
        Self {
            coeffs: F::zeroed(size),
        }
    }
    pub fn from_coeffs(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }
    /// The coefficient at `i`, zero past the allocated end (columns are sized to their content).
    pub fn at(&self, i: usize) -> F {
        self.coeffs.get(i).cloned().unwrap_or_else(F::zero)
    }
    /// Index of the last non-zero coefficient plus one.
    pub fn end_index(&self) -> usize {
        self.coeffs.iter().rposition(|c| !c.is_zero()).map_or(0, |i| i + 1)
    }
    /// The left shift `p(X) / X`, valid only when `coeffs[0] == 0` (bb "shiftable" polynomials).
    pub fn shifted(&self) -> Self {
        assert!(
            self.coeffs.first().map_or(true, FieldLike::is_zero),
            "shifting a polynomial with non-zero constant term"
        );
        let mut c = self.coeffs[1..].to_vec();
        c.push(F::zero());
        Self { coeffs: c }
    }
    /// Coefficients in reverse order over the full length: `X^{n-1} p(1/X)` (bb `Polynomial::reverse`).
    pub fn reverse(&self) -> Self {
        Self {
            coeffs: self.coeffs.iter().rev().cloned().collect(),
        }
    }
    /// Horner evaluation of the univariate `sum_i coeffs[i] X^i`.
    pub fn evaluate(&self, z: &F) -> F {
        let mut acc = F::zero();
        for c in self.coeffs.iter().rev() {
            acc = acc * z + c;
        }
        acc
    }
    /// Evaluation of the multilinear extension of the coefficients at `u` (bb `evaluate_mle`);
    /// coefficient index bit `j` corresponds to `u[j]`.
    pub fn evaluate_mle(&self, u: &[F]) -> F {
        assert_eq!(self.coeffs.len(), 1 << u.len());
        let mut vals = self.coeffs.clone();
        for u_j in u {
            vals = vals
                .chunks(2)
                .map(|c| c[0].clone() + (c[1].clone() - &c[0]) * u_j)
                .collect();
        }
        vals.pop().unwrap()
    }
    /// `self += scalar * other` (other may be shorter).
    pub fn add_scaled(&mut self, other: &Self, scalar: &F)
    where
        F: Send + Sync + 'static,
    {
        self.add_scaled_batch(&[(other, scalar.clone())]);
    }
    /// `self += sum_i scalar_i * poly_i` in one pass over the rows, chunks in parallel (bb
    /// `add_scaled_batch`); shorter polynomials are zero-extended.
    pub fn add_scaled_batch(&mut self, terms: &[(&Self, F)])
    where
        F: Send + Sync + 'static,
    {
        for (p, _) in terms {
            assert!(p.len() <= self.len(), "add_scaled_batch: term is longer");
        }
        const CHUNK: usize = 1 << 12;
        self.coeffs.par_chunks_mut(CHUNK).enumerate().for_each(|(c, chunk)| {
            let start = c * CHUNK;
            for (p, s) in terms {
                let src = &p.coeffs[start.min(p.coeffs.len())..];
                let overlap = chunk.len().min(src.len());
                // Unit scalars (Shplonk's quotient sum, rho^0) need no multiplication.
                if s.value() == <F::Native as ark_ff::Field>::ONE {
                    chunk[..overlap].iter_mut().zip(src).for_each(|(a, b)| *a += b);
                    continue;
                }
                if crate::base::wasm::try_axpy(&mut chunk[..overlap], &src[..overlap], s) {
                    continue;
                }
                // Selector columns are mostly zero inside their backing range.
                for (a, b) in chunk[..overlap].iter_mut().zip(src) {
                    if !b.is_zero() {
                        *a += &(s.clone() * b);
                    }
                }
            }
        });
    }
    /// In-place division by `(X - root)`, assuming `root` is a root (bb `factor_roots`).
    pub fn factor_root(&mut self, root: &F) {
        let n = self.coeffs.len();
        if n == 0 {
            return;
        }
        // p(X) = (X - r) q(X): q_{n-2} = p_{n-1}, q_{i-1} = p_i + r q_i, remainder p_0 + r q_0 = 0.
        let mut q = vec![F::zero(); n];
        let mut carry = F::zero();
        for i in (1..n).rev() {
            carry = self.coeffs[i].clone() + &(root.clone() * &carry);
            q[i - 1] = carry.clone();
        }
        assert!(
            (self.coeffs[0].clone() + &(root.clone() * &carry)).is_zero(),
            "factor_root: not a root"
        );
        self.coeffs = q;
    }

    /// Lagrange interpolation of `evals` at `points` (O(n^2)).
    pub fn interpolate(points: &[F], evals: &[F]) -> Self {
        let n = points.len();
        assert_eq!(n, evals.len());
        let mut result = vec![F::zero(); n];
        for i in 0..n {
            let mut num = vec![F::zero(); n];
            num[0] = F::one();
            let mut deg = 0;
            let mut denom = F::one();
            for j in 0..n {
                if j == i {
                    continue;
                }
                for k in (0..=deg).rev() {
                    let v = num[k].clone();
                    num[k + 1] += &v;
                    num[k] = v * &(-points[j].clone());
                }
                deg += 1;
                denom *= &(points[i].clone() - &points[j]);
            }
            let scale = evals[i].clone() * &denom.invert();
            for k in 0..n {
                result[k] += &(num[k].clone() * &scale);
            }
        }
        Self { coeffs: result }
    }
}

fn horner<F: FieldLike>(coeffs: &[F], z: &F) -> F {
    let mut acc = F::zero();
    for c in coeffs.iter().rev() {
        acc = acc * z + c;
    }
    acc
}

/// `q += sum_j s_j (p_j - v_j) / (X - x_j)` over terms `(p_j, x_j, v_j, s_j)`, asserting that every
/// division is exact (bb `factor_roots` per term, then `add_scaled`). A term's quotient is
/// `q_i = sum_{k>i} p_k x^{k-i-1}`: each chunk of indices Horner-evaluates its own coefficients in
/// parallel, a serial scan from the top gives the value of `q` at every chunk boundary, then the
/// chunks run the descending recurrence `q_{i-1} = p_i + x q_i` from there in parallel.
pub fn add_linear_quotients<F: FieldLike + Copy + Send + Sync>(q: &mut [F], terms: &[(&[F], F, F, F)]) {
    const CHUNK: usize = 1 << 12;
    let num_chunks = q.len().div_ceil(CHUNK);
    // bounds[c][j]: q_j at the upper boundary of chunk c, from the Horner values of chunk c + 1
    let mut bounds: Vec<Vec<F>> = (1..=num_chunks)
        .into_par_iter()
        .map(|c| {
            let range = |p: &[F]| (c * CHUNK + 1).min(p.len())..((c + 1) * CHUNK + 1).min(p.len());
            terms.iter().map(|(p, x, ..)| horner(&p[range(p)], x)).collect()
        })
        .collect();
    let x_chunk: Vec<F> = terms.iter().map(|t| t.1.pow_u64(CHUNK as u64)).collect();
    for c in (0..num_chunks.saturating_sub(1)).rev() {
        for j in 0..terms.len() {
            bounds[c][j] = bounds[c][j] + x_chunk[j] * bounds[c + 1][j];
        }
    }
    q.par_chunks_mut(CHUNK)
        .zip(bounds)
        .enumerate()
        .for_each(|(c, (out, b))| {
            let lo = c * CHUNK;
            for ((p, x, v, s), mut carry) in terms.iter().zip(b) {
                for i in (lo..(lo + out.len()).min(p.len().saturating_sub(1))).rev() {
                    carry = p[i + 1] + *x * carry;
                    out[i - lo] += *s * carry;
                }
                if c == 0 && !p.is_empty() {
                    assert!((p[0] - v + *x * carry).is_zero(), "add_linear_quotients: not a root");
                }
            }
        });
}

/// The table of `eq(x, r[..log_n]) · ∏_{j ≥ log_n} (1 - r_j)` over the hypercube, index bit `j` ↔ `r[j]`
/// (bb `ProverEqPolynomial::construct`).
pub fn eq_table<F: FieldLike + Send + Sync>(r: &[F], log_n: usize) -> Vec<F> {
    let mut tail = F::one();
    for rj in &r[log_n..] {
        tail *= &(F::one() - rj);
    }
    // In place, doubling the live prefix each level: table[2^j + i] = table[i] * r_j and
    // table[i] *= (1 - r_j). The last levels are the bulk of the work and run on the pool.
    let mut table = vec![F::zero(); 1 << log_n];
    table[0] = tail;
    for (j, rj) in r.iter().take(log_n).enumerate() {
        let len = 1 << j;
        let one_minus = F::one() - rj;
        let (lo, hi) = table.split_at_mut(len);
        let hi = &mut hi[..len];
        if len >= 4096 {
            use rayon::prelude::*;
            lo.par_chunks_mut(1024).zip(hi.par_chunks_mut(1024)).for_each(|(l, h)| {
                for (a, b) in l.iter_mut().zip(h.iter_mut()) {
                    *b = a.clone() * rj;
                    *a *= &one_minus;
                }
            });
        } else {
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                *b = a.clone() * rj;
                *a *= &one_minus;
            }
        }
    }
    table
}

/// Barycentric evaluation of a univariate given by its values on `{0, 1, ..., n-1}`
/// (bb `Univariate::evaluate`).
pub fn evaluate_univariate<F: FieldLike>(vals: &[F], u: &F) -> F {
    let n = vals.len();
    let mut full_numerator = F::one();
    for i in 0..n {
        full_numerator *= &(u.clone() - &F::from_u64(i as u64));
    }
    // bb `Univariate::evaluate`: every denominator inverse first, then the terms
    let denominator_inverses: Vec<F> = (0..n)
        .map(|i| {
            let mut denom = F::one();
            for j in 0..n {
                if j != i {
                    denom *= &(F::from_u64(i as u64) - &F::from_u64(j as u64));
                }
            }
            denom *= &(u.clone() - &F::from_u64(i as u64));
            F::one().div(&denom)
        })
        .collect();
    let mut result = F::zero();
    for (v, inv) in vals.iter().zip(&denominator_inverses) {
        result += &(v.clone() * inv);
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
