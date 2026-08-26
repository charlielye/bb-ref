//! Derived constants of the K=4 compressed Poseidon2 internal-round encoding (bb
//! `crypto/poseidon2/poseidon2_quad_params.hpp`). Everything is computed from the internal matrix
//! diagonal `D_i`; see bb's `stdlib/hash/poseidon2/README.md` for the derivation.

use crate::base::field::{from_hex, FieldLike, Fr};
use crate::base::poseidon2_params::INTERNAL_MATRIX_DIAGONAL_MINUS_ONE;
use ark_ff::Field;
use std::sync::OnceLock;

/// Coefficients on the inputs `(w_r, w_o, w_4, u_0, u_1, u_2, u_3)` of one linear form.
pub type Row = [Fr; 7];

pub struct QuadParams {
    pub d1: Fr,
    pub sigma: Fr,
    pub sigma_plus_2: Fr,
    pub b3_u0_coef: Fr,
    pub d1_minus_3: Fr,
    pub a_one: [Fr; 3],
    pub a2_one: [Fr; 3],
    pub sum_a_one: Fr,
    /// `closed_form[j]`: the state element `j` after four internal rounds.
    pub closed_form: [Row; 4],
    /// `forward_vandermonde_lhs[k]`: `Σ_j D_{j+1}^k · out_j` over the hidden lanes `j = 1..3`.
    pub forward_vandermonde_lhs: [Row; 3],
}

type Mat = [[Fr; 3]; 3];
type Vec3 = [Fr; 3];

fn mat_mul(a: &Mat, b: &Mat) -> Mat {
    let mut r = [[Fr::zero(); 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            for k in 0..3 {
                r[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    r
}
fn mat_vec(a: &Mat, v: &Vec3) -> Vec3 {
    let mut r = [Fr::zero(); 3];
    for i in 0..3 {
        for k in 0..3 {
            r[i] += a[i][k] * v[k];
        }
    }
    r
}
fn vec_mat(v: &Vec3, a: &Mat) -> Vec3 {
    let mut r = [Fr::zero(); 3];
    for j in 0..3 {
        for k in 0..3 {
            r[j] += v[k] * a[k][j];
        }
    }
    r
}

fn build() -> QuadParams {
    let d: Vec<Fr> = INTERNAL_MATRIX_DIAGONAL_MINUS_ONE.iter().map(|h| Fr::one() + from_hex::<Fr>(h)).collect();
    let (d1, d2, d3, d4) = (d[0], d[1], d[2], d[3]);
    let sigma = d2 + d3 + d4;
    let f = |v: u64| Fr::from(v);
    let inv_denom_1 = ((d2 - d3) * (d2 - d4)).inverse().unwrap();
    let inv_denom_2 = (-(d2 - d3) * (d3 - d4)).inverse().unwrap();
    let inv_denom_3 = (-(d2 - d4) * -(d3 - d4)).inverse().unwrap();
    let vinv: Mat = [
        [d3 * d4 * inv_denom_1, -(d3 + d4) * inv_denom_1, inv_denom_1],
        [d2 * d4 * inv_denom_2, -(d2 + d4) * inv_denom_2, inv_denom_2],
        [d2 * d3 * inv_denom_3, -(d2 + d3) * inv_denom_3, inv_denom_3],
    ];
    let ones = [Fr::one(); 3];
    let a: Mat = [[d2, f(1), f(1)], [f(1), d3, f(1)], [f(1), f(1), d4]];
    let a2 = mat_mul(&a, &a);
    let a3 = mat_mul(&a2, &a);
    let a4 = mat_mul(&a3, &a);
    let a_one = mat_vec(&a, &ones);
    let a2_one = mat_vec(&a2, &ones);
    let a3_one = mat_vec(&a3, &ones);
    let m = mat_mul(&a4, &vinv);
    let bw: Mat = [[f(1), f(0), f(0)], [-f(2), f(1), f(0)], [-(sigma + f(2)), -f(1), f(1)]];
    let bu: Mat = [
        [-d1, f(0), f(0)],
        [f(2) * d1 - f(3), -d1, f(0)],
        [(sigma + f(2)) * d1 - sigma - f(3), d1 - f(3), -d1],
    ];
    let mw = mat_mul(&m, &bw);
    let mbu = mat_mul(&m, &bu);
    let col_sum_a3 = vec_mat(&ones, &a3);
    let q_t3 = vec_mat(&col_sum_a3, &vinv);
    let sum_a_one = a_one[0] + a_one[1] + a_one[2];
    let sum_a2_one = a2_one[0] + a2_one[1] + a2_one[2];
    let row0_w = vec_mat(&q_t3, &bw);
    let row0_u = vec_mat(&q_t3, &bu);
    let row0: Row = [row0_w[0], row0_w[1], row0_w[2], row0_u[0] + sum_a2_one, row0_u[1] + sum_a_one, row0_u[2] + f(3), d1];
    let out_j = |j: usize| -> Row { [mw[j][0], mw[j][1], mw[j][2], mbu[j][0] + a3_one[j], mbu[j][1] + a2_one[j], mbu[j][2] + a_one[j], f(1)] };
    let closed_form = [row0, out_j(0), out_j(1), out_j(2)];
    let weights: [Vec3; 3] = [[f(1), f(1), f(1)], [d2, d3, d4], [d2 * d2, d3 * d3, d4 * d4]];
    let fwd = weights.map(|w| {
        let mut r = [Fr::zero(); 7];
        for i in 0..7 {
            r[i] = w[0] * closed_form[1][i] + w[1] * closed_form[2][i] + w[2] * closed_form[3][i];
        }
        r
    });
    let sigma_plus_2 = sigma + f(2);
    QuadParams {
        d1,
        sigma,
        sigma_plus_2,
        b3_u0_coef: sigma_plus_2 * d1 - sigma - f(3),
        d1_minus_3: d1 - f(3),
        a_one: [d2 + f(2), d3 + f(2), d4 + f(2)],
        a2_one: [d2 * d2 + d2 + sigma + f(4), d3 * d3 + d3 + sigma + f(4), d4 * d4 + d4 + sigma + f(4)],
        sum_a_one: sigma + f(6),
        closed_form,
        forward_vandermonde_lhs: fwd,
    }
}

pub fn quad_params() -> &'static QuadParams {
    static P: OnceLock<QuadParams> = OnceLock::new();
    P.get_or_init(build)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::poseidon2::{matrix_multiplication_internal, round_constants, sbox};

    /// Four native internal rounds agree with the closed-form tables (bb `poseidon2_quad_closed_form.test.cpp`).
    #[test]
    fn closed_form_matches_native_rounds() {
        let p = quad_params();
        let start = 4;
        let mut s = [Fr::from(3u64), Fr::from(5u64), Fr::from(7u64), Fr::from(11u64)];
        let mut lane0 = vec![s[0]];
        let mut u = vec![];
        for k in 0..4 {
            let mut x = s[0] + round_constants()[start + k][0];
            sbox(&mut x);
            u.push(x);
            s[0] = x;
            matrix_multiplication_internal(&mut s);
            lane0.push(s[0]);
        }
        let inputs = [lane0[1], lane0[2], lane0[3], u[0], u[1], u[2], u[3]];
        for j in 0..4 {
            let v: Fr = (0..7).map(|i| p.closed_form[j][i] * inputs[i]).sum();
            assert_eq!(v, s[j], "state element {j}");
        }
    }
}
