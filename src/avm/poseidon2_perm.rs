//! The one AVM relation bb hand-writes instead of generating (bb
//! `vm2/optimized/relations/poseidon2_perm_impl.hpp`): one Poseidon2 permutation per row, the 56
//! partial rounds quad-compressed into a single chain. Statement order follows bb exactly (the whole
//! partial-round chain is computed before its subrelations are accumulated), since in-circuit every
//! operation is a gate.

use super::tables::layout;
use crate::base::field::{from_hex, FieldLike, Fr};
use crate::base::poseidon2::round_constants;
use crate::base::poseidon2_params::INTERNAL_MATRIX_DIAGONAL_MINUS_ONE;

fn diagonal(i: usize) -> Fr {
    Fr::from(1u64) + from_hex::<Fr>(INTERNAL_MATRIX_DIAGONAL_MINUS_ONE[i])
}

fn pow5<F: FieldLike>(x: &F) -> F {
    x.sqr().sqr() * x
}

struct Ctx<'a, F> {
    acc: &'a mut [F],
    row: &'a [F],
    scaling: &'a F,
    sel: usize,
}

impl<F: FieldLike<Native = Fr>> Ctx<'_, F> {
    fn get(&self, name: &str) -> F {
        self.row[layout().col(name)].clone()
    }
    /// `evals[i] += sel · (column − value) · scaling`.
    fn pin(&mut self, i: usize, column: &str, value: &F) {
        let tmp = self.row[self.sel].clone() * &(self.get(column) - value);
        self.acc[i] += &(tmp * self.scaling);
    }
    /// bb `constrain_external_matrix`: the four MDS outputs of `input`, pinned to `out`.
    fn external_matrix(&mut self, index: usize, input: &[F; 4], out: [String; 4]) {
        let c = |v: u64| F::constant(Fr::from(v));
        let t0 = input[0].clone() + &input[1];
        let t1 = input[2].clone() + &input[3];
        let t2 = c(2) * &input[1] + &t1;
        let t3 = c(2) * &input[3] + &t0;
        let t4 = c(4) * &t1 + &t3;
        let t5 = c(4) * &t0 + &t2;
        let t6 = t3.clone() + &t5;
        let t7 = t2.clone() + &t4;
        for (k, t) in [t4, t5, t6, t7].iter().enumerate() {
            self.pin(index + k, &out[k], t);
        }
    }
    /// ARK, S-box, then the external matrix pinned to `out`.
    fn full_round(&mut self, index: usize, input: [String; 4], round: usize, out: [String; 4]) {
        let rc = &round_constants()[round];
        let mut state: [F; 4] = std::array::from_fn(|k| self.get(&input[k]) + &F::constant(rc[k]));
        for x in state.iter_mut() {
            *x = pow5(x);
        }
        self.external_matrix(index, &state, out);
    }
}

fn names(prefix: &str, idx: [u32; 4]) -> [String; 4] {
    idx.map(|i| format!("{prefix}{i}"))
}

pub fn accumulate<F: FieldLike<Native = Fr>>(acc: &mut [F], row: &[F], scaling: &F) {
    let sel = layout().col("poseidon2_perm_sel");
    let mut cx = Ctx { acc, row, scaling, sel };
    let d = [diagonal(0), diagonal(1), diagonal(2), diagonal(3)].map(F::constant);
    let (d1, d2, d3, d4) = (&d[0], &d[1], &d[2], &d[3]);

    // 0: selector booleanity
    {
        let s = cx.row[sel].clone();
        let tmp = s.clone() * &(F::one() - &s);
        cx.acc[0] += &(tmp * scaling);
    }
    // 1..4: initial external matrix on the input state
    let input = std::array::from_fn(|k| cx.get(&format!("poseidon2_perm_a_{k}")));
    cx.external_matrix(1, &input, names("poseidon2_perm_EXT_LAYER_", [4, 5, 6, 7]));

    // 5..20: four initial full rounds, each reading the previous output permuted {6, 5, 7, 4}
    for i in 0..4 {
        let input = if i == 0 {
            names("poseidon2_perm_EXT_LAYER_", [6, 5, 7, 4])
        } else {
            names(&format!("poseidon2_perm_T_{}_", i - 1), [6, 5, 7, 4])
        };
        cx.full_round(5 + 4 * i, input, i, names(&format!("poseidon2_perm_T_{i}_"), [4, 5, 6, 7]));
    }

    // 21..79: the 56 partial rounds as one chain (ALPHA on the S-boxed lane, X/Y/Z on the others)
    let b3 = [cx.get("poseidon2_perm_T_3_6"), cx.get("poseidon2_perm_T_3_5"), cx.get("poseidon2_perm_T_3_7"), cx.get("poseidon2_perm_T_3_4")];
    let b_partial = |i: usize| format!("poseidon2_perm_B_{}_0", i + 4);
    let rc = round_constants();
    let mut alphas: Vec<F> = Vec::with_capacity(56);
    let (mut xs, mut ys, mut zs): (Vec<F>, Vec<F>, Vec<F>) = (Vec::new(), Vec::new(), Vec::new());
    alphas.push(pow5(&(b3[0].clone() + &F::constant(rc[4][0]))));
    xs.push(b3[1].clone() * d2 + &b3[2] + &b3[3] + &alphas[0]);
    ys.push(b3[1].clone() + &(b3[2].clone() * d3) + &b3[3] + &alphas[0]);
    zs.push(b3[1].clone() + &b3[2] + &(b3[3].clone() * d4) + &alphas[0]);
    for i in 1..56 {
        alphas.push(pow5(&(cx.get(&b_partial(i - 1)) + &F::constant(rc[i + 4][0]))));
        if i < 55 {
            let (x, y, z) = (&xs[i - 1], &ys[i - 1], &zs[i - 1]);
            let nx = x.clone() * d2 + y + z + &alphas[i];
            let ny = x.clone() + &(y.clone() * d3) + z + &alphas[i];
            let nz = x.clone() + y + &(z.clone() * d4) + &alphas[i];
            xs.push(nx);
            ys.push(ny);
            zs.push(nz);
        }
    }
    for i in 0..56 {
        let carried = if i == 0 { [&b3[1], &b3[2], &b3[3]] } else { [&xs[i - 1], &ys[i - 1], &zs[i - 1]] };
        let value = d1.clone() * &alphas[i] + carried[0] + carried[1] + carried[2];
        cx.pin(21 + i, &b_partial(i), &value);
    }
    let (x, y, z, a) = (&xs[54], &ys[54], &zs[54], &alphas[55]);
    cx.pin(77, "poseidon2_perm_B_59_1", &(d2.clone() * x + y + z + a));
    cx.pin(78, "poseidon2_perm_B_59_2", &(x.clone() + &(d3.clone() * y) + z + a));
    cx.pin(79, "poseidon2_perm_B_59_3", &(x.clone() + y + &(d4.clone() * z) + a));

    // 80..95: four final full rounds; round 60 reads B_59_{0..3} in order, the rest {6, 5, 7, 4}
    for i in 0..4 {
        let input = if i == 0 {
            names("poseidon2_perm_B_59_", [0, 1, 2, 3])
        } else {
            names(&format!("poseidon2_perm_T_{}_", 59 + i), [6, 5, 7, 4])
        };
        cx.full_round(80 + 4 * i, input, 60 + i, names(&format!("poseidon2_perm_T_{}_", 60 + i), [4, 5, 6, 7]));
    }

    // 96..99: the outputs are the final state {T_63_6, T_63_5, T_63_7, T_63_4}
    for (k, s) in [6, 5, 7, 4].iter().enumerate() {
        let v = cx.get(&format!("poseidon2_perm_T_63_{s}"));
        cx.pin(96 + k, &format!("poseidon2_perm_b_{k}"), &v);
    }
}
