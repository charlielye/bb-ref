//! The AVM relations compiled for the prover's edge loop. The interpreter in [`super::relations`]
//! walks each expression tree once per point, in bb's C++ order (in-circuit every operation is a
//! gate). The prover only needs the values: here each relation is a flat list of operations with
//! shared subexpressions merged and constants folded, evaluated over all of an edge's points at
//! once, each operation at only as many points as the subrelations reading it need (their degree
//! plus one, bb's partial length at most), the rest found by extension. An operation of degree `d`
//! is computed at `d + 1` points and extended to more by forward differences (additions only): a
//! tuple term, linear in the edge, costs two multiplications by β rather than one per point.

use super::tables::{relations, Body, Expr};
use crate::base::field::{FieldLike, Fr};
use crate::honk::relations::RelationParams;
use std::collections::HashMap;
use std::sync::OnceLock;

/// An operand: a register (one value per point) or a constant.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Val {
    R(u32),
    K(Fr),
}

/// The relation parameters an interaction reads.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Param {
    Beta,
    Gamma,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Op {
    /// Column `j` along the edge: `row0[j] + k·delta[j]`.
    Col(u32),
    Add(u32, u32),
    Sub(u32, u32),
    Mul(u32, u32),
    AddK(u32, Fr),
    MulK(u32, Fr),
    /// `c − a`.
    KSub(Fr, u32),
    AddP(u32, Param),
    MulP(u32, Param),
}

/// One subrelation's output: its value, the points it is evaluated at, and whether it is scaled by
/// the gate separator (an interaction's second subrelation is not).
struct Out {
    val: Val,
    points: usize,
    scaled: bool,
}

pub struct Program {
    ops: Vec<Op>,
    /// Points each operation is wanted at (0: dead).
    need: Vec<u8>,
    /// Points each operation is computed at, `min(need, degree + 1)`; the rest are extended.
    computed: Vec<u8>,
    /// Register stride: the most points any operation needs.
    width: usize,
    outs: Vec<Out>,
}

#[derive(Default)]
struct Builder {
    ops: Vec<Op>,
    degree: Vec<usize>,
    seen: HashMap<Op, u32>,
}

impl Builder {
    fn push(&mut self, op: Op) -> Val {
        if let Some(&r) = self.seen.get(&op) {
            return Val::R(r);
        }
        let deg = |r: &u32| self.degree[*r as usize];
        let degree = match &op {
            Op::Col(_) => 1,
            Op::Add(a, b) | Op::Sub(a, b) => deg(a).max(deg(b)),
            Op::Mul(a, b) => deg(a) + deg(b),
            Op::AddK(a, _) | Op::MulK(a, _) | Op::KSub(_, a) | Op::AddP(a, _) | Op::MulP(a, _) => deg(a),
        };
        let r = self.ops.len() as u32;
        self.ops.push(op);
        self.degree.push(degree);
        self.seen.insert(op, r);
        Val::R(r)
    }
    fn degree(&self, v: Val) -> usize {
        match v {
            Val::R(r) => self.degree[r as usize],
            Val::K(_) => 0,
        }
    }
    fn col(&mut self, j: usize) -> Val {
        self.push(Op::Col(j as u32))
    }
    fn add(&mut self, a: Val, b: Val) -> Val {
        match (a, b) {
            (Val::K(x), Val::K(y)) => Val::K(x + y),
            (Val::R(r), Val::K(c)) | (Val::K(c), Val::R(r)) => {
                if c.is_zero() {
                    Val::R(r)
                } else {
                    self.push(Op::AddK(r, c))
                }
            }
            (Val::R(x), Val::R(y)) => self.push(Op::Add(x.min(y), x.max(y))),
        }
    }
    fn neg(&mut self, a: Val) -> Val {
        self.mul(a, Val::K(-Fr::one()))
    }
    fn sub(&mut self, a: Val, b: Val) -> Val {
        match (a, b) {
            (Val::K(x), Val::K(y)) => Val::K(x - y),
            (Val::R(r), Val::K(c)) => self.add(Val::R(r), Val::K(-c)),
            (Val::K(c), Val::R(r)) if c.is_zero() => self.neg(Val::R(r)),
            (Val::K(c), Val::R(r)) => self.push(Op::KSub(c, r)),
            (Val::R(x), Val::R(y)) if x == y => Val::K(Fr::zero()),
            (Val::R(x), Val::R(y)) => self.push(Op::Sub(x, y)),
        }
    }
    fn mul(&mut self, a: Val, b: Val) -> Val {
        match (a, b) {
            (Val::K(x), Val::K(y)) => Val::K(x * y),
            (Val::R(r), Val::K(c)) | (Val::K(c), Val::R(r)) => {
                if c.is_zero() {
                    Val::K(c)
                } else if c == Fr::one() {
                    Val::R(r)
                } else {
                    self.push(Op::MulK(r, c))
                }
            }
            (Val::R(x), Val::R(y)) => self.push(Op::Mul(x.min(y), x.max(y))),
        }
    }
    fn param(&mut self, a: Val, p: Param, mul: bool) -> Val {
        match a {
            Val::R(r) => self.push(if mul { Op::MulP(r, p) } else { Op::AddP(r, p) }),
            Val::K(c) => {
                // Only a tuple term's leading column feeds a parameter, never a constant.
                panic!("parameter applied to the constant {c}")
            }
        }
    }
    fn expr(&mut self, e: &Expr, lets: &[Val]) -> Val {
        match e {
            Expr::Col(j) => self.col(*j),
            Expr::Const(c) => Val::K(*c),
            Expr::Alias(i) => lets[*i],
            Expr::Add(a, b) => {
                let (a, b) = (self.expr(a, lets), self.expr(b, lets));
                self.add(a, b)
            }
            Expr::Sub(a, b) => {
                let (a, b) = (self.expr(a, lets), self.expr(b, lets));
                self.sub(a, b)
            }
            Expr::Mul(a, b) => {
                let (a, b) = (self.expr(a, lets), self.expr(b, lets));
                self.mul(a, b)
            }
            Expr::Neg(a) => {
                let a = self.expr(a, lets);
                self.neg(a)
            }
        }
    }
    /// bb's tuple term `((0·β + c₀)·β + c₁)·… + γ`.
    fn tuple(&mut self, cols: &[usize]) -> Val {
        let mut acc = self.col(cols[0]);
        for &c in &cols[1..] {
            let scaled = self.param(acc, Param::Beta, true);
            let c = self.col(c);
            acc = self.add(scaled, c);
        }
        self.param(acc, Param::Gamma, false)
    }
    /// Outputs at their degree plus one points, capped at bb's partial length; operations evaluated
    /// at the most points any output reading them needs.
    fn finish(self, outs: Vec<(Val, bool)>, max_points: usize) -> Program {
        let outs: Vec<Out> = outs
            .into_iter()
            .map(|(val, scaled)| Out { val, points: (self.degree(val) + 1).min(max_points), scaled })
            .collect();
        let mut need = vec![0u8; self.ops.len()];
        for o in &outs {
            if let Val::R(r) = o.val {
                need[r as usize] = need[r as usize].max(o.points as u8);
            }
        }
        let mut computed = vec![0u8; self.ops.len()];
        for i in (0..self.ops.len()).rev() {
            computed[i] = need[i].min(self.degree[i] as u8 + 1);
            let n = computed[i];
            let mut feed = |r: u32| need[r as usize] = need[r as usize].max(n);
            match self.ops[i] {
                Op::Col(_) => {}
                Op::Add(a, b) | Op::Sub(a, b) | Op::Mul(a, b) => {
                    feed(a);
                    feed(b);
                }
                Op::AddK(a, _) | Op::MulK(a, _) | Op::KSub(_, a) | Op::AddP(a, _) | Op::MulP(a, _) => feed(a),
            }
        }
        let width = need.iter().copied().max().unwrap_or(0) as usize;
        Program { ops: self.ops, need, computed, width, outs }
    }
}

/// The compiled relations (`None` for the handwritten poseidon2 one, which runs per point).
pub fn programs() -> &'static [Option<Program>] {
    static P: OnceLock<Vec<Option<Program>>> = OnceLock::new();
    P.get_or_init(|| relations().iter().map(compile).collect())
}

fn compile(r: &super::tables::Relation) -> Option<Program> {
    let mut b = Builder::default();
    let outs = match &r.body {
        Body::Handwritten => return None,
        Body::Generated { lets, subs } => {
            let mut vals = Vec::with_capacity(lets.len());
            for e in lets {
                let v = b.expr(e, &vals);
                vals.push(v);
            }
            subs.iter().map(|e| (b.expr(e, &vals), true)).collect()
        }
        Body::Interaction { src_sel, dst_sel, inverses, counts, src, dst } => {
            let (a, s) = (b.col(*src_sel), b.col(*dst_sel));
            let inv = b.col(*inverses);
            let (t0, t1) = (b.tuple(src), b.tuple(dst));
            // inverse · t0 · t1 − (a + s − a·s)
            let prod = b.mul(t1, t0);
            let lhs = b.mul(prod, inv);
            let (sum, both) = (b.add(a, s), b.mul(a, s));
            let exists = b.sub(sum, both);
            let first = b.sub(lhs, exists);
            // a · inverse · t1 − s · inverse · t0 (· counts)
            let (inv_t1, inv_t0) = (b.mul(inv, t1), b.mul(t0, inv));
            let read = b.mul(a, inv_t1);
            let mut write = b.mul(s, inv_t0);
            if let Some(c) = counts {
                let c = b.col(*c);
                write = b.mul(write, c);
            }
            let second = b.sub(read, write);
            vec![(first, true), (second, false)]
        }
    };
    Some(b.finish(outs, r.partial_length))
}

impl Program {
    /// Subrelation `j`'s points.
    pub fn points(&self, j: usize) -> usize {
        self.outs[j].points
    }
    /// Add the relation over the edge `row0 + k·delta` into `acc` (point-major, one value per
    /// subrelation per point, each subrelation at its own points).
    pub fn accumulate<F: FieldLike<Native = Fr>>(
        &self,
        acc: &mut [F],
        row0: &[F],
        delta: &[F],
        p: &RelationParams<F>,
        scaling: &F,
        regs: &mut Vec<F>,
    ) {
        let w = self.width;
        if regs.len() < self.ops.len() * w {
            regs.resize(self.ops.len() * w, F::zero());
        }
        let param = |q: Param| match q {
            Param::Beta => &p.beta,
            Param::Gamma => &p.gamma,
        };
        for (i, op) in self.ops.iter().enumerate() {
            let n = self.computed[i] as usize;
            if n == 0 {
                continue;
            }
            let (lo, hi) = regs.split_at_mut(i * w);
            let out = &mut hi[..n];
            let reg = |r: u32| &lo[r as usize * w..r as usize * w + n];
            match *op {
                Op::Col(j) => {
                    let (j, mut v) = (j as usize, row0[j as usize].clone());
                    for (k, o) in out.iter_mut().enumerate() {
                        if k > 0 {
                            v += &delta[j];
                        }
                        *o = v.clone();
                    }
                }
                Op::Add(a, b) => zip(out, reg(a), reg(b), |x, y| x.clone() + y),
                Op::Sub(a, b) => zip(out, reg(a), reg(b), |x, y| x.clone() - y),
                Op::Mul(a, b) => zip(out, reg(a), reg(b), |x, y| x.clone() * y),
                Op::AddK(a, c) => map(out, reg(a), &F::constant(c), |x, c| x.clone() + c),
                Op::MulK(a, c) => map(out, reg(a), &F::constant(c), |x, c| x.clone() * c),
                Op::KSub(c, a) => map(out, reg(a), &F::constant(c), |x, c| c.clone() - x),
                Op::AddP(a, q) => map(out, reg(a), param(q), |x, c| x.clone() + c),
                Op::MulP(a, q) => map(out, reg(a), param(q), |x, c| x.clone() * c),
            }
            extend(&mut hi[..self.need[i] as usize], n);
        }
        let ns = self.outs.len();
        for (j, o) in self.outs.iter().enumerate() {
            for k in 0..o.points {
                let v = match o.val {
                    Val::R(r) => regs[r as usize * w + k].clone(),
                    Val::K(c) if c.is_zero() => break,
                    Val::K(c) => F::constant(c),
                };
                acc[k * ns + j] += &if o.scaled { v * scaling } else { v };
            }
        }
    }
}

/// `v[..c]` are a degree-`c − 1` polynomial's values at `0..c`: fill the rest by stepping its
/// forward differences.
fn extend<F: FieldLike>(v: &mut [F], c: usize) {
    if v.len() <= c {
        return;
    }
    let mut diff: [F; 8] = std::array::from_fn(|k| if k < c { v[k].clone() } else { F::zero() });
    for m in 1..c {
        for i in (m..c).rev() {
            diff[i] = diff[i].clone() - &diff[i - 1];
        }
    }
    // diff[m] = Δᵐv(0); step it to Δᵐv(k) for each k.
    for (k, out) in v.iter_mut().enumerate().skip(1) {
        for m in 0..c - 1 {
            let next = diff[m + 1].clone();
            diff[m] += &next;
        }
        if k >= c {
            *out = diff[0].clone();
        }
    }
}

fn zip<F>(out: &mut [F], a: &[F], b: &[F], f: impl Fn(&F, &F) -> F) {
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = f(x, y);
    }
}

fn map<F>(out: &mut [F], a: &[F], c: &F, f: impl Fn(&F, &F) -> F) {
    for (o, x) in out.iter_mut().zip(a) {
        *o = f(x, c);
    }
}
