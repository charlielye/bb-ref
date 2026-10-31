//! The generated AVM tables (`generated/layout.txt`, `generated/relations.txt`, written by
//! `dev/regen_avm.py` from the pin's bb-pilcom output), parsed once into the column layout, the fixed
//! verification key and the relation list the interpreter in [`super::relations`] evaluates.

use crate::base::field::{from_hex, Fr};
use crate::base::G1Affine;
use ark_ec::AffineRepr;
use std::collections::HashMap;
use std::sync::OnceLock;

const LAYOUT: &str = include_str!("generated/layout.txt");
const RELATIONS: &str = include_str!("generated/relations.txt");

pub struct Layout {
    pub max_trace_log_size: usize,
    pub proof_length: usize,
    pub public_input_column_lengths: [usize; 4],
    pub max_partial_length: usize,
    pub num_subrelations: usize,
    pub num_precomputed: usize,
    pub num_wires: usize,
    pub num_derived: usize,
    pub num_shifted: usize,
    pub vk_hash: Fr,
    /// The fixed commitments to the precomputed columns (bb `AvmHardCodedVKAndHash`).
    pub vk: Vec<G1Affine>,
    /// Every entity in bb's `ColumnAndShifts` order: precomputed, wires, derived, shifted.
    pub columns: Vec<&'static str>,
    pub index: HashMap<&'static str, usize>,
}

impl Layout {
    pub fn num_witness(&self) -> usize {
        self.num_wires + self.num_derived
    }
    pub fn num_unshifted(&self) -> usize {
        self.num_precomputed + self.num_witness()
    }
    pub fn num_all(&self) -> usize {
        self.columns.len()
    }
    /// bb `WIRES_TO_BE_SHIFTED_START_IDX`: the to-be-shifted columns are the trailing wires.
    pub fn to_be_shifted_start(&self) -> usize {
        self.num_precomputed + self.num_wires - self.num_shifted
    }
    pub fn to_be_shifted_end(&self) -> usize {
        self.num_precomputed + self.num_wires
    }
    pub fn col(&self, name: &str) -> usize {
        *self.index.get(name).unwrap_or_else(|| panic!("unknown AVM column {name}"))
    }
}

/// A relation expression, in bb's evaluation order: children are evaluated left to right.
#[derive(Debug)]
pub enum Expr {
    Col(usize),
    Const(Fr),
    Alias(usize),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
}

pub enum Body {
    /// A bb-pilcom relation: `lets` are the aliases bb hoists above the subrelations, evaluated in
    /// order; `subs` are the subrelations.
    Generated { lets: Vec<Expr>, subs: Vec<Expr> },
    /// A relation bb hand-writes (`vm2/optimized/`), ported in Rust.
    Handwritten,
    /// A log-derivative lookup (`counts` set) or permutation over two column tuples.
    Interaction {
        src_sel: usize,
        dst_sel: usize,
        inverses: usize,
        counts: Option<usize>,
        src: Vec<usize>,
        dst: Vec<usize>,
    },
}

pub struct Relation {
    pub name: &'static str,
    pub num_subrelations: usize,
    /// bb's max subrelation partial length, or for an interaction its degree in the edge variable
    /// plus one: the points the prover evaluates before extending.
    pub partial_length: usize,
    pub body: Body,
    /// bb `skip()`: the relation vanishes on an edge where the sum of these columns is zero on
    /// both rows (empty: it never skips).
    pub skip: Vec<usize>,
}

pub fn layout() -> &'static Layout {
    static L: OnceLock<Layout> = OnceLock::new();
    L.get_or_init(parse_layout)
}

pub fn relations() -> &'static [Relation] {
    static R: OnceLock<Vec<Relation>> = OnceLock::new();
    R.get_or_init(|| parse_relations(layout()))
}

fn parse_layout() -> Layout {
    let mut lines = LAYOUT.lines().filter(|l| !l.starts_with('#'));
    let mut fields: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut vk = Vec::new();
    for line in lines.by_ref() {
        if line == "columns" {
            break;
        }
        let mut it = line.split(' ');
        let key = it.next().unwrap();
        let rest: Vec<&str> = it.collect();
        if key == "vk" {
            vk.push(match rest.as_slice() {
                ["infinity"] => G1Affine::zero(),
                [x, y] => G1Affine::new_unchecked(from_hex(x), from_hex(y)),
                _ => panic!("bad vk line {line}"),
            });
        } else {
            fields.insert(key, rest);
        }
    }
    let columns: Vec<&'static str> = lines.collect();
    let one = |k: &str| -> usize { fields[k][0].parse().unwrap() };
    let counts: Vec<usize> = fields["counts"].iter().map(|v| v.parse().unwrap()).collect();
    let lengths: Vec<usize> = fields["public_input_column_lengths"].iter().map(|v| v.parse().unwrap()).collect();
    let index = columns.iter().enumerate().map(|(i, c)| (*c, i)).collect();
    let l = Layout {
        max_trace_log_size: one("max_trace_log_size"),
        proof_length: one("proof_length"),
        public_input_column_lengths: lengths.try_into().unwrap(),
        max_partial_length: one("max_partial_length"),
        num_subrelations: one("num_subrelations"),
        num_precomputed: counts[0],
        num_wires: counts[1],
        num_derived: counts[2],
        num_shifted: counts[3],
        vk_hash: from_hex(fields["vk_hash"][0]),
        vk,
        columns,
        index,
    };
    assert_eq!(l.vk.len(), l.num_precomputed);
    assert_eq!(l.num_all(), l.num_unshifted() + l.num_shifted);
    l
}

fn parse_relations(l: &Layout) -> Vec<Relation> {
    let mut out: Vec<Relation> = Vec::new();
    let mut aliases: HashMap<&str, usize> = HashMap::new();
    for line in RELATIONS.lines().filter(|l| !l.starts_with('#')) {
        let (head, rest) = line.split_once(' ').unwrap();
        match head {
            "relation" => {
                let mut it = rest.split(' ');
                let name = it.next().unwrap();
                let lengths: Vec<usize> = it.next().unwrap().split(',').map(|n| n.parse().unwrap()).collect();
                let body = match it.next() {
                    Some("handwritten") => Body::Handwritten,
                    None => Body::Generated {
                        lets: Vec::new(),
                        subs: Vec::new(),
                    },
                    Some(x) => panic!("bad relation tag {x}"),
                };
                aliases.clear();
                out.push(Relation {
                    name,
                    num_subrelations: lengths.len(),
                    partial_length: *lengths.iter().max().unwrap(),
                    body,
                    skip: Vec::new(),
                });
            }
            "let" | "sub" => {
                let Some(Relation {
                    body: Body::Generated { lets, subs },
                    ..
                }) = out.last_mut()
                else {
                    panic!("`{head}` outside a generated relation");
                };
                if head == "let" {
                    let (name, expr) = rest.split_once(' ').unwrap();
                    lets.push(parse_expr(expr, l, &aliases));
                    aliases.insert(name, lets.len() - 1);
                } else {
                    subs.push(parse_expr(rest, l, &aliases));
                }
            }
            "skip" => {
                out.last_mut().expect("`skip` outside a relation").skip = rest.split(' ').map(|c| l.col(c)).collect();
            }
            "lookup" | "perm" => {
                let mut parts = rest.split(" : ");
                let head_fields: Vec<&str> = parts.next().unwrap().split(' ').collect();
                let cols = |s: &str| -> Vec<usize> { s.split(' ').map(|c| l.col(c)).collect() };
                let src = cols(parts.next().unwrap());
                let dst = cols(parts.next().unwrap());
                let counts = (head == "lookup").then(|| l.col(head_fields[4]));
                let inverses = l.col(head_fields[3]);
                out.push(Relation {
                    name: head_fields[0],
                    num_subrelations: 2,
                    // t0·t1·inverse, and the selector·term·inverse sums (times the counts).
                    partial_length: if counts.is_some() { 5 } else { 4 },
                    skip: vec![inverses],
                    body: Body::Interaction {
                        src_sel: l.col(head_fields[1]),
                        dst_sel: l.col(head_fields[2]),
                        inverses,
                        counts,
                        src,
                        dst,
                    },
                });
            }
            _ => panic!("bad relations line {line}"),
        }
    }
    for r in &out {
        if let Body::Generated { subs, .. } = &r.body {
            assert_eq!(subs.len(), r.num_subrelations, "{}", r.name);
        }
    }
    assert_eq!(out.iter().map(|r| r.num_subrelations).sum::<usize>(), l.num_subrelations);
    assert!(out.iter().all(|r| r.partial_length <= l.max_partial_length));
    out
}

fn parse_expr(s: &str, l: &Layout, aliases: &HashMap<&str, usize>) -> Expr {
    let spaced = s.replace('(', "( ").replace(')', " )");
    let mut tokens = spaced.split_whitespace().peekable();
    let e = parse_tokens(&mut tokens, l, aliases);
    assert!(tokens.next().is_none(), "trailing tokens in {s}");
    e
}

fn parse_tokens<'a>(
    it: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
    l: &Layout,
    aliases: &HashMap<&str, usize>,
) -> Expr {
    let t = it.next().expect("unexpected end of expression");
    if t != "(" {
        return if let Some(c) = t.strip_prefix('#') {
            Expr::Const(c.parse::<Fr>().ok().expect("bad constant"))
        } else if let Some(a) = t.strip_prefix('$') {
            Expr::Alias(aliases[a])
        } else {
            Expr::Col(l.col(t))
        };
    }
    let op = it.next().unwrap();
    let a = Box::new(parse_tokens(it, l, aliases));
    let e = if op == "neg" {
        Expr::Neg(a)
    } else {
        let b = Box::new(parse_tokens(it, l, aliases));
        match op {
            "+" => Expr::Add(a, b),
            "-" => Expr::Sub(a, b),
            "*" => Expr::Mul(a, b),
            _ => panic!("bad op {op}"),
        }
    };
    assert_eq!(it.next(), Some(")"), "unclosed expression");
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_parse_and_agree_with_the_proof_layout() {
        let l = layout();
        let rels = relations();
        assert_eq!(l.num_all(), 3223);
        assert_eq!(rels.iter().filter(|r| matches!(r.body, Body::Handwritten)).count(), 1);
        // bb `AvmFlavor::COMPUTED_AVM_PROOF_LENGTH_IN_FIELDS`: 4 fields per commitment, 1 per scalar.
        let log_n = l.max_trace_log_size;
        let batched = l.max_partial_length + 1;
        let len = l.num_witness() * 4 + l.num_all() + log_n * batched + (log_n - 1) * 4 + log_n + 2 * 4;
        assert_eq!(len, l.proof_length);
        assert!(l.vk[..l.num_precomputed].iter().filter(|p| !p.is_zero()).all(|p| p.is_on_curve()));
    }
}
