//! Interpreter for the circuit scripts in `tests/data/scripts/` (mirrors `run_script` in the bb-side
//! `bbref_dump.test.cpp`): one builder call per line.
use bb_ref::base::field::{from_bytes_be, FieldLike};
use bb_ref::base::{Fq, Fr, G1Affine};
use bb_ref::circuit::builder::{AddQuad, MulQuad};
use bb_ref::circuit::mega::BilinearBatchedEqGate;
use bb_ref::stdlib::memory::{RamTable, RomTable};
use bb_ref::stdlib::{poseidon2, Ctx, FieldT};

fn parse_field<F: ark_ff::PrimeField<BigInt = bb_ref::base::U256>>(s: &str) -> F {
    if let Some(h) = s.strip_prefix("0x") {
        let mut bytes = vec![0u8; 64 - h.len()];
        bytes.extend_from_slice(h.as_bytes());
        return from_bytes_be(&hex::decode(String::from_utf8(bytes).unwrap()).unwrap());
    }
    let (neg, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s),
    };
    let v = F::from(digits.parse::<u64>().unwrap());
    if neg {
        -v
    } else {
        v
    }
}

pub fn run_script(ctx: &Ctx, text: &str) {
    let mut roms: Vec<RomTable> = vec![];
    let mut rams: Vec<RamTable> = vec![];
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.is_empty() || t[0].starts_with('#') {
            continue;
        }
        let u = |i: usize| t[i].parse::<u32>().unwrap();
        let f = |i: usize| parse_field::<Fr>(t[i]);
        let q = |i: usize| parse_field::<Fq>(t[i]);
        let w = |i: usize| FieldT::from_witness_index(ctx, u(i));
        let point = || G1Affine::new_unchecked(q(1), q(2));
        let mut b = ctx.borrow_mut();
        match t[0] {
            "var" => {
                b.add_variable(f(1));
            }
            "pub" => {
                b.add_public_variable(f(1));
            }
            "add_gate" => b.create_big_add_gate(
                AddQuad {
                    a: u(1),
                    b: u(2),
                    c: u(3),
                    d: u(4),
                    a_scaling: f(5),
                    b_scaling: f(6),
                    c_scaling: f(7),
                    d_scaling: f(8),
                    const_scaling: f(9),
                },
                t.get(10) == Some(&"1"),
            ),
            "mul_gate" => b.create_big_mul_add_gate(
                &MulQuad {
                    a: u(1),
                    b: u(2),
                    c: u(3),
                    d: u(4),
                    mul_scaling: f(5),
                    a_scaling: f(6),
                    b_scaling: f(7),
                    c_scaling: f(8),
                    d_scaling: f(9),
                    const_scaling: f(10),
                },
                false,
            ),
            "bool" => b.create_bool_gate(u(1)),
            "range" => b.create_dyadic_range_constraint(u(1), u(2) as u64),
            "bilinear" | "batched_eq" => {
                let bilinear = t[0] == "bilinear";
                b.create_bilinear_batched_eq_gate(&BilinearBatchedEqGate {
                    bilinear,
                    a: u(1),
                    b: u(2),
                    c: u(3),
                    d: u(4),
                    q_l: f(5),
                    q_r: f(6),
                    q_o: f(7),
                    q_4: f(8),
                    q_c: f(9),
                    q_m: f(10),
                    q_5: if bilinear { f(11) } else { Fr::zero() },
                })
            }
            "calldata" => b.add_public_calldata(u(1) as usize, u(2)),
            "retdata" => b.add_public_return_data(u(1)),
            "read_calldata" => {
                b.read_calldata(u(1) as usize, u(2));
            }
            "read_retdata" => {
                b.read_return_data(u(1));
            }
            "ecc_add" => {
                b.queue_ecc_add_accum(point());
            }
            "ecc_mul" => {
                b.queue_ecc_mul_accum(point(), f(3));
            }
            "ecc_eq" => {
                b.queue_ecc_eq();
            }
            "ecc_no_op" => {
                b.queue_ecc_no_op();
            }
            "poseidon2" => {
                drop(b);
                let state = [w(1), w(2), w(3), w(4)];
                poseidon2::permutation(ctx, &state);
            }
            "rom" | "ram" => {
                drop(b);
                let entries: Vec<FieldT> = (2..2 + u(1) as usize).map(w).collect();
                if t[0] == "rom" {
                    roms.push(RomTable::new(ctx, entries));
                } else {
                    rams.push(RamTable::new(ctx, entries));
                }
            }
            "rom_read" => {
                drop(b);
                roms[u(1) as usize].read(&w(2));
            }
            "ram_read" => {
                drop(b);
                rams[u(1) as usize].read(&w(2));
            }
            "ram_write" => {
                drop(b);
                rams[u(1) as usize].write(&w(2), &w(3));
            }
            "default_io" => {
                drop(b);
                bb_ref::acir::lower::add_default_pairing_points(&mut ctx.borrow_mut());
            }
            other => panic!("unknown script command {other}"),
        }
    }
}
