//! bb's exact wasm multiply as a four-lane SIMD kernel (`VectorField`): operands transposed into
//! `u32x4` lanes per 29-bit limb (`QuadFp`), Karatsuba 5+4, eight Yuval reductions (the round
//! multiplier is the masked low limb, no inverse multiply) and one standard Montgomery round,
//! dividing by 2^261 — closed over the 2^261 stored domain, so packing is a pure transpose. Lanes
//! are independent; values are coarse `[0, 2p)`. Ported from the vendored ark-ff (2026-09-07).

use super::mont29::{to29, MASK29};
use core::arch::wasm32::*;

/// 2^-29 mod p, 29-bit limbs (the Yuval-reduction constant), for bn254 Fr and Fq.
pub const FR_RINV29: [u32; 9] = [
    0x18f05361, 0x12bb1fe, 0xf5d8135, 0x1e6275f6, 0x7e7a880, 0x10c6bf1f, 0x11f74a6c, 0x6fdaecb, 0x183227,
];
pub const FQ_RINV29: [u32; 9] = [
    0x17789a9f, 0x5ffc3dc, 0xd6bde42, 0x1cf152e3, 0x18eb055f, 0xed815e2, 0x16626d2, 0xb8bab0f, 0x6d7c4,
];

/// 4 field elements, transposed into u32x4 lanes per limb.
#[derive(Clone, Copy)]
pub struct QuadFp {
    pub limbs: [v128; 9],
}

/// 4x4 i32 lane transpose in 8 shuffles (bb `transpose_4x4_i32x4`).
#[inline(always)]
fn transpose4(r0: v128, r1: v128, r2: v128, r3: v128) -> (v128, v128, v128, v128) {
    let t0 = i32x4_shuffle::<0, 4, 1, 5>(r0, r1);
    let t1 = i32x4_shuffle::<2, 6, 3, 7>(r0, r1);
    let t2 = i32x4_shuffle::<0, 4, 1, 5>(r2, r3);
    let t3 = i32x4_shuffle::<2, 6, 3, 7>(r2, r3);
    (
        i32x4_shuffle::<0, 1, 4, 5>(t0, t2),
        i32x4_shuffle::<2, 3, 6, 7>(t0, t2),
        i32x4_shuffle::<0, 1, 4, 5>(t1, t3),
        i32x4_shuffle::<2, 3, 6, 7>(t1, t3),
    )
}

impl QuadFp {
    /// Pack four 4x64 values (the stored ark form, < 2^255) via bb VectorField's SIMD
    /// transpose: 8 loads, two 4x4 transposes, then each 29-bit limb assembled from the
    /// two straddling u32 chunks — no per-lane scalar radix conversion.
    #[allow(unsafe_code)]
    pub fn pack(e: &[[u64; 4]; 4]) -> QuadFp {
        let m = u32x4_splat(MASK29 as u32);
        unsafe {
            let p = e.as_ptr() as *const v128;
            let (i0, i1, i2, i3) = transpose4(
                v128_load(p),
                v128_load(p.add(2)),
                v128_load(p.add(4)),
                v128_load(p.add(6)),
            );
            let (i4, i5, i6, i7) = transpose4(
                v128_load(p.add(1)),
                v128_load(p.add(3)),
                v128_load(p.add(5)),
                v128_load(p.add(7)),
            );
            QuadFp {
                limbs: [
                    v128_and(i0, m),
                    v128_and(v128_or(u32x4_shr(i0, 29), i32x4_shl(i1, 3)), m),
                    v128_and(v128_or(u32x4_shr(i1, 26), i32x4_shl(i2, 6)), m),
                    v128_and(v128_or(u32x4_shr(i2, 23), i32x4_shl(i3, 9)), m),
                    v128_and(v128_or(u32x4_shr(i3, 20), i32x4_shl(i4, 12)), m),
                    v128_and(v128_or(u32x4_shr(i4, 17), i32x4_shl(i5, 15)), m),
                    v128_and(v128_or(u32x4_shr(i5, 14), i32x4_shl(i6, 18)), m),
                    v128_and(v128_or(u32x4_shr(i6, 11), i32x4_shl(i7, 21)), m),
                    u32x4_shr(i7, 8),
                ],
            }
        }
    }
    /// Unpack to canonical 4x64: one packed conditional `- p` (borrow chain + blend)
    /// canonicalizes all four coarse lanes, then u32 chunks reassemble and transpose back.
    #[allow(unsafe_code)]
    pub fn unpack(&self, modulus: &[u64; 4]) -> [[u64; 4]; 4] {
        let p29 = to29(modulus);
        let mask = u32x4_splat(MASK29 as u32);
        let mut d = [u32x4_splat(0); 9];
        let mut v = i32x4_sub(self.limbs[0], u32x4_splat(p29[0] as u32));
        let mut borrow = u32x4_shr(v, 31);
        d[0] = v128_and(v, mask);
        for k in 1..9 {
            v = i32x4_sub(i32x4_sub(self.limbs[k], u32x4_splat(p29[k] as u32)), borrow);
            borrow = u32x4_shr(v, 31);
            d[k] = v128_and(v, mask);
        }
        let keep_a = i32x4_eq(borrow, u32x4_splat(1));
        let l: [v128; 9] = core::array::from_fn(|k| v128_bitselect(self.limbs[k], d[k], keep_a));
        let o0 = v128_or(l[0], i32x4_shl(l[1], 29));
        let o1 = v128_or(u32x4_shr(l[1], 3), i32x4_shl(l[2], 26));
        let o2 = v128_or(u32x4_shr(l[2], 6), i32x4_shl(l[3], 23));
        let o3 = v128_or(u32x4_shr(l[3], 9), i32x4_shl(l[4], 20));
        let o4 = v128_or(u32x4_shr(l[4], 12), i32x4_shl(l[5], 17));
        let o5 = v128_or(u32x4_shr(l[5], 15), i32x4_shl(l[6], 14));
        let o6 = v128_or(u32x4_shr(l[6], 18), i32x4_shl(l[7], 11));
        let o7 = v128_or(u32x4_shr(l[7], 21), i32x4_shl(l[8], 8));
        let (f1l, f2l, f3l, f4l) = transpose4(o0, o1, o2, o3);
        let (f1h, f2h, f3h, f4h) = transpose4(o4, o5, o6, o7);
        let mut out = [[0u64; 4]; 4];
        unsafe {
            let p = out.as_mut_ptr() as *mut v128;
            v128_store(p, f1l);
            v128_store(p.add(1), f1h);
            v128_store(p.add(2), f2l);
            v128_store(p.add(3), f2h);
            v128_store(p.add(4), f3l);
            v128_store(p.add(5), f3h);
            v128_store(p.add(6), f4l);
            v128_store(p.add(7), f4h);
        }
        out
    }
}

/// Lanewise `a + b` on coarse [0, 2p) values, entirely in u32x4 (bb VectorField's TNM
/// trick, no 64-bit widening): raw carry-propagated add `r = a + b`, an independent chain
/// `t = r + (2^261 - 2p)` whose top-limb carry fires exactly when `a + b >= 2p`, and a
/// per-lane blend. Output back in [0, 2p).
pub fn add(a: &QuadFp, b: &QuadFp, c: &Consts) -> QuadFp {
    let mask = c.mask32;
    let mut r = [u32x4_splat(0); 9];
    let mut v = u32x4_add(a.limbs[0], b.limbs[0]);
    let mut carry = u32x4_shr(v, 29);
    r[0] = v128_and(v, mask);
    for k in 1..9 {
        // 29-bit limb + 29-bit limb + carry <= 2^30: fits u32, carry is bit 29.
        v = u32x4_add(u32x4_add(a.limbs[k], b.limbs[k]), carry);
        carry = u32x4_shr(v, 29);
        r[k] = v128_and(v, mask);
    }
    let mut t = [u32x4_splat(0); 9];
    v = u32x4_add(r[0], c.tnm[0]);
    carry = u32x4_shr(v, 29);
    t[0] = v128_and(v, mask);
    for k in 1..9 {
        v = u32x4_add(u32x4_add(r[k], c.tnm[k]), carry);
        carry = u32x4_shr(v, 29);
        t[k] = v128_and(v, mask);
    }
    // Top-limb carry set (per lane) => a + b >= 2p => t (= r - 2p mod 2^261) is the value.
    let pick_t = i32x4_eq(carry, u32x4_splat(1));
    let mut out = [u32x4_splat(0); 9];
    for k in 0..9 {
        out[k] = v128_bitselect(t[k], r[k], pick_t);
    }
    QuadFp { limbs: out }
}

/// Lanewise `a - b` on coarse values, entirely in u32x4: borrow-propagated raw subtract
/// (29-bit limbs keep bits 29..31 clear, so underflow shows in bit 31), a `+2p` chain, and
/// a per-lane blend on the final borrow. Output in [0, 2p).
pub fn sub(a: &QuadFp, b: &QuadFp, c: &Consts) -> QuadFp {
    let mask = c.mask32;
    let mut r = [u32x4_splat(0); 9];
    let mut v = i32x4_sub(a.limbs[0], b.limbs[0]);
    let mut borrow = u32x4_shr(v, 31);
    r[0] = v128_and(v, mask);
    for k in 1..9 {
        v = i32x4_sub(i32x4_sub(a.limbs[k], b.limbs[k]), borrow);
        borrow = u32x4_shr(v, 31);
        r[k] = v128_and(v, mask);
    }
    let pick_s = i32x4_eq(borrow, u32x4_splat(1));
    let mut s = [u32x4_splat(0); 9];
    v = u32x4_add(r[0], c.twop[0]);
    let mut carry = u32x4_shr(v, 29);
    s[0] = v128_and(v, mask);
    for k in 1..9 {
        v = u32x4_add(u32x4_add(r[k], c.twop[k]), carry);
        carry = u32x4_shr(v, 29);
        s[k] = v128_and(v, mask);
    }
    let mut out = [u32x4_splat(0); 9];
    for k in 0..9 {
        out[k] = v128_bitselect(s[k], r[k], pick_s);
    }
    QuadFp { limbs: out }
}

/// Splatted per-field constants, prepared once per loop instead of per multiply.
#[derive(Clone, Copy)]
pub struct Consts {
    pub ri: [v128; 9],
    pub p: [v128; 9],
    /// 2p as splatted 29-bit limbs (sub's blend chain).
    pub twop: [v128; 9],
    /// 2^261 - 2p as splatted 29-bit limbs (add's TNM chain).
    pub tnm: [v128; 9],
    pub invv: v128,
    pub mask64: v128,
    pub mask32: v128,
}

impl Consts {
    pub fn new(rinv29: &[u32; 9], p29: &[u64; 9], inv: u64) -> Self {
        let mut twop = [0u32; 9];
        let mut carry = 0u64;
        for k in 0..9 {
            let v = 2 * p29[k] + carry;
            twop[k] = (v & MASK29) as u32;
            carry = v >> 29;
        }
        let mut tnm = [0u32; 9];
        carry = 1;
        for k in 0..9 {
            let v = ((!(twop[k] as u64)) & MASK29) + carry;
            tnm[k] = (v & MASK29) as u32;
            carry = v >> 29;
        }
        Consts {
            ri: core::array::from_fn(|k| u32x4_splat(rinv29[k])),
            p: core::array::from_fn(|k| u32x4_splat(p29[k] as u32)),
            twop: core::array::from_fn(|k| u32x4_splat(twop[k])),
            tnm: core::array::from_fn(|k| u32x4_splat(tnm[k])),
            invv: u32x4_splat(inv as u32),
            mask64: u64x2_splat(MASK29),
            mask32: u32x4_splat(MASK29 as u32),
        }
    }
}

/// Per-lane `a * b / 2^261 mod p`, coarse in/out.
#[allow(clippy::too_many_lines)]
pub fn mont_mul(a: &QuadFp, b: &QuadFp, c: &Consts) -> QuadFp {
    let mask64 = c.mask64;
    let invv = c.invv;
    let ri0 = c.ri[0];
    let p0 = c.p[0];
    let ri1 = c.ri[1];
    let p1 = c.p[1];
    let ri2 = c.ri[2];
    let p2 = c.p[2];
    let ri3 = c.ri[3];
    let p3 = c.p[3];
    let ri4 = c.ri[4];
    let p4 = c.p[4];
    let ri5 = c.ri[5];
    let p5 = c.p[5];
    let ri6 = c.ri[6];
    let p6 = c.p[6];
    let ri7 = c.ri[7];
    let p7 = c.p[7];
    let ri8 = c.ri[8];
    let p8 = c.p[8];
    let a0 = a.limbs[0];
    let b0 = b.limbs[0];
    let a1 = a.limbs[1];
    let b1 = b.limbs[1];
    let a2 = a.limbs[2];
    let b2 = b.limbs[2];
    let a3 = a.limbs[3];
    let b3 = b.limbs[3];
    let a4 = a.limbs[4];
    let b4 = b.limbs[4];
    let a5 = a.limbs[5];
    let b5 = b.limbs[5];
    let a6 = a.limbs[6];
    let b6 = b.limbs[6];
    let a7 = a.limbs[7];
    let b7 = b.limbs[7];
    let a8 = a.limbs[8];
    let b8 = b.limbs[8];
    let sl0 = u32x4_add(a0, a5);
    let sr0 = u32x4_add(b0, b5);
    let sl1 = u32x4_add(a1, a6);
    let sr1 = u32x4_add(b1, b6);
    let sl2 = u32x4_add(a2, a7);
    let sr2 = u32x4_add(b2, b7);
    let sl3 = u32x4_add(a3, a8);
    let sr3 = u32x4_add(b3, b8);
    let sl4 = a4;
    let sr4 = b4;
    let pl0_l = u64x2_extmul_low_u32x4(a0, b0);
    let pl0_h = u64x2_extmul_high_u32x4(a0, b0);
    let pl1_l = u64x2_add(u64x2_extmul_low_u32x4(a0, b1), u64x2_extmul_low_u32x4(a1, b0));
    let pl1_h = u64x2_add(u64x2_extmul_high_u32x4(a0, b1), u64x2_extmul_high_u32x4(a1, b0));
    let pl2_l = u64x2_add(
        u64x2_add(u64x2_extmul_low_u32x4(a0, b2), u64x2_extmul_low_u32x4(a1, b1)),
        u64x2_extmul_low_u32x4(a2, b0),
    );
    let pl2_h = u64x2_add(
        u64x2_add(u64x2_extmul_high_u32x4(a0, b2), u64x2_extmul_high_u32x4(a1, b1)),
        u64x2_extmul_high_u32x4(a2, b0),
    );
    let pl3_l = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a0, b3), u64x2_extmul_low_u32x4(a1, b2)),
            u64x2_extmul_low_u32x4(a2, b1),
        ),
        u64x2_extmul_low_u32x4(a3, b0),
    );
    let pl3_h = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a0, b3), u64x2_extmul_high_u32x4(a1, b2)),
            u64x2_extmul_high_u32x4(a2, b1),
        ),
        u64x2_extmul_high_u32x4(a3, b0),
    );
    let pl4_l = u64x2_add(
        u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(a0, b4), u64x2_extmul_low_u32x4(a1, b3)),
                u64x2_extmul_low_u32x4(a2, b2),
            ),
            u64x2_extmul_low_u32x4(a3, b1),
        ),
        u64x2_extmul_low_u32x4(a4, b0),
    );
    let pl4_h = u64x2_add(
        u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(a0, b4), u64x2_extmul_high_u32x4(a1, b3)),
                u64x2_extmul_high_u32x4(a2, b2),
            ),
            u64x2_extmul_high_u32x4(a3, b1),
        ),
        u64x2_extmul_high_u32x4(a4, b0),
    );
    let pl5_l = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a1, b4), u64x2_extmul_low_u32x4(a2, b3)),
            u64x2_extmul_low_u32x4(a3, b2),
        ),
        u64x2_extmul_low_u32x4(a4, b1),
    );
    let pl5_h = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a1, b4), u64x2_extmul_high_u32x4(a2, b3)),
            u64x2_extmul_high_u32x4(a3, b2),
        ),
        u64x2_extmul_high_u32x4(a4, b1),
    );
    let pl6_l = u64x2_add(
        u64x2_add(u64x2_extmul_low_u32x4(a2, b4), u64x2_extmul_low_u32x4(a3, b3)),
        u64x2_extmul_low_u32x4(a4, b2),
    );
    let pl6_h = u64x2_add(
        u64x2_add(u64x2_extmul_high_u32x4(a2, b4), u64x2_extmul_high_u32x4(a3, b3)),
        u64x2_extmul_high_u32x4(a4, b2),
    );
    let pl7_l = u64x2_add(u64x2_extmul_low_u32x4(a3, b4), u64x2_extmul_low_u32x4(a4, b3));
    let pl7_h = u64x2_add(u64x2_extmul_high_u32x4(a3, b4), u64x2_extmul_high_u32x4(a4, b3));
    let pl8_l = u64x2_extmul_low_u32x4(a4, b4);
    let pl8_h = u64x2_extmul_high_u32x4(a4, b4);
    let ph0_l = u64x2_extmul_low_u32x4(a5, b5);
    let ph0_h = u64x2_extmul_high_u32x4(a5, b5);
    let ph1_l = u64x2_add(u64x2_extmul_low_u32x4(a5, b6), u64x2_extmul_low_u32x4(a6, b5));
    let ph1_h = u64x2_add(u64x2_extmul_high_u32x4(a5, b6), u64x2_extmul_high_u32x4(a6, b5));
    let ph2_l = u64x2_add(
        u64x2_add(u64x2_extmul_low_u32x4(a5, b7), u64x2_extmul_low_u32x4(a6, b6)),
        u64x2_extmul_low_u32x4(a7, b5),
    );
    let ph2_h = u64x2_add(
        u64x2_add(u64x2_extmul_high_u32x4(a5, b7), u64x2_extmul_high_u32x4(a6, b6)),
        u64x2_extmul_high_u32x4(a7, b5),
    );
    let ph3_l = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a5, b8), u64x2_extmul_low_u32x4(a6, b7)),
            u64x2_extmul_low_u32x4(a7, b6),
        ),
        u64x2_extmul_low_u32x4(a8, b5),
    );
    let ph3_h = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a5, b8), u64x2_extmul_high_u32x4(a6, b7)),
            u64x2_extmul_high_u32x4(a7, b6),
        ),
        u64x2_extmul_high_u32x4(a8, b5),
    );
    let ph4_l = u64x2_add(
        u64x2_add(u64x2_extmul_low_u32x4(a6, b8), u64x2_extmul_low_u32x4(a7, b7)),
        u64x2_extmul_low_u32x4(a8, b6),
    );
    let ph4_h = u64x2_add(
        u64x2_add(u64x2_extmul_high_u32x4(a6, b8), u64x2_extmul_high_u32x4(a7, b7)),
        u64x2_extmul_high_u32x4(a8, b6),
    );
    let ph5_l = u64x2_add(u64x2_extmul_low_u32x4(a7, b8), u64x2_extmul_low_u32x4(a8, b7));
    let ph5_h = u64x2_add(u64x2_extmul_high_u32x4(a7, b8), u64x2_extmul_high_u32x4(a8, b7));
    let ph6_l = u64x2_extmul_low_u32x4(a8, b8);
    let ph6_h = u64x2_extmul_high_u32x4(a8, b8);
    let pc0_l = u64x2_extmul_low_u32x4(sl0, sr0);
    let pc0_h = u64x2_extmul_high_u32x4(sl0, sr0);
    let pc1_l = u64x2_add(u64x2_extmul_low_u32x4(sl0, sr1), u64x2_extmul_low_u32x4(sl1, sr0));
    let pc1_h = u64x2_add(u64x2_extmul_high_u32x4(sl0, sr1), u64x2_extmul_high_u32x4(sl1, sr0));
    let pc2_l = u64x2_add(
        u64x2_add(u64x2_extmul_low_u32x4(sl0, sr2), u64x2_extmul_low_u32x4(sl1, sr1)),
        u64x2_extmul_low_u32x4(sl2, sr0),
    );
    let pc2_h = u64x2_add(
        u64x2_add(u64x2_extmul_high_u32x4(sl0, sr2), u64x2_extmul_high_u32x4(sl1, sr1)),
        u64x2_extmul_high_u32x4(sl2, sr0),
    );
    let pc3_l = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(sl0, sr3), u64x2_extmul_low_u32x4(sl1, sr2)),
            u64x2_extmul_low_u32x4(sl2, sr1),
        ),
        u64x2_extmul_low_u32x4(sl3, sr0),
    );
    let pc3_h = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(sl0, sr3), u64x2_extmul_high_u32x4(sl1, sr2)),
            u64x2_extmul_high_u32x4(sl2, sr1),
        ),
        u64x2_extmul_high_u32x4(sl3, sr0),
    );
    let pc4_l = u64x2_add(
        u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(sl0, sr4), u64x2_extmul_low_u32x4(sl1, sr3)),
                u64x2_extmul_low_u32x4(sl2, sr2),
            ),
            u64x2_extmul_low_u32x4(sl3, sr1),
        ),
        u64x2_extmul_low_u32x4(sl4, sr0),
    );
    let pc4_h = u64x2_add(
        u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(sl0, sr4), u64x2_extmul_high_u32x4(sl1, sr3)),
                u64x2_extmul_high_u32x4(sl2, sr2),
            ),
            u64x2_extmul_high_u32x4(sl3, sr1),
        ),
        u64x2_extmul_high_u32x4(sl4, sr0),
    );
    let pc5_l = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(sl1, sr4), u64x2_extmul_low_u32x4(sl2, sr3)),
            u64x2_extmul_low_u32x4(sl3, sr2),
        ),
        u64x2_extmul_low_u32x4(sl4, sr1),
    );
    let pc5_h = u64x2_add(
        u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(sl1, sr4), u64x2_extmul_high_u32x4(sl2, sr3)),
            u64x2_extmul_high_u32x4(sl3, sr2),
        ),
        u64x2_extmul_high_u32x4(sl4, sr1),
    );
    let pc6_l = u64x2_add(
        u64x2_add(u64x2_extmul_low_u32x4(sl2, sr4), u64x2_extmul_low_u32x4(sl3, sr3)),
        u64x2_extmul_low_u32x4(sl4, sr2),
    );
    let pc6_h = u64x2_add(
        u64x2_add(u64x2_extmul_high_u32x4(sl2, sr4), u64x2_extmul_high_u32x4(sl3, sr3)),
        u64x2_extmul_high_u32x4(sl4, sr2),
    );
    let pc7_l = u64x2_add(u64x2_extmul_low_u32x4(sl3, sr4), u64x2_extmul_low_u32x4(sl4, sr3));
    let pc7_h = u64x2_add(u64x2_extmul_high_u32x4(sl3, sr4), u64x2_extmul_high_u32x4(sl4, sr3));
    let pc8_l = u64x2_extmul_low_u32x4(sl4, sr4);
    let pc8_h = u64x2_extmul_high_u32x4(sl4, sr4);
    let t0_l = pl0_l;
    let mut t1_l = pl1_l;
    let mut t2_l = pl2_l;
    let mut t3_l = pl3_l;
    let mut t4_l = pl4_l;
    let m0_l = u64x2_sub(u64x2_sub(pc0_l, pl0_l), ph0_l);
    let m1_l = u64x2_sub(u64x2_sub(pc1_l, pl1_l), ph1_l);
    let m2_l = u64x2_sub(u64x2_sub(pc2_l, pl2_l), ph2_l);
    let m3_l = u64x2_sub(u64x2_sub(pc3_l, pl3_l), ph3_l);
    let m4_l = u64x2_sub(u64x2_sub(pc4_l, pl4_l), ph4_l);
    let m5_l = u64x2_sub(u64x2_sub(pc5_l, pl5_l), ph5_l);
    let m6_l = u64x2_sub(u64x2_sub(pc6_l, pl6_l), ph6_l);
    let m7_l = u64x2_sub(pc7_l, pl7_l);
    let m8_l = u64x2_sub(pc8_l, pl8_l);
    let mut t5_l = u64x2_add(pl5_l, m0_l);
    let mut t6_l = u64x2_add(pl6_l, m1_l);
    let mut t7_l = u64x2_add(pl7_l, m2_l);
    let mut t8_l = u64x2_add(pl8_l, m3_l);
    let mut t9_l = m4_l;
    let mut t10_l = u64x2_add(m5_l, ph0_l);
    let mut t11_l = u64x2_add(m6_l, ph1_l);
    let mut t12_l = u64x2_add(m7_l, ph2_l);
    let mut t13_l = u64x2_add(m8_l, ph3_l);
    let mut t14_l = ph4_l;
    let mut t15_l = ph5_l;
    let mut t16_l = ph6_l;
    let t0_h = pl0_h;
    let mut t1_h = pl1_h;
    let mut t2_h = pl2_h;
    let mut t3_h = pl3_h;
    let mut t4_h = pl4_h;
    let m0_h = u64x2_sub(u64x2_sub(pc0_h, pl0_h), ph0_h);
    let m1_h = u64x2_sub(u64x2_sub(pc1_h, pl1_h), ph1_h);
    let m2_h = u64x2_sub(u64x2_sub(pc2_h, pl2_h), ph2_h);
    let m3_h = u64x2_sub(u64x2_sub(pc3_h, pl3_h), ph3_h);
    let m4_h = u64x2_sub(u64x2_sub(pc4_h, pl4_h), ph4_h);
    let m5_h = u64x2_sub(u64x2_sub(pc5_h, pl5_h), ph5_h);
    let m6_h = u64x2_sub(u64x2_sub(pc6_h, pl6_h), ph6_h);
    let m7_h = u64x2_sub(pc7_h, pl7_h);
    let m8_h = u64x2_sub(pc8_h, pl8_h);
    let mut t5_h = u64x2_add(pl5_h, m0_h);
    let mut t6_h = u64x2_add(pl6_h, m1_h);
    let mut t7_h = u64x2_add(pl7_h, m2_h);
    let mut t8_h = u64x2_add(pl8_h, m3_h);
    let mut t9_h = m4_h;
    let mut t10_h = u64x2_add(m5_h, ph0_h);
    let mut t11_h = u64x2_add(m6_h, ph1_h);
    let mut t12_h = u64x2_add(m7_h, ph2_h);
    let mut t13_h = u64x2_add(m8_h, ph3_h);
    let mut t14_h = ph4_h;
    let mut t15_h = ph5_h;
    let mut t16_h = ph6_h;
    let kml = v128_and(t0_l, mask64);
    let kmh = v128_and(t0_h, mask64);
    let k0 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t1_l = u64x2_add(t1_l, u64x2_shr(t0_l, 29));
    t1_h = u64x2_add(t1_h, u64x2_shr(t0_h, 29));
    t1_l = u64x2_add(t1_l, u64x2_extmul_low_u32x4(k0, ri0));
    t1_h = u64x2_add(t1_h, u64x2_extmul_high_u32x4(k0, ri0));
    t2_l = u64x2_add(t2_l, u64x2_extmul_low_u32x4(k0, ri1));
    t2_h = u64x2_add(t2_h, u64x2_extmul_high_u32x4(k0, ri1));
    t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k0, ri2));
    t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k0, ri2));
    t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k0, ri3));
    t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k0, ri3));
    t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k0, ri4));
    t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k0, ri4));
    t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k0, ri5));
    t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k0, ri5));
    t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k0, ri6));
    t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k0, ri6));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k0, ri7));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k0, ri7));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k0, ri8));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k0, ri8));
    let kml = v128_and(t1_l, mask64);
    let kmh = v128_and(t1_h, mask64);
    let k1 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t2_l = u64x2_add(t2_l, u64x2_shr(t1_l, 29));
    t2_h = u64x2_add(t2_h, u64x2_shr(t1_h, 29));
    t2_l = u64x2_add(t2_l, u64x2_extmul_low_u32x4(k1, ri0));
    t2_h = u64x2_add(t2_h, u64x2_extmul_high_u32x4(k1, ri0));
    t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k1, ri1));
    t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k1, ri1));
    t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k1, ri2));
    t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k1, ri2));
    t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k1, ri3));
    t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k1, ri3));
    t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k1, ri4));
    t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k1, ri4));
    t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k1, ri5));
    t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k1, ri5));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k1, ri6));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k1, ri6));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k1, ri7));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k1, ri7));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k1, ri8));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k1, ri8));
    let kml = v128_and(t2_l, mask64);
    let kmh = v128_and(t2_h, mask64);
    let k2 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t3_l = u64x2_add(t3_l, u64x2_shr(t2_l, 29));
    t3_h = u64x2_add(t3_h, u64x2_shr(t2_h, 29));
    t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k2, ri0));
    t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k2, ri0));
    t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k2, ri1));
    t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k2, ri1));
    t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k2, ri2));
    t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k2, ri2));
    t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k2, ri3));
    t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k2, ri3));
    t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k2, ri4));
    t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k2, ri4));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k2, ri5));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k2, ri5));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k2, ri6));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k2, ri6));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k2, ri7));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k2, ri7));
    t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k2, ri8));
    t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k2, ri8));
    let kml = v128_and(t3_l, mask64);
    let kmh = v128_and(t3_h, mask64);
    let k3 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t4_l = u64x2_add(t4_l, u64x2_shr(t3_l, 29));
    t4_h = u64x2_add(t4_h, u64x2_shr(t3_h, 29));
    t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k3, ri0));
    t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k3, ri0));
    t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k3, ri1));
    t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k3, ri1));
    t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k3, ri2));
    t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k3, ri2));
    t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k3, ri3));
    t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k3, ri3));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k3, ri4));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k3, ri4));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k3, ri5));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k3, ri5));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k3, ri6));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k3, ri6));
    t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k3, ri7));
    t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k3, ri7));
    t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k3, ri8));
    t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k3, ri8));
    let kml = v128_and(t4_l, mask64);
    let kmh = v128_and(t4_h, mask64);
    let k4 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t5_l = u64x2_add(t5_l, u64x2_shr(t4_l, 29));
    t5_h = u64x2_add(t5_h, u64x2_shr(t4_h, 29));
    t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k4, ri0));
    t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k4, ri0));
    t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k4, ri1));
    t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k4, ri1));
    t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k4, ri2));
    t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k4, ri2));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k4, ri3));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k4, ri3));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k4, ri4));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k4, ri4));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k4, ri5));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k4, ri5));
    t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k4, ri6));
    t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k4, ri6));
    t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k4, ri7));
    t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k4, ri7));
    t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k4, ri8));
    t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k4, ri8));
    let kml = v128_and(t5_l, mask64);
    let kmh = v128_and(t5_h, mask64);
    let k5 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t6_l = u64x2_add(t6_l, u64x2_shr(t5_l, 29));
    t6_h = u64x2_add(t6_h, u64x2_shr(t5_h, 29));
    t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k5, ri0));
    t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k5, ri0));
    t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k5, ri1));
    t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k5, ri1));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k5, ri2));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k5, ri2));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k5, ri3));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k5, ri3));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k5, ri4));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k5, ri4));
    t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k5, ri5));
    t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k5, ri5));
    t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k5, ri6));
    t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k5, ri6));
    t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k5, ri7));
    t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k5, ri7));
    t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k5, ri8));
    t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k5, ri8));
    let kml = v128_and(t6_l, mask64);
    let kmh = v128_and(t6_h, mask64);
    let k6 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t7_l = u64x2_add(t7_l, u64x2_shr(t6_l, 29));
    t7_h = u64x2_add(t7_h, u64x2_shr(t6_h, 29));
    t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k6, ri0));
    t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k6, ri0));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k6, ri1));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k6, ri1));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k6, ri2));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k6, ri2));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k6, ri3));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k6, ri3));
    t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k6, ri4));
    t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k6, ri4));
    t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k6, ri5));
    t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k6, ri5));
    t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k6, ri6));
    t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k6, ri6));
    t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k6, ri7));
    t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k6, ri7));
    t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k6, ri8));
    t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k6, ri8));
    let kml = v128_and(t7_l, mask64);
    let kmh = v128_and(t7_h, mask64);
    let k7 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
    t8_l = u64x2_add(t8_l, u64x2_shr(t7_l, 29));
    t8_h = u64x2_add(t8_h, u64x2_shr(t7_h, 29));
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k7, ri0));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k7, ri0));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k7, ri1));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k7, ri1));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k7, ri2));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k7, ri2));
    t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k7, ri3));
    t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k7, ri3));
    t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k7, ri4));
    t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k7, ri4));
    t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k7, ri5));
    t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k7, ri5));
    t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k7, ri6));
    t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k7, ri6));
    t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k7, ri7));
    t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k7, ri7));
    t16_l = u64x2_add(t16_l, u64x2_extmul_low_u32x4(k7, ri8));
    t16_h = u64x2_add(t16_h, u64x2_extmul_high_u32x4(k7, ri8));
    let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(t8_l, mask64), v128_and(t8_h, mask64));
    let kl = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
    let kh = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
    let k8 = u32x4_shuffle::<0, 2, 4, 6>(kl, kh);
    t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k8, p0));
    t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k8, p0));
    t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k8, p1));
    t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k8, p1));
    t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k8, p2));
    t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k8, p2));
    t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k8, p3));
    t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k8, p3));
    t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k8, p4));
    t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k8, p4));
    t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k8, p5));
    t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k8, p5));
    t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k8, p6));
    t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k8, p6));
    t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k8, p7));
    t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k8, p7));
    t16_l = u64x2_add(t16_l, u64x2_extmul_low_u32x4(k8, p8));
    t16_h = u64x2_add(t16_h, u64x2_extmul_high_u32x4(k8, p8));
    t9_l = u64x2_add(t9_l, u64x2_shr(t8_l, 29));
    t9_h = u64x2_add(t9_h, u64x2_shr(t8_h, 29));
    let mut t17_l = u64x2(0, 0);
    let mut t17_h = u64x2(0, 0);
    t10_l = u64x2_add(t10_l, u64x2_shr(t9_l, 29));
    t9_l = v128_and(t9_l, mask64);
    t10_h = u64x2_add(t10_h, u64x2_shr(t9_h, 29));
    t9_h = v128_and(t9_h, mask64);
    t11_l = u64x2_add(t11_l, u64x2_shr(t10_l, 29));
    t10_l = v128_and(t10_l, mask64);
    t11_h = u64x2_add(t11_h, u64x2_shr(t10_h, 29));
    t10_h = v128_and(t10_h, mask64);
    t12_l = u64x2_add(t12_l, u64x2_shr(t11_l, 29));
    t11_l = v128_and(t11_l, mask64);
    t12_h = u64x2_add(t12_h, u64x2_shr(t11_h, 29));
    t11_h = v128_and(t11_h, mask64);
    t13_l = u64x2_add(t13_l, u64x2_shr(t12_l, 29));
    t12_l = v128_and(t12_l, mask64);
    t13_h = u64x2_add(t13_h, u64x2_shr(t12_h, 29));
    t12_h = v128_and(t12_h, mask64);
    t14_l = u64x2_add(t14_l, u64x2_shr(t13_l, 29));
    t13_l = v128_and(t13_l, mask64);
    t14_h = u64x2_add(t14_h, u64x2_shr(t13_h, 29));
    t13_h = v128_and(t13_h, mask64);
    t15_l = u64x2_add(t15_l, u64x2_shr(t14_l, 29));
    t14_l = v128_and(t14_l, mask64);
    t15_h = u64x2_add(t15_h, u64x2_shr(t14_h, 29));
    t14_h = v128_and(t14_h, mask64);
    t16_l = u64x2_add(t16_l, u64x2_shr(t15_l, 29));
    t15_l = v128_and(t15_l, mask64);
    t16_h = u64x2_add(t16_h, u64x2_shr(t15_h, 29));
    t15_h = v128_and(t15_h, mask64);
    t17_l = u64x2_add(t17_l, u64x2_shr(t16_l, 29));
    t16_l = v128_and(t16_l, mask64);
    t17_h = u64x2_add(t17_h, u64x2_shr(t16_h, 29));
    t16_h = v128_and(t16_h, mask64);
    QuadFp {
        limbs: [
            u32x4_shuffle::<0, 2, 4, 6>(t9_l, t9_h),
            u32x4_shuffle::<0, 2, 4, 6>(t10_l, t10_h),
            u32x4_shuffle::<0, 2, 4, 6>(t11_l, t11_h),
            u32x4_shuffle::<0, 2, 4, 6>(t12_l, t12_h),
            u32x4_shuffle::<0, 2, 4, 6>(t13_l, t13_h),
            u32x4_shuffle::<0, 2, 4, 6>(t14_l, t14_h),
            u32x4_shuffle::<0, 2, 4, 6>(t15_l, t15_h),
            u32x4_shuffle::<0, 2, 4, 6>(t16_l, t16_h),
            u32x4_shuffle::<0, 2, 4, 6>(t17_l, t17_h),
        ],
    }
}
