//! Radix-2^29 Montgomery arithmetic (R = 2^261) — the wasm field core. wasm has no widening
//! 64x64 multiply, so 4x64-bit Montgomery decomposes into carry-heavy 32-bit pieces (ark's
//! generic mul measures 121ns under wasmtime against 20ns native); with 29-bit limbs every
//! product is at most 58 bits and fits a single `i64.mul`, no intra-product carries. Same
//! design as bb's wasm field (its 9x29 modulus constants match [`FR_P`] limb for limb).
//!
//! This is the scalar (one element per call) core; values are canonical-form Montgomery
//! residues `a * 2^261 mod p` in nine 29-bit limbs. SIMD quad-packing layers on top later.

pub const MASK: u64 = (1 << 29) - 1;

pub const FR_P: [u32; 9] = [
    0x10000001, 0x1f0fac9f, 0xe5c2450, 0x7d090f3, 0x1585d283, 0x2db40c0, 0xa6e141, 0xe5c2634, 0x30644e,
];
pub const FR_INV: u64 = 0xfffffff;
pub const FR_R2: [u32; 9] = [
    0x5b69bd4, 0x6170a5a, 0x20cddce, 0x1db6310b, 0xe54d0ff, 0x1cf855e3, 0x1c15e103, 0x7d09161, 0xa054a,
];

pub const FQ_P: [u32; 9] = [
    0x187cfd47, 0x10460b6, 0x1c72a34f, 0x2d522d0, 0x1585d978, 0x2db40c0, 0xa6e141, 0xe5c2634, 0x30644e,
];
pub const FQ_INV: u64 = 0x4866389;
pub const FQ_R2: [u32; 9] = [
    0x59bac10, 0xd1503a3, 0x18016b8, 0x10ab0ca8, 0x2632639, 0x2c0169f, 0x169bfd53, 0x11869d4c, 0x2a11a6,
];

/// Montgomery product `a * b / 2^261 mod p`. Inputs and output in [0, 2p); the schoolbook
/// column sums stay under 2^63, so the whole product accumulates carry-free in u64 columns and
/// the nine reduction rounds each retire one low limb.
#[inline]
pub fn mont_mul(a: &[u32; 9], b: &[u32; 9], p: &[u32; 9], inv: u64) -> [u32; 9] {
    let mut t = [0u64; 18];
    for i in 0..9 {
        let ai = a[i] as u64;
        for j in 0..9 {
            t[i + j] += ai * b[j] as u64;
        }
    }
    for r in 0..9 {
        let k = t[r].wrapping_mul(inv) & MASK;
        for j in 0..9 {
            t[r + j] += k * p[j] as u64;
        }
        t[r + 1] += t[r] >> 29;
    }
    let mut out = [0u32; 9];
    let mut carry = 0u64;
    for j in 0..9 {
        let v = t[9 + j] + carry;
        out[j] = (v & MASK) as u32;
        carry = v >> 29;
    }
    debug_assert_eq!(carry, 0);
    out
}

/// Fully-unrolled variant of [`mont_mul`]: straight-line code, all intermediates in locals.
#[inline]
#[allow(clippy::too_many_lines)]
pub fn mont_mul_u(a: &[u32; 9], b: &[u32; 9], p: &[u32; 9], inv: u64) -> [u32; 9] {
    let a0 = a[0] as u64;
    let a1 = a[1] as u64;
    let a2 = a[2] as u64;
    let a3 = a[3] as u64;
    let a4 = a[4] as u64;
    let a5 = a[5] as u64;
    let a6 = a[6] as u64;
    let a7 = a[7] as u64;
    let a8 = a[8] as u64;
    let b0 = b[0] as u64;
    let b1 = b[1] as u64;
    let b2 = b[2] as u64;
    let b3 = b[3] as u64;
    let b4 = b[4] as u64;
    let b5 = b[5] as u64;
    let b6 = b[6] as u64;
    let b7 = b[7] as u64;
    let b8 = b[8] as u64;
    let p0 = p[0] as u64;
    let p1 = p[1] as u64;
    let p2 = p[2] as u64;
    let p3 = p[3] as u64;
    let p4 = p[4] as u64;
    let p5 = p[5] as u64;
    let p6 = p[6] as u64;
    let p7 = p[7] as u64;
    let p8 = p[8] as u64;
    let mut t0: u64 = a0 * b0;
    let mut t1: u64 = a0 * b1 + a1 * b0;
    let mut t2: u64 = a0 * b2 + a1 * b1 + a2 * b0;
    let mut t3: u64 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    let mut t4: u64 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    let mut t5: u64 = a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    let mut t6: u64 = a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    let mut t7: u64 = a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    let mut t8: u64 = a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
    let mut t9: u64 = a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1;
    let mut t10: u64 = a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2;
    let mut t11: u64 = a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3;
    let mut t12: u64 = a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4;
    let mut t13: u64 = a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5;
    let mut t14: u64 = a6 * b8 + a7 * b7 + a8 * b6;
    let mut t15: u64 = a7 * b8 + a8 * b7;
    let mut t16: u64 = a8 * b8;
    let mut t17: u64 = 0;
    let k0 = t0.wrapping_mul(inv) & MASK;
    t0 = t0.wrapping_add(k0 * p0);
    t1 = t1.wrapping_add(k0 * p1);
    t2 = t2.wrapping_add(k0 * p2);
    t3 = t3.wrapping_add(k0 * p3);
    t4 = t4.wrapping_add(k0 * p4);
    t5 = t5.wrapping_add(k0 * p5);
    t6 = t6.wrapping_add(k0 * p6);
    t7 = t7.wrapping_add(k0 * p7);
    t8 = t8.wrapping_add(k0 * p8);
    t1 = t1.wrapping_add(t0 >> 29);
    let k1 = t1.wrapping_mul(inv) & MASK;
    t1 = t1.wrapping_add(k1 * p0);
    t2 = t2.wrapping_add(k1 * p1);
    t3 = t3.wrapping_add(k1 * p2);
    t4 = t4.wrapping_add(k1 * p3);
    t5 = t5.wrapping_add(k1 * p4);
    t6 = t6.wrapping_add(k1 * p5);
    t7 = t7.wrapping_add(k1 * p6);
    t8 = t8.wrapping_add(k1 * p7);
    t9 = t9.wrapping_add(k1 * p8);
    t2 = t2.wrapping_add(t1 >> 29);
    let k2 = t2.wrapping_mul(inv) & MASK;
    t2 = t2.wrapping_add(k2 * p0);
    t3 = t3.wrapping_add(k2 * p1);
    t4 = t4.wrapping_add(k2 * p2);
    t5 = t5.wrapping_add(k2 * p3);
    t6 = t6.wrapping_add(k2 * p4);
    t7 = t7.wrapping_add(k2 * p5);
    t8 = t8.wrapping_add(k2 * p6);
    t9 = t9.wrapping_add(k2 * p7);
    t10 = t10.wrapping_add(k2 * p8);
    t3 = t3.wrapping_add(t2 >> 29);
    let k3 = t3.wrapping_mul(inv) & MASK;
    t3 = t3.wrapping_add(k3 * p0);
    t4 = t4.wrapping_add(k3 * p1);
    t5 = t5.wrapping_add(k3 * p2);
    t6 = t6.wrapping_add(k3 * p3);
    t7 = t7.wrapping_add(k3 * p4);
    t8 = t8.wrapping_add(k3 * p5);
    t9 = t9.wrapping_add(k3 * p6);
    t10 = t10.wrapping_add(k3 * p7);
    t11 = t11.wrapping_add(k3 * p8);
    t4 = t4.wrapping_add(t3 >> 29);
    let k4 = t4.wrapping_mul(inv) & MASK;
    t4 = t4.wrapping_add(k4 * p0);
    t5 = t5.wrapping_add(k4 * p1);
    t6 = t6.wrapping_add(k4 * p2);
    t7 = t7.wrapping_add(k4 * p3);
    t8 = t8.wrapping_add(k4 * p4);
    t9 = t9.wrapping_add(k4 * p5);
    t10 = t10.wrapping_add(k4 * p6);
    t11 = t11.wrapping_add(k4 * p7);
    t12 = t12.wrapping_add(k4 * p8);
    t5 = t5.wrapping_add(t4 >> 29);
    let k5 = t5.wrapping_mul(inv) & MASK;
    t5 = t5.wrapping_add(k5 * p0);
    t6 = t6.wrapping_add(k5 * p1);
    t7 = t7.wrapping_add(k5 * p2);
    t8 = t8.wrapping_add(k5 * p3);
    t9 = t9.wrapping_add(k5 * p4);
    t10 = t10.wrapping_add(k5 * p5);
    t11 = t11.wrapping_add(k5 * p6);
    t12 = t12.wrapping_add(k5 * p7);
    t13 = t13.wrapping_add(k5 * p8);
    t6 = t6.wrapping_add(t5 >> 29);
    let k6 = t6.wrapping_mul(inv) & MASK;
    t6 = t6.wrapping_add(k6 * p0);
    t7 = t7.wrapping_add(k6 * p1);
    t8 = t8.wrapping_add(k6 * p2);
    t9 = t9.wrapping_add(k6 * p3);
    t10 = t10.wrapping_add(k6 * p4);
    t11 = t11.wrapping_add(k6 * p5);
    t12 = t12.wrapping_add(k6 * p6);
    t13 = t13.wrapping_add(k6 * p7);
    t14 = t14.wrapping_add(k6 * p8);
    t7 = t7.wrapping_add(t6 >> 29);
    let k7 = t7.wrapping_mul(inv) & MASK;
    t7 = t7.wrapping_add(k7 * p0);
    t8 = t8.wrapping_add(k7 * p1);
    t9 = t9.wrapping_add(k7 * p2);
    t10 = t10.wrapping_add(k7 * p3);
    t11 = t11.wrapping_add(k7 * p4);
    t12 = t12.wrapping_add(k7 * p5);
    t13 = t13.wrapping_add(k7 * p6);
    t14 = t14.wrapping_add(k7 * p7);
    t15 = t15.wrapping_add(k7 * p8);
    t8 = t8.wrapping_add(t7 >> 29);
    let k8 = t8.wrapping_mul(inv) & MASK;
    t8 = t8.wrapping_add(k8 * p0);
    t9 = t9.wrapping_add(k8 * p1);
    t10 = t10.wrapping_add(k8 * p2);
    t11 = t11.wrapping_add(k8 * p3);
    t12 = t12.wrapping_add(k8 * p4);
    t13 = t13.wrapping_add(k8 * p5);
    t14 = t14.wrapping_add(k8 * p6);
    t15 = t15.wrapping_add(k8 * p7);
    t16 = t16.wrapping_add(k8 * p8);
    t9 = t9.wrapping_add(t8 >> 29);
    let mut out = [0u32; 9];
    let mut carry = 0u64;
    let v = t9 + carry;
    out[0] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t10 + carry;
    out[1] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t11 + carry;
    out[2] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t12 + carry;
    out[3] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t13 + carry;
    out[4] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t14 + carry;
    out[5] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t15 + carry;
    out[6] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t16 + carry;
    out[7] = (v & MASK) as u32;
    carry = v >> 29;
    let v = t17 + carry;
    out[8] = (v & MASK) as u32;
    carry = v >> 29;
    debug_assert_eq!(carry, 0);
    out
}

/// `a + b mod p`, output in the same [0, 2p) coarse range as the inputs: add, then subtract
/// 2p once if the sum reached it.
#[inline]
pub fn add(a: &[u32; 9], b: &[u32; 9], p: &[u32; 9]) -> [u32; 9] {
    let mut s = [0u64; 9];
    let mut carry = 0u64;
    for i in 0..9 {
        let v = a[i] as u64 + b[i] as u64 + carry;
        s[i] = v & MASK;
        carry = v >> 29;
    }
    debug_assert_eq!(carry, 0);
    // 2p as proper 29-bit limbs (2*p[i] can exceed the limb base), then subtract-with-borrow.
    let mut twop = [0u64; 9];
    let mut c = 0u64;
    for i in 0..9 {
        let v = 2 * (p[i] as u64) + c;
        twop[i] = v & MASK;
        c = v >> 29;
    }
    let mut borrow = 0i64;
    let mut d = [0u64; 9];
    for i in 0..9 {
        let v = s[i] as i64 - twop[i] as i64 - borrow;
        d[i] = (v & MASK as i64) as u64;
        borrow = (v >> 63) & 1;
    }
    let mut out = [0u32; 9];
    for i in 0..9 {
        out[i] = if borrow == 1 { s[i] as u32 } else { d[i] as u32 };
    }
    out
}

/// Fully reduce a [0, 2p) value to canonical [0, p).
pub fn reduce(a: &[u32; 9], p: &[u32; 9]) -> [u32; 9] {
    let mut borrow = 0i64;
    let mut d = [0u32; 9];
    for i in 0..9 {
        let v = a[i] as i64 - p[i] as i64 - borrow;
        d[i] = (v & MASK as i64) as u32;
        borrow = (v >> 63) & 1;
    }
    if borrow == 1 {
        *a
    } else {
        d
    }
}

/// Repack a canonical 4x64-bit value into 29-bit limbs (raw, not Montgomery).
pub fn from_u64x4(a: &[u64; 4]) -> [u32; 9] {
    let mut out = [0u32; 9];
    for (i, o) in out.iter_mut().enumerate() {
        let bit = 29 * i;
        let (limb, sh) = (bit / 64, bit % 64);
        let mut v = a[limb] >> sh;
        if sh > 35 && limb + 1 < 4 {
            v |= a[limb + 1] << (64 - sh);
        }
        *o = (v & MASK) as u32;
    }
    out
}

/// Repack canonical 29-bit limbs back to 4x64.
pub fn to_u64x4(a: &[u32; 9]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, &l) in a.iter().enumerate() {
        let bit = 29 * i;
        let (limb, sh) = (bit / 64, bit % 64);
        out[limb] |= (l as u64) << sh;
        if sh > 35 && limb + 1 < 4 {
            out[limb + 1] |= (l as u64) >> (64 - sh);
        }
    }
    out
}


/// Four elements per call, bb's layout: `limbs[k]` is a u32x4 whose lane L is element L's limb
/// k. `i64x2.extmul_low/high_i32x4_u` then yields all four 58-bit products of a limb pair in two
/// instructions with no shuffles — the entire schoolbook runs at half a multiply instruction per
/// element. Accumulators are i64x2 pairs (elements 0,1 in `lo`, 2,3 in `hi`); the per-round
/// Montgomery multiplier is repacked to u32x4 with one shuffle per round.
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
pub mod quad {
    use super::MASK;
    use core::arch::wasm32::*;

    /// 4 field elements, transposed into u32x4 lanes per limb.
    #[derive(Clone, Copy)]
    pub struct Quad {
        pub limbs: [v128; 9],
    }

    impl Quad {
        pub fn pack(e: &[[u32; 9]; 4]) -> Self {
            Quad {
                limbs: core::array::from_fn(|k| u32x4(e[0][k], e[1][k], e[2][k], e[3][k])),
            }
        }
        pub fn unpack(&self) -> [[u32; 9]; 4] {
            let mut out = [[0u32; 9]; 4];
            for k in 0..9 {
                out[0][k] = u32x4_extract_lane::<0>(self.limbs[k]);
                out[1][k] = u32x4_extract_lane::<1>(self.limbs[k]);
                out[2][k] = u32x4_extract_lane::<2>(self.limbs[k]);
                out[3][k] = u32x4_extract_lane::<3>(self.limbs[k]);
            }
            out
        }
    }

    /// Montgomery product of two quads (per-lane), inputs/outputs in [0, 2p). Product-scanning
    /// (comba) order: each output column is finished with two live i64x2 accumulators before
    /// moving on, so the working set fits the 16 xmm registers — row-scanning kept 36 live
    /// accumulators and spilled every add. The Montgomery multiplier k_s for round s becomes
    /// available exactly when column s closes, in the same pass.
    pub fn mont_mul(a: &Quad, b: &Quad, p: &[u32; 9], inv: u64) -> Quad {
        let pv: [v128; 9] = core::array::from_fn(|k| u32x4_splat(p[k]));
        let invv = u32x4_splat(inv as u32);
        let mask64 = u64x2_splat(MASK);
        let mut ks = [u32x4_splat(0); 9];
        let mut out = [u32x4_splat(0); 9];
        // carry_lo/hi: the running value shifted past the closed columns.
        let (mut carry_l, mut carry_h) = (u64x2(0, 0), u64x2(0, 0));
        for k in 0..18usize {
            let (mut acc_l, mut acc_h) = (carry_l, carry_h);
            let ilo = k.saturating_sub(8);
            let ihi = if k < 9 { k } else { 8 };
            for i in ilo..=ihi {
                acc_l = u64x2_add(acc_l, u64x2_extmul_low_u32x4(a.limbs[i], b.limbs[k - i]));
                acc_h = u64x2_add(acc_h, u64x2_extmul_high_u32x4(a.limbs[i], b.limbs[k - i]));
            }
            let slo = k.saturating_sub(8);
            let shi = if k < 9 { k } else { 8 };
            for s in slo..=shi.min(if k < 9 { k.wrapping_sub(1) } else { 8 }) {
                // k_s * p[k-s]; for s == k the multiplier is computed below, not here.
                if s < 9 && k - s < 9 && s != k {
                    acc_l = u64x2_add(acc_l, u64x2_extmul_low_u32x4(ks[s], pv[k - s]));
                    acc_h = u64x2_add(acc_h, u64x2_extmul_high_u32x4(ks[s], pv[k - s]));
                }
            }
            if k < 9 {
                // Close the column: choose k_k so the column becomes divisible by 2^29.
                let kl = v128_and(acc_l, mask64);
                let kh = v128_and(acc_h, mask64);
                let k4 = u32x4_shuffle::<0, 2, 4, 6>(kl, kh);
                let ml = v128_and(u64x2_extmul_low_u32x4(k4, invv), mask64);
                let mh = v128_and(u64x2_extmul_high_u32x4(k4, invv), mask64);
                let kk = u32x4_shuffle::<0, 2, 4, 6>(ml, mh);
                ks[k] = kk;
                acc_l = u64x2_add(acc_l, u64x2_extmul_low_u32x4(kk, pv[0]));
                acc_h = u64x2_add(acc_h, u64x2_extmul_high_u32x4(kk, pv[0]));
                carry_l = u64x2_shr(acc_l, 29);
                carry_h = u64x2_shr(acc_h, 29);
            } else {
                out[k - 9] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(acc_l, mask64), v128_and(acc_h, mask64));
                carry_l = u64x2_shr(acc_l, 29);
                carry_h = u64x2_shr(acc_h, 29);
            }
        }
        Quad { limbs: out }
    }

    /// Fully-unrolled product-scanning Montgomery quad mul (see [`mont_mul`]); straight-line
    /// so the register allocator sees the whole dataflow, mirroring bb's generated WAT kernels.
    #[allow(clippy::too_many_lines)]
    pub fn mont_mul_u(a: &Quad, b: &Quad, p: &[u32; 9], inv: u64) -> Quad {
        let invv = u32x4_splat(inv as u32);
        let mask64 = u64x2_splat(MASK);
        let p0 = u32x4_splat(p[0]);
        let p1 = u32x4_splat(p[1]);
        let p2 = u32x4_splat(p[2]);
        let p3 = u32x4_splat(p[3]);
        let p4 = u32x4_splat(p[4]);
        let p5 = u32x4_splat(p[5]);
        let p6 = u32x4_splat(p[6]);
        let p7 = u32x4_splat(p[7]);
        let p8 = u32x4_splat(p[8]);
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
        let (mut cl, mut ch) = (u64x2(0, 0), u64x2(0, 0));
        let mut out = [u32x4_splat(0); 9];
        // column 0
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b0));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k0 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 1
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k1 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 2
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k2 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 3
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k3 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 4
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k4 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 5
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k5 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 6
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k6 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 7
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k7 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 8
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a0, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a0, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b0));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k0, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k0, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k8 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 9
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a1, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a1, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b1));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k1, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k1, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p1));
        out[0] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 10
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a2, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a2, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k2, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k2, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p2));
        out[1] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 11
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a3, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a3, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k3, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k3, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p3));
        out[2] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 12
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a4, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a4, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k4, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k4, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p4));
        out[3] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 13
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a5, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a5, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k5, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k5, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p5));
        out[4] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 14
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a6, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a6, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k6, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k6, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p6));
        out[5] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 15
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a7, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a7, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k7, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k7, p8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p7));
        out[6] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 16
        let (mut al, mut ah) = (cl, ch);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(a8, b8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(a8, b8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(k8, p8));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(k8, p8));
        out[7] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 17
        let (mut al, mut ah) = (cl, ch);
        out[8] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        Quad { limbs: out }
    }

    /// bb's `q1s1` shape: one scalar element and one quad multiplied in the same pass,
    /// statements interleaved column by column so V8 keeps the integer and SIMD pipes both
    /// busy. Five elements per call.
    #[allow(clippy::too_many_lines)]
    pub fn mont_mul_mix5(sa: &[u32; 9], sb: &[u32; 9], a: &Quad, b: &Quad, p: &[u32; 9], inv: u64) -> ([u32; 9], Quad) {
        let invv = u32x4_splat(inv as u32);
        let mask64 = u64x2_splat(MASK);
        let qp0 = u32x4_splat(p[0]);
        let sp0 = p[0] as u64;
        let qp1 = u32x4_splat(p[1]);
        let sp1 = p[1] as u64;
        let qp2 = u32x4_splat(p[2]);
        let sp2 = p[2] as u64;
        let qp3 = u32x4_splat(p[3]);
        let sp3 = p[3] as u64;
        let qp4 = u32x4_splat(p[4]);
        let sp4 = p[4] as u64;
        let qp5 = u32x4_splat(p[5]);
        let sp5 = p[5] as u64;
        let qp6 = u32x4_splat(p[6]);
        let sp6 = p[6] as u64;
        let qp7 = u32x4_splat(p[7]);
        let sp7 = p[7] as u64;
        let qp8 = u32x4_splat(p[8]);
        let sp8 = p[8] as u64;
        let qa0 = a.limbs[0];
        let sa0 = sa[0] as u64;
        let qb0 = b.limbs[0];
        let sb0 = sb[0] as u64;
        let qa1 = a.limbs[1];
        let sa1 = sa[1] as u64;
        let qb1 = b.limbs[1];
        let sb1 = sb[1] as u64;
        let qa2 = a.limbs[2];
        let sa2 = sa[2] as u64;
        let qb2 = b.limbs[2];
        let sb2 = sb[2] as u64;
        let qa3 = a.limbs[3];
        let sa3 = sa[3] as u64;
        let qb3 = b.limbs[3];
        let sb3 = sb[3] as u64;
        let qa4 = a.limbs[4];
        let sa4 = sa[4] as u64;
        let qb4 = b.limbs[4];
        let sb4 = sb[4] as u64;
        let qa5 = a.limbs[5];
        let sa5 = sa[5] as u64;
        let qb5 = b.limbs[5];
        let sb5 = sb[5] as u64;
        let qa6 = a.limbs[6];
        let sa6 = sa[6] as u64;
        let qb6 = b.limbs[6];
        let sb6 = sb[6] as u64;
        let qa7 = a.limbs[7];
        let sa7 = sa[7] as u64;
        let qb7 = b.limbs[7];
        let sb7 = sb[7] as u64;
        let qa8 = a.limbs[8];
        let sa8 = sa[8] as u64;
        let qb8 = b.limbs[8];
        let sb8 = sb[8] as u64;
        let (mut cl, mut ch) = (u64x2(0, 0), u64x2(0, 0));
        let mut s_c: u64 = 0;
        let mut q_out = [u32x4_splat(0); 9];
        let mut s_out = [0u32; 9];
        // column 0
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb0));
        let sk0 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb0));
        s_acc = s_acc.wrapping_add(sk0 * sp0);
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        s_c = s_acc >> 29;
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk0 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 1
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb1));
        s_acc = s_acc.wrapping_add(sa1 * sb0);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb1));
        s_acc = s_acc.wrapping_add(sk0 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb0));
        let sk1 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb0));
        s_acc = s_acc.wrapping_add(sk1 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp1));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk1 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 2
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb2);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb2));
        s_acc = s_acc.wrapping_add(sa1 * sb1);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb2));
        s_acc = s_acc.wrapping_add(sa2 * sb0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb1));
        s_acc = s_acc.wrapping_add(sk0 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb1));
        s_acc = s_acc.wrapping_add(sk1 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb0));
        let sk2 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb0));
        s_acc = s_acc.wrapping_add(sk2 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp2));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk2 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 3
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb3));
        s_acc = s_acc.wrapping_add(sa1 * sb2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb3));
        s_acc = s_acc.wrapping_add(sa2 * sb1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb2));
        s_acc = s_acc.wrapping_add(sa3 * sb0);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb2));
        s_acc = s_acc.wrapping_add(sk0 * sp3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb1));
        s_acc = s_acc.wrapping_add(sk1 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb1));
        s_acc = s_acc.wrapping_add(sk2 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb0));
        let sk3 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb0));
        s_acc = s_acc.wrapping_add(sk3 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp3));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk3 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 4
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb4));
        s_acc = s_acc.wrapping_add(sa1 * sb3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb4));
        s_acc = s_acc.wrapping_add(sa2 * sb2);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb3));
        s_acc = s_acc.wrapping_add(sa3 * sb1);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb3));
        s_acc = s_acc.wrapping_add(sa4 * sb0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb2));
        s_acc = s_acc.wrapping_add(sk0 * sp4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb2));
        s_acc = s_acc.wrapping_add(sk1 * sp3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb1));
        s_acc = s_acc.wrapping_add(sk2 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb1));
        s_acc = s_acc.wrapping_add(sk3 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb0));
        let sk4 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb0));
        s_acc = s_acc.wrapping_add(sk4 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp4));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk4 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 5
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb5));
        s_acc = s_acc.wrapping_add(sa1 * sb4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb5));
        s_acc = s_acc.wrapping_add(sa2 * sb3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb4));
        s_acc = s_acc.wrapping_add(sa3 * sb2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb4));
        s_acc = s_acc.wrapping_add(sa4 * sb1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb3));
        s_acc = s_acc.wrapping_add(sa5 * sb0);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb3));
        s_acc = s_acc.wrapping_add(sk0 * sp5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb2));
        s_acc = s_acc.wrapping_add(sk1 * sp4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb2));
        s_acc = s_acc.wrapping_add(sk2 * sp3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb1));
        s_acc = s_acc.wrapping_add(sk3 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb1));
        s_acc = s_acc.wrapping_add(sk4 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb0));
        let sk5 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb0));
        s_acc = s_acc.wrapping_add(sk5 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp5));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk5 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 6
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb6));
        s_acc = s_acc.wrapping_add(sa1 * sb5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb6));
        s_acc = s_acc.wrapping_add(sa2 * sb4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb5));
        s_acc = s_acc.wrapping_add(sa3 * sb3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb5));
        s_acc = s_acc.wrapping_add(sa4 * sb2);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb4));
        s_acc = s_acc.wrapping_add(sa5 * sb1);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb4));
        s_acc = s_acc.wrapping_add(sa6 * sb0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb3));
        s_acc = s_acc.wrapping_add(sk0 * sp6);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb3));
        s_acc = s_acc.wrapping_add(sk1 * sp5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb2));
        s_acc = s_acc.wrapping_add(sk2 * sp4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb2));
        s_acc = s_acc.wrapping_add(sk3 * sp3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb1));
        s_acc = s_acc.wrapping_add(sk4 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb1));
        s_acc = s_acc.wrapping_add(sk5 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb0));
        let sk6 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb0));
        s_acc = s_acc.wrapping_add(sk6 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp6));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk6 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 7
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb7);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb7));
        s_acc = s_acc.wrapping_add(sa1 * sb6);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb7));
        s_acc = s_acc.wrapping_add(sa2 * sb5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb6));
        s_acc = s_acc.wrapping_add(sa3 * sb4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb6));
        s_acc = s_acc.wrapping_add(sa4 * sb3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb5));
        s_acc = s_acc.wrapping_add(sa5 * sb2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb5));
        s_acc = s_acc.wrapping_add(sa6 * sb1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb4));
        s_acc = s_acc.wrapping_add(sa7 * sb0);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb4));
        s_acc = s_acc.wrapping_add(sk0 * sp7);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb3));
        s_acc = s_acc.wrapping_add(sk1 * sp6);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb3));
        s_acc = s_acc.wrapping_add(sk2 * sp5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb2));
        s_acc = s_acc.wrapping_add(sk3 * sp4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb2));
        s_acc = s_acc.wrapping_add(sk4 * sp3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb1));
        s_acc = s_acc.wrapping_add(sk5 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb1));
        s_acc = s_acc.wrapping_add(sk6 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb0));
        let sk7 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb0));
        s_acc = s_acc.wrapping_add(sk7 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp7));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk7 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 8
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa0 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa0, qb8));
        s_acc = s_acc.wrapping_add(sa1 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa0, qb8));
        s_acc = s_acc.wrapping_add(sa2 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb7));
        s_acc = s_acc.wrapping_add(sa3 * sb5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb7));
        s_acc = s_acc.wrapping_add(sa4 * sb4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb6));
        s_acc = s_acc.wrapping_add(sa5 * sb3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb6));
        s_acc = s_acc.wrapping_add(sa6 * sb2);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb5));
        s_acc = s_acc.wrapping_add(sa7 * sb1);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb5));
        s_acc = s_acc.wrapping_add(sa8 * sb0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb4));
        s_acc = s_acc.wrapping_add(sk0 * sp8);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb4));
        s_acc = s_acc.wrapping_add(sk1 * sp7);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb3));
        s_acc = s_acc.wrapping_add(sk2 * sp6);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb3));
        s_acc = s_acc.wrapping_add(sk3 * sp5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb2));
        s_acc = s_acc.wrapping_add(sk4 * sp4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb2));
        s_acc = s_acc.wrapping_add(sk5 * sp3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb1));
        s_acc = s_acc.wrapping_add(sk6 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb1));
        s_acc = s_acc.wrapping_add(sk7 * sp1);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb0));
        let sk8 = s_acc.wrapping_mul(inv) & MASK;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb0));
        s_acc = s_acc.wrapping_add(sk8 * sp0);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk0, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk0, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp1));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        let km_l = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let km_h = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let qk8 = u32x4_shuffle::<0, 2, 4, 6>(km_l, km_h);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp0));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp0));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 9
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa1 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa1, qb8));
        s_acc = s_acc.wrapping_add(sa2 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa1, qb8));
        s_acc = s_acc.wrapping_add(sa3 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb7));
        s_acc = s_acc.wrapping_add(sa4 * sb5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb7));
        s_acc = s_acc.wrapping_add(sa5 * sb4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb6));
        s_acc = s_acc.wrapping_add(sa6 * sb3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb6));
        s_acc = s_acc.wrapping_add(sa7 * sb2);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb5));
        s_acc = s_acc.wrapping_add(sa8 * sb1);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb5));
        s_acc = s_acc.wrapping_add(sk1 * sp8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb4));
        s_acc = s_acc.wrapping_add(sk2 * sp7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb4));
        s_acc = s_acc.wrapping_add(sk3 * sp6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb3));
        s_acc = s_acc.wrapping_add(sk4 * sp5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb3));
        s_acc = s_acc.wrapping_add(sk5 * sp4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb2));
        s_acc = s_acc.wrapping_add(sk6 * sp3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb2));
        s_acc = s_acc.wrapping_add(sk7 * sp2);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb1));
        s_acc = s_acc.wrapping_add(sk8 * sp1);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb1));
        s_out[0] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk1, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk1, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp2));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp1));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp1));
        q_out[0] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 10
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa2 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa2, qb8));
        s_acc = s_acc.wrapping_add(sa3 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa2, qb8));
        s_acc = s_acc.wrapping_add(sa4 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb7));
        s_acc = s_acc.wrapping_add(sa5 * sb5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb7));
        s_acc = s_acc.wrapping_add(sa6 * sb4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb6));
        s_acc = s_acc.wrapping_add(sa7 * sb3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb6));
        s_acc = s_acc.wrapping_add(sa8 * sb2);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb5));
        s_acc = s_acc.wrapping_add(sk2 * sp8);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb5));
        s_acc = s_acc.wrapping_add(sk3 * sp7);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb4));
        s_acc = s_acc.wrapping_add(sk4 * sp6);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb4));
        s_acc = s_acc.wrapping_add(sk5 * sp5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb3));
        s_acc = s_acc.wrapping_add(sk6 * sp4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb3));
        s_acc = s_acc.wrapping_add(sk7 * sp3);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb2));
        s_acc = s_acc.wrapping_add(sk8 * sp2);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb2));
        s_out[1] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk2, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk2, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp3));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp2));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp2));
        q_out[1] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 11
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa3 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa3, qb8));
        s_acc = s_acc.wrapping_add(sa4 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa3, qb8));
        s_acc = s_acc.wrapping_add(sa5 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb7));
        s_acc = s_acc.wrapping_add(sa6 * sb5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb7));
        s_acc = s_acc.wrapping_add(sa7 * sb4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb6));
        s_acc = s_acc.wrapping_add(sa8 * sb3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb6));
        s_acc = s_acc.wrapping_add(sk3 * sp8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb5));
        s_acc = s_acc.wrapping_add(sk4 * sp7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb5));
        s_acc = s_acc.wrapping_add(sk5 * sp6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb4));
        s_acc = s_acc.wrapping_add(sk6 * sp5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb4));
        s_acc = s_acc.wrapping_add(sk7 * sp4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb3));
        s_acc = s_acc.wrapping_add(sk8 * sp3);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb3));
        s_out[2] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk3, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk3, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp4));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp3));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp3));
        q_out[2] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 12
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa4 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa4, qb8));
        s_acc = s_acc.wrapping_add(sa5 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa4, qb8));
        s_acc = s_acc.wrapping_add(sa6 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb7));
        s_acc = s_acc.wrapping_add(sa7 * sb5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb7));
        s_acc = s_acc.wrapping_add(sa8 * sb4);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb6));
        s_acc = s_acc.wrapping_add(sk4 * sp8);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb6));
        s_acc = s_acc.wrapping_add(sk5 * sp7);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb5));
        s_acc = s_acc.wrapping_add(sk6 * sp6);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb5));
        s_acc = s_acc.wrapping_add(sk7 * sp5);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb4));
        s_acc = s_acc.wrapping_add(sk8 * sp4);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb4));
        s_out[3] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk4, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk4, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp5));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp4));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp4));
        q_out[3] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 13
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa5 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa5, qb8));
        s_acc = s_acc.wrapping_add(sa6 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa5, qb8));
        s_acc = s_acc.wrapping_add(sa7 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb7));
        s_acc = s_acc.wrapping_add(sa8 * sb5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb7));
        s_acc = s_acc.wrapping_add(sk5 * sp8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb6));
        s_acc = s_acc.wrapping_add(sk6 * sp7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb6));
        s_acc = s_acc.wrapping_add(sk7 * sp6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb5));
        s_acc = s_acc.wrapping_add(sk8 * sp5);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb5));
        s_out[4] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk5, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk5, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp6));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp5));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp5));
        q_out[4] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 14
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa6 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa6, qb8));
        s_acc = s_acc.wrapping_add(sa7 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa6, qb8));
        s_acc = s_acc.wrapping_add(sa8 * sb6);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb7));
        s_acc = s_acc.wrapping_add(sk6 * sp8);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb7));
        s_acc = s_acc.wrapping_add(sk7 * sp7);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb6));
        s_acc = s_acc.wrapping_add(sk8 * sp6);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb6));
        s_out[5] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk6, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk6, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp7));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp6));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp6));
        q_out[5] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 15
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa7 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa7, qb8));
        s_acc = s_acc.wrapping_add(sa8 * sb7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa7, qb8));
        s_acc = s_acc.wrapping_add(sk7 * sp8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb7));
        s_acc = s_acc.wrapping_add(sk8 * sp7);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb7));
        s_out[6] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk7, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk7, qp8));
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp7));
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp7));
        q_out[6] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 16
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_acc = s_acc.wrapping_add(sa8 * sb8);
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qa8, qb8));
        s_acc = s_acc.wrapping_add(sk8 * sp8);
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qa8, qb8));
        s_out[7] = (s_acc & MASK) as u32;
        al = u64x2_add(al, u64x2_extmul_low_u32x4(qk8, qp8));
        s_c = s_acc >> 29;
        ah = u64x2_add(ah, u64x2_extmul_high_u32x4(qk8, qp8));
        q_out[7] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        // column 17
        let mut s_acc = s_c;
        let (mut al, mut ah) = (cl, ch);
        s_out[8] = (s_acc & MASK) as u32;
        q_out[8] = u32x4_shuffle::<0, 2, 4, 6>(v128_and(al, mask64), v128_and(ah, mask64));
        s_c = s_acc >> 29;
        cl = u64x2_shr(al, 29);
        ch = u64x2_shr(ah, 29);
        (s_out, Quad { limbs: q_out })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField, UniformRand};

    fn ark_to_m29<F: PrimeField<BigInt = ark_ff::BigInt<4>>>(x: F, r2: &[u32; 9], p: &[u32; 9], inv: u64) -> [u32; 9] {
        let limbs: [u64; 4] = x.into_bigint().as_ref().try_into().unwrap();
        mont_mul(&from_u64x4(&limbs), r2, p, inv)
    }
    fn m29_to_ark<F: PrimeField<BigInt = ark_ff::BigInt<4>>>(a: &[u32; 9], p: &[u32; 9], inv: u64) -> F {
        let mut one = [0u32; 9];
        one[0] = 1;
        let raw = reduce(&mont_mul(a, &one, p, inv), p);
        F::from_bigint(ark_ff::BigInt(to_u64x4(&raw))).unwrap()
    }

    fn roundtrip_and_ops<F: PrimeField<BigInt = ark_ff::BigInt<4>>>(p: &[u32; 9], inv: u64, r2: &[u32; 9]) {
        let mut rng = ark_std::test_rng();
        for _ in 0..20_000 {
            let (x, y) = (F::rand(&mut rng), F::rand(&mut rng));
            let (mx, my) = (ark_to_m29(x, r2, p, inv), ark_to_m29(y, r2, p, inv));
            assert_eq!(m29_to_ark::<F>(&mx, p, inv), x);
            assert_eq!(m29_to_ark::<F>(&mont_mul(&mx, &my, p, inv), p, inv), x * y);
            assert_eq!(m29_to_ark::<F>(&add(&mx, &my, p), p, inv), x + y);
        }
        for special in [F::from(0u64), F::from(1u64), -F::from(1u64)] {
            let m = ark_to_m29(special, r2, p, inv);
            assert_eq!(m29_to_ark::<F>(&mont_mul(&m, &m, p, inv), p, inv), special * special);
            assert_eq!(m29_to_ark::<F>(&add(&m, &m, p), p, inv), special + special);
        }
    }

    #[test]
    fn unrolled_matches_looped() {
        let mut rng = ark_std::test_rng();
        for _ in 0..50_000 {
            let x = crate::base::Fr::rand(&mut rng);
            let y = crate::base::Fr::rand(&mut rng);
            let mx = ark_to_m29(x, &FR_R2, &FR_P, FR_INV);
            let my = ark_to_m29(y, &FR_R2, &FR_P, FR_INV);
            assert_eq!(mont_mul(&mx, &my, &FR_P, FR_INV), mont_mul_u(&mx, &my, &FR_P, FR_INV));
        }
    }

    #[test]
    fn fr_matches_ark() {
        roundtrip_and_ops::<crate::base::Fr>(&FR_P, FR_INV, &FR_R2);
    }
    #[test]
    fn fq_matches_ark() {
        roundtrip_and_ops::<ark_bn254::Fq>(&FQ_P, FQ_INV, &FQ_R2);
    }
}
