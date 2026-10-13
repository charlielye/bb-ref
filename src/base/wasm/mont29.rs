//! bb's wasm field multiply: nine 29-bit limbs so every partial product fits one `i64.mul` with no
//! intra-product carries (a 4x64 Montgomery multiply decomposes into carry-heavy 32-bit pieces on
//! wasm), Karatsuba 5+4, then eight radix-2^29 rounds and one radix-2^24 round dividing by 2^261,
//! straight-lined. Operands and results are 4x64 stored limbs in the 2^261 Montgomery domain; the
//! 29-bit form lives only inside a call. Same design and constants as bb's `field_impl_generic`
//! wasm branch. Ported from the vendored ark-ff that carried it until 2026-09-07.

pub const MASK29: u64 = (1 << 29) - 1;

#[allow(clippy::missing_const_for_fn)]
pub const fn to29(a: &[u64; 4]) -> [u64; 9] {
    let mut out = [0u64; 9];
    let mut i = 0;
    while i < 9 {
        let bit = 29 * i;
        let (limb, sh) = (bit / 64, bit % 64);
        let mut v = a[limb] >> sh;
        if sh > 35 && limb + 1 < 4 {
            v |= a[limb + 1] << (64 - sh);
        }
        out[i] = v & MASK29;
        i += 1;
    }
    out
}

/// Nine 29-bit limbs (the top one up to 40 bits) back to 4x64.
pub fn from29(l: &[u64; 9]) -> [u64; 4] {
    [
        l[0] | (l[1] << 29) | (l[2] << 58),
        (l[2] >> 6) | (l[3] << 23) | (l[4] << 52),
        (l[4] >> 12) | (l[5] << 17) | (l[6] << 46),
        (l[6] >> 18) | (l[7] << 11) | (l[8] << 40),
    ]
}

/// -p^-1 mod 2^29 (Newton lift from the 64-bit INV would also work; direct is clearer).
pub const fn inv29(p0: u64) -> u64 {
    // Newton iteration for the inverse of p mod 2^29, then negate.
    let mut x: u64 = 1;
    let mut i = 0;
    while i < 5 {
        x = x.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg() & MASK29
}

/// `a * b / 2^261 mod p`, canonical in and out — the mul for the wasm 2^261 stored domain:
/// nine full 29-bit Montgomery rounds, result repacked with no bit offset. Always inlined: out of
/// line, the `[u64; 4]` comes back through an sret slot whose 8-byte stores the caller re-reads as
/// 16-byte loads, a store-forwarding stall on every dependent multiply (−1% wasm proving).
#[inline(always)]
#[allow(clippy::too_many_lines)]
pub fn mont_mul_261(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4], p: &[u64; 9], inv: u64) -> [u64; 4] {
    let l = to29(a);
    let r = to29(b);
    let l0 = l[0];
    let r0 = r[0];
    let l1 = l[1];
    let r1 = r[1];
    let l2 = l[2];
    let r2 = r[2];
    let l3 = l[3];
    let r3 = r[3];
    let l4 = l[4];
    let r4 = r[4];
    let l5 = l[5];
    let r5 = r[5];
    let l6 = l[6];
    let r6 = r[6];
    let l7 = l[7];
    let r7 = r[7];
    let l8 = l[8];
    let r8 = r[8];
    let p0 = p[0];
    let p1 = p[1];
    let p2 = p[2];
    let p3 = p[3];
    let p4 = p[4];
    let p5 = p[5];
    let p6 = p[6];
    let p7 = p[7];
    let p8 = p[8];
    let pl0 = l0 * r0;
    let pl1 = l0 * r1 + l1 * r0;
    let pl2 = l0 * r2 + l1 * r1 + l2 * r0;
    let pl3 = l0 * r3 + l1 * r2 + l2 * r1 + l3 * r0;
    let pl4 = l0 * r4 + l1 * r3 + l2 * r2 + l3 * r1 + l4 * r0;
    let pl5 = l1 * r4 + l2 * r3 + l3 * r2 + l4 * r1;
    let pl6 = l2 * r4 + l3 * r3 + l4 * r2;
    let pl7 = l3 * r4 + l4 * r3;
    let pl8 = l4 * r4;
    let ph0 = l5 * r5;
    let ph1 = l5 * r6 + l6 * r5;
    let ph2 = l5 * r7 + l6 * r6 + l7 * r5;
    let ph3 = l5 * r8 + l6 * r7 + l7 * r6 + l8 * r5;
    let ph4 = l6 * r8 + l7 * r7 + l8 * r6;
    let ph5 = l7 * r8 + l8 * r7;
    let ph6 = l8 * r8;
    let sl0 = l0 + l5;
    let sr0 = r0 + r5;
    let sl1 = l1 + l6;
    let sr1 = r1 + r6;
    let sl2 = l2 + l7;
    let sr2 = r2 + r7;
    let sl3 = l3 + l8;
    let sr3 = r3 + r8;
    let sl4 = l4;
    let sr4 = r4;
    let pc0 = sl0 * sr0;
    let pc1 = sl0 * sr1 + sl1 * sr0;
    let pc2 = sl0 * sr2 + sl1 * sr1 + sl2 * sr0;
    let pc3 = sl0 * sr3 + sl1 * sr2 + sl2 * sr1 + sl3 * sr0;
    let pc4 = sl0 * sr4 + sl1 * sr3 + sl2 * sr2 + sl3 * sr1 + sl4 * sr0;
    let pc5 = sl1 * sr4 + sl2 * sr3 + sl3 * sr2 + sl4 * sr1;
    let pc6 = sl2 * sr4 + sl3 * sr3 + sl4 * sr2;
    let pc7 = sl3 * sr4 + sl4 * sr3;
    let pc8 = sl4 * sr4;
    let mut t0 = pl0;
    let mut t1 = pl1;
    let mut t2 = pl2;
    let mut t3 = pl3;
    let mut t4 = pl4;
    let m0 = pc0.wrapping_sub(pl0).wrapping_sub(ph0);
    let m1 = pc1.wrapping_sub(pl1).wrapping_sub(ph1);
    let m2 = pc2.wrapping_sub(pl2).wrapping_sub(ph2);
    let m3 = pc3.wrapping_sub(pl3).wrapping_sub(ph3);
    let m4 = pc4.wrapping_sub(pl4).wrapping_sub(ph4);
    let m5 = pc5.wrapping_sub(pl5).wrapping_sub(ph5);
    let m6 = pc6.wrapping_sub(pl6).wrapping_sub(ph6);
    let m7 = pc7.wrapping_sub(pl7);
    let m8 = pc8.wrapping_sub(pl8);
    let mut t5 = pl5.wrapping_add(m0);
    let mut t6 = pl6.wrapping_add(m1);
    let mut t7 = pl7.wrapping_add(m2);
    let mut t8 = pl8.wrapping_add(m3);
    let mut t9 = m4;
    let mut t10 = m5.wrapping_add(ph0);
    let mut t11 = m6.wrapping_add(ph1);
    let mut t12 = m7.wrapping_add(ph2);
    let mut t13 = m8.wrapping_add(ph3);
    let mut t14 = ph4;
    let mut t15 = ph5;
    let mut t16 = ph6;
    let mut t17: u64 = 0;
    let k0 = t0.wrapping_mul(inv) & MASK29;
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
    let k1 = t1.wrapping_mul(inv) & MASK29;
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
    let k2 = t2.wrapping_mul(inv) & MASK29;
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
    let k3 = t3.wrapping_mul(inv) & MASK29;
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
    let k4 = t4.wrapping_mul(inv) & MASK29;
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
    let k5 = t5.wrapping_mul(inv) & MASK29;
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
    let k6 = t6.wrapping_mul(inv) & MASK29;
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
    let k7 = t7.wrapping_mul(inv) & MASK29;
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
    let k8 = t8.wrapping_mul(inv) & MASK29;
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
    t10 = t10.wrapping_add(t9 >> 29);
    t9 &= MASK29;
    t11 = t11.wrapping_add(t10 >> 29);
    t10 &= MASK29;
    t12 = t12.wrapping_add(t11 >> 29);
    t11 &= MASK29;
    t13 = t13.wrapping_add(t12 >> 29);
    t12 &= MASK29;
    t14 = t14.wrapping_add(t13 >> 29);
    t13 &= MASK29;
    t15 = t15.wrapping_add(t14 >> 29);
    t14 &= MASK29;
    t16 = t16.wrapping_add(t15 >> 29);
    t15 &= MASK29;
    t17 = t17.wrapping_add(t16 >> 29);
    t16 &= MASK29;
    let wide = from29(&[t9, t10, t11, t12, t13, t14, t15, t16, t17]);
    let mut borrow = 0u64;
    let mut d = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let (v1, b1) = wide[i].overflowing_sub(modulus[i]);
        let (v2, b2) = v1.overflowing_sub(borrow);
        d[i] = v2;
        borrow = (b1 as u64) | (b2 as u64);
        i += 1;
    }
    if borrow == 1 {
        wide
    } else {
        d
    }
}
