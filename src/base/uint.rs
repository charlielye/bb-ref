//! A 1024-bit unsigned integer on the stack (bb's `uint256_t`/`uint512_t`/`uint1024_t`): the subset
//! of `num_bigint::BigUint` that the stdlib's non-native arithmetic uses, without a heap allocation
//! per operation. Overflow, underflow and division by zero panic, so a bound that bb's fixed widths
//! would wrap can never pass silently.
use ark_ff::{BigInt, PrimeField};
use std::cmp::Ordering;
use std::ops::{
    Add, AddAssign, BitAnd, Div, DivAssign, Mul, MulAssign, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub,
    SubAssign,
};

const N: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uint([u64; N]);

impl Uint {
    pub const ZERO: Self = Self([0; N]);

    pub fn from_limbs(d: &[u64]) -> Self {
        let mut r = [0; N];
        for (i, &x) in d.iter().enumerate() {
            if i < N {
                r[i] = x;
            } else {
                assert_eq!(x, 0, "Uint overflow");
            }
        }
        Self(r)
    }
    pub fn from_bigint<B: ark_ff::BigInteger>(b: B) -> Self {
        Self::from_limbs(b.as_ref())
    }
    fn len(&self) -> usize {
        self.0.iter().rposition(|&d| d != 0).map_or(0, |i| i + 1)
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0; N]
    }
    pub fn bits(&self) -> u64 {
        match self.len() {
            0 => 0,
            l => 64 * l as u64 - self.0[l - 1].leading_zeros() as u64,
        }
    }
    pub fn bit(&self, i: u64) -> bool {
        i < 64 * N as u64 && (self.0[(i / 64) as usize] >> (i % 64)) & 1 == 1
    }
    pub fn trailing_zeros(&self) -> Option<u64> {
        let i = self.0.iter().position(|&d| d != 0)?;
        Some(64 * i as u64 + self.0[i].trailing_zeros() as u64)
    }
    /// Little-endian digits without leading zeros (none for zero), as `BigUint`'s.
    pub fn iter_u64_digits(&self) -> impl Iterator<Item = u64> + '_ {
        self.0[..self.len()].iter().copied()
    }
    pub fn pow(&self, e: u32) -> Self {
        (0..e).fold(Self::from(1u64), |r, _| r * self)
    }
    pub fn parse_bytes(s: &[u8], radix: u32) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        s.iter().try_fold(Self::ZERO, |r, &c| {
            Some(r * radix as u64 + (c as char).to_digit(radix)? as u64)
        })
    }
    /// Big-endian bytes without leading zeros (`[0]` for zero), as `BigUint`'s.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let bytes: Vec<u8> = self.0.iter().rev().flat_map(|d| d.to_be_bytes()).collect();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        bytes[first..].to_vec()
    }
    /// The value reduced into `F`.
    pub fn to_field<F: PrimeField>(&self) -> F {
        let v = if self.bits() > 256 {
            self % Self::from_limbs(F::MODULUS.as_ref())
        } else {
            *self
        };
        crate::base::field::from_limbs_mod_order(v.iter_u64_digits())
    }

    fn add(a: &Self, b: &Self) -> Self {
        let mut r = [0; N];
        let mut carry = false;
        for i in 0..N {
            let (s, c1) = a.0[i].overflowing_add(b.0[i]);
            let (s, c2) = s.overflowing_add(carry as u64);
            r[i] = s;
            carry = c1 | c2;
        }
        assert!(!carry, "Uint overflow");
        Self(r)
    }
    fn sub(a: &Self, b: &Self) -> Self {
        let mut r = [0; N];
        let mut borrow = false;
        for i in 0..N {
            let (s, b1) = a.0[i].overflowing_sub(b.0[i]);
            let (s, b2) = s.overflowing_sub(borrow as u64);
            r[i] = s;
            borrow = b1 | b2;
        }
        assert!(!borrow, "Uint underflow");
        Self(r)
    }
    fn mul(a: &Self, b: &Self) -> Self {
        let (la, lb) = (a.len(), b.len());
        let mut r = [0u64; 2 * N];
        for i in 0..la {
            let mut carry = 0u128;
            for j in 0..lb {
                let t = a.0[i] as u128 * b.0[j] as u128 + r[i + j] as u128 + carry;
                r[i + j] = t as u64;
                carry = t >> 64;
            }
            r[i + lb] = carry as u64;
        }
        Self::from_limbs(&r)
    }
    /// Knuth's algorithm D on 64-bit digits.
    pub fn div_rem(a: &Self, b: &Self) -> (Self, Self) {
        let lb = b.len();
        assert!(lb > 0, "Uint division by zero");
        if a < b {
            return (Self::ZERO, *a);
        }
        let mut q = [0u64; N];
        if lb == 1 {
            let d = b.0[0] as u128;
            let mut r = 0u128;
            for i in (0..a.len()).rev() {
                let cur = (r << 64) | a.0[i] as u128;
                q[i] = (cur / d) as u64;
                r = cur % d;
            }
            return (Self(q), Self::from(r as u64));
        }
        let s = b.0[lb - 1].leading_zeros();
        let shl = |x: &[u64; N], out: &mut [u64; N + 1]| {
            for i in 0..N {
                out[i] |= x[i] << s;
                if s > 0 {
                    out[i + 1] |= x[i] >> (64 - s);
                }
            }
        };
        let mut v = [0u64; N + 1];
        shl(&b.0, &mut v);
        let mut u = [0u64; N + 1];
        shl(&a.0, &mut u);
        let la = a.len();
        let top = v[lb - 1] as u128;
        for j in (0..=la - lb).rev() {
            let num = ((u[j + lb] as u128) << 64) | u[j + lb - 1] as u128;
            let (mut qhat, mut rhat) = (num / top, num % top);
            while qhat >> 64 != 0 || qhat * v[lb - 2] as u128 > ((rhat << 64) | u[j + lb - 2] as u128) {
                qhat -= 1;
                rhat += top;
                if rhat >> 64 != 0 {
                    break;
                }
            }
            let (mut borrow, mut carry) = (0i128, 0u128);
            for i in 0..lb {
                let p = qhat * v[i] as u128 + carry;
                carry = p >> 64;
                let t = u[i + j] as i128 - (p as u64) as i128 + borrow;
                u[i + j] = t as u64;
                borrow = t >> 64;
            }
            let t = u[j + lb] as i128 - carry as i128 + borrow;
            u[j + lb] = t as u64;
            if t < 0 {
                qhat -= 1;
                let mut c = 0u128;
                for i in 0..lb {
                    let sum = u[i + j] as u128 + v[i] as u128 + c;
                    u[i + j] = sum as u64;
                    c = sum >> 64;
                }
                u[j + lb] = u[j + lb].wrapping_add(c as u64);
            }
            q[j] = qhat as u64;
        }
        let mut r = [0u64; N];
        for i in 0..lb {
            r[i] = (u[i] >> s) | if s > 0 { u[i + 1] << (64 - s) } else { 0 };
        }
        (Self(q), Self(r))
    }
    fn shl(a: &Self, n: u64) -> Self {
        if a.is_zero() {
            return *a;
        }
        assert!(a.bits() + n <= 64 * N as u64, "Uint overflow");
        let (w, b) = ((n / 64) as usize, (n % 64) as u32);
        let mut r = [0u64; N];
        for i in (w..N).rev() {
            r[i] = a.0[i - w] << b;
            if b > 0 && i > w {
                r[i] |= a.0[i - w - 1] >> (64 - b);
            }
        }
        Self(r)
    }
    fn shr(a: &Self, n: u64) -> Self {
        let (w, b) = ((n / 64) as usize, (n % 64) as u32);
        let mut r = [0u64; N];
        for i in 0..N.saturating_sub(w) {
            r[i] = a.0[i + w] >> b;
            if b > 0 && i + w + 1 < N {
                r[i] |= a.0[i + w + 1] << (64 - b);
            }
        }
        Self(r)
    }
    fn and(a: &Self, b: &Self) -> Self {
        Self(std::array::from_fn(|i| a.0[i] & b.0[i]))
    }
}

impl Ord for Uint {
    fn cmp(&self, o: &Self) -> Ordering {
        self.0.iter().rev().cmp(o.0.iter().rev())
    }
}
impl PartialOrd for Uint {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl From<u64> for Uint {
    fn from(v: u64) -> Self {
        Self::from_limbs(&[v])
    }
}
impl From<u32> for Uint {
    fn from(v: u32) -> Self {
        Self::from(v as u64)
    }
}
impl From<usize> for Uint {
    fn from(v: usize) -> Self {
        Self::from(v as u64)
    }
}
impl<const M: usize> From<BigInt<M>> for Uint {
    fn from(v: BigInt<M>) -> Self {
        Self::from_limbs(&v.0)
    }
}

impl<P: ark_ff::FpConfig<4>> From<Uint> for ark_ff::Fp<P, 4> {
    fn from(v: Uint) -> Self {
        v.to_field()
    }
}

impl std::fmt::Debug for Uint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_bytes_be()))
    }
}
impl std::fmt::Display for Uint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

macro_rules! binop {
    ($tr:ident, $m:ident, $atr:ident, $am:ident, $f:expr) => {
        impl $tr<&Uint> for &Uint {
            type Output = Uint;
            fn $m(self, o: &Uint) -> Uint {
                $f(self, o)
            }
        }
        impl $tr<Uint> for Uint {
            type Output = Uint;
            fn $m(self, o: Uint) -> Uint {
                $f(&self, &o)
            }
        }
        impl $tr<&Uint> for Uint {
            type Output = Uint;
            fn $m(self, o: &Uint) -> Uint {
                $f(&self, o)
            }
        }
        impl $tr<Uint> for &Uint {
            type Output = Uint;
            fn $m(self, o: Uint) -> Uint {
                $f(self, &o)
            }
        }
        impl $tr<u64> for Uint {
            type Output = Uint;
            fn $m(self, o: u64) -> Uint {
                $f(&self, &Uint::from(o))
            }
        }
        impl $tr<u64> for &Uint {
            type Output = Uint;
            fn $m(self, o: u64) -> Uint {
                $f(self, &Uint::from(o))
            }
        }
        impl $atr<Uint> for Uint {
            fn $am(&mut self, o: Uint) {
                *self = $f(self, &o)
            }
        }
        impl $atr<&Uint> for Uint {
            fn $am(&mut self, o: &Uint) {
                *self = $f(self, o)
            }
        }
        impl $atr<u64> for Uint {
            fn $am(&mut self, o: u64) {
                *self = $f(self, &Uint::from(o))
            }
        }
    };
}
binop!(Add, add, AddAssign, add_assign, Uint::add);
binop!(Sub, sub, SubAssign, sub_assign, Uint::sub);
binop!(Mul, mul, MulAssign, mul_assign, Uint::mul);
binop!(Div, div, DivAssign, div_assign, |a, b| Uint::div_rem(a, b).0);
binop!(Rem, rem, RemAssign, rem_assign, |a, b| Uint::div_rem(a, b).1);

impl BitAnd<&Uint> for &Uint {
    type Output = Uint;
    fn bitand(self, o: &Uint) -> Uint {
        Uint::and(self, o)
    }
}
impl BitAnd<Uint> for Uint {
    type Output = Uint;
    fn bitand(self, o: Uint) -> Uint {
        Uint::and(&self, &o)
    }
}
impl BitAnd<&Uint> for Uint {
    type Output = Uint;
    fn bitand(self, o: &Uint) -> Uint {
        Uint::and(&self, o)
    }
}
impl BitAnd<Uint> for &Uint {
    type Output = Uint;
    fn bitand(self, o: Uint) -> Uint {
        Uint::and(self, &o)
    }
}

macro_rules! shifts {
    ($($t:ty),*) => {$(
        impl Shl<$t> for Uint { type Output = Uint; fn shl(self, n: $t) -> Uint { Uint::shl(&self, n as u64) } }
        impl Shl<$t> for &Uint { type Output = Uint; fn shl(self, n: $t) -> Uint { Uint::shl(self, n as u64) } }
        impl Shr<$t> for Uint { type Output = Uint; fn shr(self, n: $t) -> Uint { Uint::shr(&self, n as u64) } }
        impl Shr<$t> for &Uint { type Output = Uint; fn shr(self, n: $t) -> Uint { Uint::shr(self, n as u64) } }
        impl ShlAssign<$t> for Uint { fn shl_assign(&mut self, n: $t) { *self = Uint::shl(self, n as u64) } }
        impl ShrAssign<$t> for Uint { fn shr_assign(&mut self, n: $t) { *self = Uint::shr(self, n as u64) } }
    )*};
}
shifts!(u32, u64, usize, i32);

impl std::iter::Sum for Uint {
    fn sum<I: Iterator<Item = Uint>>(it: I) -> Uint {
        it.fold(Uint::ZERO, |a, b| a + b)
    }
}
impl<'a> std::iter::Sum<&'a Uint> for Uint {
    fn sum<I: Iterator<Item = &'a Uint>>(it: I) -> Uint {
        it.fold(Uint::ZERO, |a, b| a + b)
    }
}

#[cfg(test)]
mod tests {
    use super::Uint;
    use num_bigint::BigUint;
    use rand::Rng;

    fn big(u: &Uint) -> BigUint {
        BigUint::from_bytes_be(&u.to_bytes_be())
    }
    fn rand_uint(rng: &mut impl Rng, bits: u64) -> Uint {
        let limbs: Vec<u64> = (0..bits.div_ceil(64)).map(|_| rng.gen()).collect();
        Uint::from_limbs(&limbs) >> (limbs.len() as u64 * 64 - bits)
    }

    #[test]
    fn matches_biguint() {
        let mut rng = rand::thread_rng();
        for _ in 0..2000 {
            let (ba, bb) = (rng.gen_range(1..=600), rng.gen_range(1..=400));
            let (a, b) = (rand_uint(&mut rng, ba), rand_uint(&mut rng, bb));
            if b.is_zero() {
                continue;
            }
            let (x, y) = (big(&a), big(&b));
            assert_eq!(big(&(a + b)), &x + &y);
            assert_eq!(big(&(a * b)), &x * &y);
            assert_eq!(big(&(a / b)), &x / &y);
            assert_eq!(big(&(a % b)), &x % &y);
            if a >= b {
                assert_eq!(big(&(a - b)), &x - &y);
            }
            assert_eq!(a.cmp(&b), x.cmp(&y));
            let s = rng.gen_range(0..300u64);
            assert_eq!(big(&(a >> s)), &x >> s);
            assert_eq!(big(&(a << s)), &x << s);
            assert_eq!(a.bits(), x.bits());
            assert_eq!(a.to_bytes_be(), x.to_bytes_be());
            assert_eq!(
                a.iter_u64_digits().collect::<Vec<_>>(),
                x.iter_u64_digits().collect::<Vec<_>>()
            );
        }
    }
}
