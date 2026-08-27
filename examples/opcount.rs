//! Field-operation counts of the relation bodies (they are generic over FieldLike, so a counting
//! wrapper runs them unchanged).
use ark_ff::UniformRand;
use bb_ref::base::field::{FieldLike, U256};
use bb_ref::base::{Fq, Fr};
use bb_ref::goblin::eccvm::relations::{EccvmRelations, ECCVM_RELATIONS};
use bb_ref::goblin::translator::relations::{TranslatorRelations, TRANSLATOR_RELATIONS};
use bb_ref::honk::flavor::MEGA_KERNEL;
use bb_ref::honk::relations::RelationParams;
use bb_ref::honk::sumcheck::{HonkRelations, RelationSet};
use std::cell::Cell;
use std::ops::*;

thread_local! { static MULS: Cell<u64> = const { Cell::new(0) }; static ADDS: Cell<u64> = const { Cell::new(0) }; }
#[derive(Clone, Debug, PartialEq)]
struct C<F>(F);
macro_rules! ops {
    ($F:ty) => {
        impl Add for C<$F> {
            type Output = Self;
            fn add(self, o: Self) -> Self {
                ADDS.with(|a| a.set(a.get() + 1));
                C(self.0 + o.0)
            }
        }
        impl Sub for C<$F> {
            type Output = Self;
            fn sub(self, o: Self) -> Self {
                ADDS.with(|a| a.set(a.get() + 1));
                C(self.0 - o.0)
            }
        }
        impl Mul for C<$F> {
            type Output = Self;
            fn mul(self, o: Self) -> Self {
                MULS.with(|a| a.set(a.get() + 1));
                C(self.0 * o.0)
            }
        }
        impl<'a> Add<&'a Self> for C<$F> {
            type Output = Self;
            fn add(self, o: &Self) -> Self {
                ADDS.with(|a| a.set(a.get() + 1));
                C(self.0 + o.0)
            }
        }
        impl<'a> Sub<&'a Self> for C<$F> {
            type Output = Self;
            fn sub(self, o: &Self) -> Self {
                ADDS.with(|a| a.set(a.get() + 1));
                C(self.0 - o.0)
            }
        }
        impl<'a> Mul<&'a Self> for C<$F> {
            type Output = Self;
            fn mul(self, o: &Self) -> Self {
                MULS.with(|a| a.set(a.get() + 1));
                C(self.0 * o.0)
            }
        }
        impl Neg for C<$F> {
            type Output = Self;
            fn neg(self) -> Self {
                C(-self.0)
            }
        }
        impl AddAssign for C<$F> {
            fn add_assign(&mut self, o: Self) {
                ADDS.with(|a| a.set(a.get() + 1));
                self.0 += o.0
            }
        }
        impl SubAssign for C<$F> {
            fn sub_assign(&mut self, o: Self) {
                ADDS.with(|a| a.set(a.get() + 1));
                self.0 -= o.0
            }
        }
        impl MulAssign for C<$F> {
            fn mul_assign(&mut self, o: Self) {
                MULS.with(|a| a.set(a.get() + 1));
                self.0 *= o.0
            }
        }
        impl<'a> AddAssign<&'a Self> for C<$F> {
            fn add_assign(&mut self, o: &Self) {
                ADDS.with(|a| a.set(a.get() + 1));
                self.0 += o.0
            }
        }
        impl<'a> SubAssign<&'a Self> for C<$F> {
            fn sub_assign(&mut self, o: &Self) {
                ADDS.with(|a| a.set(a.get() + 1));
                self.0 -= o.0
            }
        }
        impl<'a> MulAssign<&'a Self> for C<$F> {
            fn mul_assign(&mut self, o: &Self) {
                MULS.with(|a| a.set(a.get() + 1));
                self.0 *= o.0
            }
        }
        impl FieldLike for C<$F> {
            type Native = $F;
            type Ctx = ();
            fn ctx(&self) -> Option<()> {
                None
            }
            fn constant(v: $F) -> Self {
                C(v)
            }
            fn from_witness(_: &(), v: $F) -> Self {
                C(v)
            }
            fn value(&self) -> $F {
                self.0
            }
            fn invert(&self) -> Self {
                MULS.with(|a| a.set(a.get() + 100));
                C(self.0.invert())
            }
            fn assert_equal(&self, _: &Self) {}
        }
    };
}
ops!(Fq);
ops!(Fr);
fn count(label: &str, f: impl FnOnce()) {
    MULS.with(|m| m.set(0));
    ADDS.with(|a| a.set(0));
    f();
    println!(
        "{label:>28}: {:5} mul, {:5} add",
        MULS.with(|m| m.get()),
        ADDS.with(|a| a.get())
    );
}
fn main() {
    let mut rng = ark_std::test_rng();
    let row: Vec<C<Fq>> = (0..119).map(|_| C(Fq::rand(&mut rng))).collect();
    let mut p = RelationParams::<C<Fq>>::default();
    p.beta = C(Fq::rand(&mut rng));
    p.gamma = C(Fq::rand(&mut rng));
    p.beta_sqr = C(Fq::rand(&mut rng));
    p.beta_cube = C(Fq::rand(&mut rng));
    p.beta_quartic = C(Fq::rand(&mut rng));
    p.eccvm_set_permutation_delta = C(Fq::rand(&mut rng));
    let s = C(Fq::rand(&mut rng));
    let mut total = (0, 0);
    for (r, rel) in ECCVM_RELATIONS.iter().enumerate() {
        let mut acc = vec![C(Fq::from(0u64)); rel.num_subrelations()];
        MULS.with(|m| m.set(0));
        ADDS.with(|a| a.set(0));
        RelationSet::<C<Fq>>::accumulate(&EccvmRelations, r, &mut acc, &row, &p, &s);
        let (m, a) = (MULS.with(|m| m.get()), ADDS.with(|a| a.get()));
        total.0 += m * RelationSet::<C<Fq>>::partial_length(&EccvmRelations, r) as u64;
        total.1 += a;
        println!(
            "eccvm {rel:?}: {m} mul, {a} add per point (x{} points)",
            RelationSet::<C<Fq>>::partial_length(&EccvmRelations, r)
        );
    }
    println!("eccvm total muls per edge (sum over points): {}", total.0);
    let layout = MEGA_KERNEL.layout();
    let row: Vec<C<Fr>> = (0..layout.num_all()).map(|_| C(Fr::rand(&mut rng))).collect();
    let mut p = RelationParams::<C<Fr>>::default();
    p.beta = C(Fr::rand(&mut rng));
    p.gamma = C(Fr::rand(&mut rng));
    p.public_input_delta = C(Fr::rand(&mut rng));
    p.eta = C(Fr::rand(&mut rng));
    p.eta_two = C(Fr::rand(&mut rng));
    p.eta_three = C(Fr::rand(&mut rng));
    let s = C(Fr::rand(&mut rng));
    let rels = HonkRelations {
        flavor: &MEGA_KERNEL,
        layout: &layout,
    };
    for r in 0..MEGA_KERNEL.relations.len() {
        let mut acc = vec![C(Fr::from(0u64)); RelationSet::<C<Fr>>::num_subrelations(&rels, r)];
        count(&format!("kernel {:?}", MEGA_KERNEL.relations[r]), || {
            RelationSet::<C<Fr>>::accumulate(&rels, r, &mut acc, &row, &p, &s)
        });
    }
    let row: Vec<C<Fr>> = (0..bb_ref::goblin::translator::NUM_ALL_ENTITIES)
        .map(|_| C(Fr::rand(&mut rng)))
        .collect();
    for (r, rel) in TRANSLATOR_RELATIONS.iter().enumerate() {
        let mut acc = vec![C(Fr::from(0u64)); rel.num_subrelations()];
        count(&format!("translator {rel:?}"), || {
            RelationSet::<C<Fr>>::accumulate(&TranslatorRelations, r, &mut acc, &row, &p, &s)
        });
    }
    let _ = U256::default();
}
