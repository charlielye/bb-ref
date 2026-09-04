//! MSM inner-loop design probe: packed-Jacobian bucket accumulation (candidate A) vs
//! packed-columns batched-affine tree (candidate B) vs the current scalar tree (baseline C),
//! all as array-throughput loops over pre-packed data — the shape stage 4 would actually run
//! if gather wrote packed coordinate columns. wasm32+simd128 only (native prints a notice).
//!
//! Per-pair op counts modeled:
//!   A: madd-2007-bl mixed add, 11 quad muls + ~10 quad add/sub per 4 lane-adds, no inversion,
//!      one sequential dependence chain per lane — K accumulator groups interleave for ILP.
//!   B: tree level = 1 sub (den) + 3 muls (batched-inversion chain) + 3 muls / 5 add-sub
//!      (lambda, x3, y3) per 4 pairs, one 4-lane scalar inversion per level.
//!   C: the same level in scalar ark Fq (what src/base/msm.rs pays today).

fn main() {
    #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
    run();
    #[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
    println!("msmmodel requires wasm32 with +simd128");
}

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
fn run() {
    use ark_bn254::Fq;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use bb_ref::base::field::FieldLike;
    use bb_ref::honk::quadf::QuadF;
    use std::hint::black_box;
    use std::time::Instant;

    type Q = QuadF<Fq>;
    let mut rng = ark_std::test_rng();
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8_000_000);

    fn rand_q<R: ark_std::rand::Rng>(rng: &mut R) -> (QuadF<Fq>, [Fq; 4]) {
        let l: [Fq; 4] = core::array::from_fn(|_| Fq::rand(rng));
        (QuadF::lanes(l[0], l[1], l[2], l[3]), l)
    }

    // ---- Candidate A: packed Jacobian mixed add (madd-2007-bl), chained accumulators ----
    struct JacQ {
        x: QuadF<Fq>,
        y: QuadF<Fq>,
        z: QuadF<Fq>,
    }
    #[inline(always)]
    fn mixed_add(acc: &mut JacQ, px: &QuadF<Fq>, py: &QuadF<Fq>) {
        let z1z1 = acc.z * &acc.z;
        let u2 = *px * &z1z1;
        let s2 = *py * &(acc.z * &z1z1);
        let h = u2 - &acc.x;
        let hh = h * &h;
        let i4 = {
            let d = hh + &hh;
            d + &d
        };
        let j = h * &i4;
        let r = {
            let t = s2 - &acc.y;
            t + &t
        };
        let v = acc.x * &i4;
        let x3 = r * &r - &j - &(v + &v);
        let zh = acc.z + &h;
        acc.z = zh * &zh - &z1z1 - &hh;
        let yj = acc.y * &j;
        acc.y = r * &(v - &x3) - &(yj + &yj);
        acc.x = x3;
    }

    // Scalar reference of the same formula for the cross-check.
    fn mixed_add_ref(acc: &mut (Fq, Fq, Fq), px: Fq, py: Fq) {
        let z1z1 = acc.2 * acc.2;
        let u2 = px * z1z1;
        let s2 = py * acc.2 * z1z1;
        let h = u2 - acc.0;
        let hh = h * h;
        let i4 = hh.double().double();
        let j = h * i4;
        let r = (s2 - acc.1).double();
        let v = acc.0 * i4;
        let x3 = r * r - j - v.double();
        acc.2 = (acc.2 + h).square() - z1z1 - hh;
        acc.1 = r * (v - x3) - (acc.1 * j).double();
        acc.0 = x3;
    }

    {
        let mut refs: [(Fq, Fq, Fq); 4] =
            core::array::from_fn(|_| (Fq::rand(&mut rng), Fq::rand(&mut rng), Fq::rand(&mut rng)));
        let mut acc = JacQ {
            x: Q::lanes(refs[0].0, refs[1].0, refs[2].0, refs[3].0),
            y: Q::lanes(refs[0].1, refs[1].1, refs[2].1, refs[3].1),
            z: Q::lanes(refs[0].2, refs[1].2, refs[2].2, refs[3].2),
        };
        for _ in 0..64 {
            let px: [Fq; 4] = core::array::from_fn(|_| Fq::rand(&mut rng));
            let py: [Fq; 4] = core::array::from_fn(|_| Fq::rand(&mut rng));
            mixed_add(
                &mut acc,
                &Q::lanes(px[0], px[1], px[2], px[3]),
                &Q::lanes(py[0], py[1], py[2], py[3]),
            );
            for l in 0..4 {
                mixed_add_ref(&mut refs[l], px[l], py[l]);
            }
        }
        assert!(
            acc.x == Q::lanes(refs[0].0, refs[1].0, refs[2].0, refs[3].0),
            "A x mismatch"
        );
        assert!(
            acc.y == Q::lanes(refs[0].1, refs[1].1, refs[2].1, refs[3].1),
            "A y mismatch"
        );
        assert!(
            acc.z == Q::lanes(refs[0].2, refs[1].2, refs[2].2, refs[3].2),
            "A z mismatch"
        );
        println!("A cross-check OK");
    }

    const NG: usize = 4096;
    let pts: Vec<(Q, Q)> = (0..NG).map(|_| (rand_q(&mut rng).0, rand_q(&mut rng).0)).collect();
    for k in [1usize, 2, 4, 8] {
        let mut accs: Vec<JacQ> = (0..k)
            .map(|_| JacQ {
                x: rand_q(&mut rng).0,
                y: rand_q(&mut rng).0,
                z: rand_q(&mut rng).0,
            })
            .collect();
        let reps = (n / (NG * 4)).max(1);
        let t = Instant::now();
        for _ in 0..reps {
            for (i, (px, py)) in pts.iter().enumerate() {
                mixed_add(&mut accs[i & (k - 1)], px, py);
            }
        }
        let ns = t.elapsed().as_nanos() as f64 / (reps * NG * 4) as f64;
        black_box(accs[0].x.hsum());
        println!("A jacobian mixed-add, {k} chains: {ns:.1} ns/point-add");
    }

    // ---- Candidate B: packed batched-affine tree level, packed end-to-end ----
    let (ax, axl): (Vec<Q>, Vec<[Fq; 4]>) = (0..NG).map(|_| rand_q(&mut rng)).unzip();
    let (ay, ayl): (Vec<Q>, Vec<[Fq; 4]>) = (0..NG).map(|_| rand_q(&mut rng)).unzip();
    let (bx, bxl): (Vec<Q>, Vec<[Fq; 4]>) = (0..NG).map(|_| rand_q(&mut rng)).unzip();
    let (by, byl): (Vec<Q>, Vec<[Fq; 4]>) = (0..NG).map(|_| rand_q(&mut rng)).unzip();
    let mut dens: Vec<Q> = vec![Q::splat(Fq::ZERO); NG];
    let mut prod: Vec<Q> = vec![Q::splat(Fq::ZERO); NG];
    let mut ox: Vec<Q> = vec![Q::splat(Fq::ZERO); NG];
    let mut oy: Vec<Q> = vec![Q::splat(Fq::ZERO); NG];
    let mut level =
        |ax: &[Q], ay: &[Q], bx: &[Q], by: &[Q], dens: &mut [Q], prod: &mut [Q], ox: &mut [Q], oy: &mut [Q]| {
            for i in 0..NG {
                dens[i] = bx[i] - &ax[i];
            }
            prod[0] = dens[0];
            for i in 1..NG {
                prod[i] = prod[i - 1] * &dens[i];
            }
            let mut inv = prod[NG - 1].invert(); // one 4-lane scalar inversion per level
            for i in (1..NG).rev() {
                let d = inv * &prod[i - 1];
                inv = inv * &dens[i];
                dens[i] = d;
            }
            dens[0] = inv;
            for i in 0..NG {
                let lambda = (by[i] - &ay[i]) * &dens[i];
                let x3 = lambda * &lambda - &ax[i] - &bx[i];
                oy[i] = lambda * &(ax[i] - &x3) - &ay[i];
                ox[i] = x3;
            }
        };
    // Cross-check one level against the scalar affine-add formula.
    {
        level(&ax, &ay, &bx, &by, &mut dens, &mut prod, &mut ox, &mut oy);
        for i in [0usize, 1, NG / 2, NG - 1] {
            let mut ex = [Fq::ZERO; 4];
            let mut ey = [Fq::ZERO; 4];
            for l in 0..4 {
                let lambda = (byl[i][l] - ayl[i][l]) / (bxl[i][l] - axl[i][l]);
                ex[l] = lambda.square() - axl[i][l] - bxl[i][l];
                ey[l] = lambda * (axl[i][l] - ex[l]) - ayl[i][l];
            }
            assert!(ox[i] == Q::lanes(ex[0], ex[1], ex[2], ex[3]), "B x3 mismatch group {i}");
            assert!(oy[i] == Q::lanes(ey[0], ey[1], ey[2], ey[3]), "B y3 mismatch group {i}");
        }
        println!("B cross-check OK");
    }

    let reps = (n / (NG * 4 * 6)).max(1);
    let t = Instant::now();
    for _ in 0..reps {
        level(&ax, &ay, &bx, &by, &mut dens, &mut prod, &mut ox, &mut oy);
    }
    black_box(ox[0].hsum());
    println!(
        "B packed tree level: {:.1} ns/pair",
        t.elapsed().as_nanos() as f64 / (reps * NG * 4) as f64
    );

    // ---- Baseline C: the same tree level in scalar (what msm.rs pays today) ----
    let sax: Vec<Fq> = (0..NG * 4).map(|_| Fq::rand(&mut rng)).collect();
    let say: Vec<Fq> = (0..NG * 4).map(|_| Fq::rand(&mut rng)).collect();
    let sbx: Vec<Fq> = (0..NG * 4).map(|_| Fq::rand(&mut rng)).collect();
    let sby: Vec<Fq> = (0..NG * 4).map(|_| Fq::rand(&mut rng)).collect();
    let m = NG * 4;
    let mut sdens: Vec<Fq> = vec![Fq::ZERO; m];
    let mut sprod: Vec<Fq> = vec![Fq::ZERO; m];
    let (mut sox, mut soy): (Vec<Fq>, Vec<Fq>) = (vec![Fq::ZERO; m], vec![Fq::ZERO; m]);
    let reps = (n / (m * 6)).max(1);
    let t = Instant::now();
    for _ in 0..reps {
        for i in 0..m {
            sdens[i] = sbx[i] - sax[i];
        }
        sprod[0] = sdens[0];
        for i in 1..m {
            sprod[i] = sprod[i - 1] * sdens[i];
        }
        let mut inv = sprod[m - 1].inverse().unwrap();
        for i in (1..m).rev() {
            let d = inv * sprod[i - 1];
            inv *= sdens[i];
            sdens[i] = d;
        }
        sdens[0] = inv;
        for i in 0..m {
            let lambda = (sby[i] - say[i]) * sdens[i];
            let x3 = lambda.square() - sax[i] - sbx[i];
            soy[i] = lambda * (sax[i] - x3) - say[i];
            sox[i] = x3;
        }
    }
    black_box((sox[0], soy[0]));
    println!(
        "C scalar tree level: {:.1} ns/pair",
        t.elapsed().as_nanos() as f64 / (reps * m) as f64
    );
}
