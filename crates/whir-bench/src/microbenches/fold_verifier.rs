//! Full fold-verifier wall-clock: FS derivation + initial-target compute
//! + twin-constraint sumcheck verification. Axis: `arity`.
//!
//! Non-zero μ_i, η_i are passed into the target computation so the
//! compiler can't elide the work (earlier version had an `eq * F::ZERO`
//! bug that let LLVM dead-code-eliminate the whole loop).

use p3_field::{Field, PrimeCharacteristicRing};
use rand::{SeedableRng, rngs::SmallRng};
use warp::fold::{derive_fold_challenges, derive_fold_challenges_union, warp_fold_verify_sumcheck};

use crate::{
    fixtures::{DIGEST, F, MyChallenger, Perm},
    microbench::{Microbench, MicrobenchAxes, MicrobenchRow},
};

#[derive(Debug)]
pub struct FoldVerifier;

fn eval_deg2_at(h0: F, h1: F, h2: F, c: F) -> F {
    let two = F::from_u64(2);
    let inv2 = two.inverse();
    h0 * ((c - F::ONE) * (c - two) * inv2) - h1 * (c * (c - two)) + h2 * (c * (c - F::ONE) * inv2)
}

fn build_trace(initial_target: F, chals: &[F]) -> Vec<Vec<F>> {
    let two_inv = F::from_u64(2).inverse();
    let mut round_polys = Vec::with_capacity(chals.len());
    let mut expected = initial_target;
    for &c in chals {
        let half = expected * two_inv;
        let poly = vec![half, half, F::ONE];
        expected = eval_deg2_at(poly[0], poly[1], poly[2], c);
        round_polys.push(poly);
    }
    round_polys
}

impl Microbench for FoldVerifier {
    const NAME: &'static str = "fold_verify";

    fn run(axes: &MicrobenchAxes) -> Vec<MicrobenchRow> {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let log_m = axes.log_m;
        let log_n = axes.log_n;

        axes.arity
            .iter()
            .map(|&l| {
                let num_fresh = l - 1;
                let log_l = l.trailing_zeros() as usize;
                let mu_vals: Vec<F> = (0..l).map(|i| F::from_u64(i as u64 + 1)).collect();
                let eta_vals: Vec<F> = (0..l).map(|i| F::from_u64(7 + 3 * i as u64)).collect();

                // Standard
                let start_std = std::time::Instant::now();
                let mut std_accum = F::ZERO;
                for iter in 0..100 {
                    let mut ch = MyChallenger::new(perm.clone());
                    let (omega, tau, _) = derive_fold_challenges(
                        &[F::ZERO; DIGEST],
                        F::ZERO,
                        &vec![F::ZERO; log_n],
                        F::ZERO,
                        &vec![[F::ZERO; DIGEST]; num_fresh],
                        log_n,
                        log_m,
                        &mut ch,
                    );
                    let mut initial_target = F::ZERO;
                    for idx in 0..l {
                        let mut eq = F::ONE;
                        for j in 0..log_l {
                            let bit = (idx >> j) & 1;
                            eq *= if bit == 1 { tau[j] } else { F::ONE - tau[j] };
                        }
                        initial_target += eq * (mu_vals[idx] + omega * eta_vals[idx]);
                    }
                    let chals: Vec<F> = (0..log_l)
                        .map(|i| F::from_u64(i as u64 + 1 + iter as u64))
                        .collect();
                    let polys = build_trace(initial_target, &chals);
                    let final_eval = warp_fold_verify_sumcheck(initial_target, &polys, &chals)
                        .expect("sumcheck trace rejected");
                    std_accum += final_eval;
                }
                let std_us = start_std.elapsed().as_micros() as f64 / 100.0;
                let _ = std::hint::black_box(std_accum);

                // Union
                let start_uni = std::time::Instant::now();
                let mut uni_accum = F::ZERO;
                for iter in 0..100 {
                    let mut ch = MyChallenger::new(perm.clone());
                    let (omega, tau, _) = derive_fold_challenges_union(
                        &[F::ZERO; DIGEST],
                        F::ZERO,
                        &vec![F::ZERO; log_n],
                        F::ZERO,
                        &[F::ZERO; DIGEST],
                        num_fresh,
                        log_m,
                        &mut ch,
                    );
                    let mut initial_target = F::ZERO;
                    for idx in 0..l {
                        let mut eq = F::ONE;
                        for j in 0..log_l {
                            let bit = (idx >> j) & 1;
                            eq *= if bit == 1 { tau[j] } else { F::ONE - tau[j] };
                        }
                        initial_target += eq * (mu_vals[idx] + omega * eta_vals[idx]);
                    }
                    let chals: Vec<F> = (0..log_l)
                        .map(|i| F::from_u64(i as u64 + 1 + iter as u64))
                        .collect();
                    let polys = build_trace(initial_target, &chals);
                    let final_eval = warp_fold_verify_sumcheck(initial_target, &polys, &chals)
                        .expect("sumcheck trace rejected");
                    uni_accum += final_eval;
                }
                let uni_us = start_uni.elapsed().as_micros() as f64 / 100.0;
                let _ = std::hint::black_box(uni_accum);

                MicrobenchRow::new(Self::NAME)
                    .with_axis("arity", l)
                    .with_axis("log_m", log_m)
                    .with_axis("log_n", log_n)
                    .with_value("standard_us", std_us)
                    .with_value("union_us", uni_us)
                    .with_value("speedup", std_us / uni_us)
            })
            .collect()
    }
}
