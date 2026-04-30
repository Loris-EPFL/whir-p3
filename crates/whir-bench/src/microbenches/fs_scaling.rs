//! FS challenge derivation cost: standard (absorbs ℓ roots) vs union
//! (absorbs 1 union root). Axis: `arity`. Both paths still sample
//! O(ℓ·log_m) fresh_betas, so the wall-clock speedup plateaus.

use p3_field::PrimeCharacteristicRing;
use rand::{SeedableRng, rngs::SmallRng};
use warp::fold::{derive_fold_challenges, derive_fold_challenges_union};

use crate::{
    fixtures::{DIGEST, F, MyChallenger, Perm},
    microbench::{Microbench, MicrobenchAxes, MicrobenchRow},
};

#[derive(Debug)]
pub struct FsScaling;

impl Microbench for FsScaling {
    const NAME: &'static str = "fs_scaling";

    fn run(axes: &MicrobenchAxes) -> Vec<MicrobenchRow> {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let log_m = axes.log_m;
        let log_n = axes.log_n;

        axes.arity
            .iter()
            .map(|&l| {
                let num_fresh = l - 1;

                let start_std = std::time::Instant::now();
                for _ in 0..100 {
                    let mut ch = MyChallenger::new(perm.clone());
                    let _c = derive_fold_challenges(
                        &[F::ZERO; DIGEST],
                        F::ZERO,
                        &vec![F::ZERO; log_n],
                        F::ZERO,
                        &vec![[F::ZERO; DIGEST]; num_fresh],
                        log_n,
                        log_m,
                        &mut ch,
                    );
                }
                let std_us = start_std.elapsed().as_micros() as f64 / 100.0;

                let start_uni = std::time::Instant::now();
                for _ in 0..100 {
                    let mut ch = MyChallenger::new(perm.clone());
                    let _c = derive_fold_challenges_union(
                        &[F::ZERO; DIGEST],
                        F::ZERO,
                        &vec![F::ZERO; log_n],
                        F::ZERO,
                        &[F::ZERO; DIGEST],
                        num_fresh,
                        log_m,
                        &mut ch,
                    );
                }
                let uni_us = start_uni.elapsed().as_micros() as f64 / 100.0;

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
