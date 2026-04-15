use std::time::Instant;

use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_poseidon2::poseidon2_round_numbers_128;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{rngs::SmallRng, SeedableRng};

use whir_circuit::poseidon2::Poseidon2CircuitConfig;

use accumulation::linearized::linearized_statement_from_spartan_proof;
use warp::{
    accumulator::{WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness},
    fold::WarpFoldResult,
};
use whir_core::poly::evals::EvaluationsList;
use whir_core::poly::multilinear::MultilinearPoint;
use whir_pcs::whir::{
    constraints::statement::LinearStatement,
    parameters::WhirConfig,
};
use whir_core::parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters};
use whir_pcs::fiat_shamir::domain_separator::DomainSeparator;
use whir_spartan::{
    r1cs::{R1CSInstance, R1CSShape},
    r1cs_prover::R1CSProver,
};

pub type F = KoalaBear;
pub type EF = BinomialExtensionField<F, 4>;
pub type Perm = Poseidon2KoalaBear<16>;
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;
pub const DIGEST: usize = 8;
pub const RS_LOG_INV_RATE: usize = 1;

pub fn parse_csv(s: &str) -> Vec<usize> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

pub fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

pub fn make_whir_config(nv: usize) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    WhirConfig::new(
        nv,
        ProtocolParameters {
            security_level: 100,
            pow_bits: 0,
            rs_domain_initial_reduction_factor: 1,
            folding_factor: FoldingFactor::Constant(2),
            merkle_hash: MyHash::new(p.clone()),
            merkle_compress: MyCompress::new(p),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: RS_LOG_INV_RATE,
        },
    )
}

pub fn make_ds(c: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>) -> DomainSeparator<EF, F> {
    let mut d = DomainSeparator::<EF, F>::new(vec![]);
    d.commit_statement::<_, _, _, DIGEST>(c);
    d.add_whir_proof::<_, _, _, DIGEST>(c);
    d
}

pub fn seed_ch(s: u64, d: &DomainSeparator<EF, F>) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(s));
    let mut c = MyChallenger::new(p);
    d.observe_domain_separator(&mut c);
    c
}

pub fn make_challenger(seed: u64) -> MyChallenger {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    MyChallenger::new(p)
}

pub fn make_hc() -> (MyHash, MyCompress) {
    let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
    (MyHash::new(p.clone()), MyCompress::new(p))
}

pub fn rebuild_acc(r: &WarpFoldResult<F>) -> WarpAccumulator<F, F, F, DIGEST> {
    let ec = r
        .witness
        .codeword
        .evaluate_hypercube_base(&MultilinearPoint::new(r.instance.eval_point.clone()));
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: r.commitment_root,
            eval_point: r.instance.eval_point.clone(),
            eval_claim: ec,
            pesat_tau: r.instance.pesat_tau.clone(),
            pesat_x: r.instance.pesat_x.clone(),
            pesat_target: r.instance.pesat_target,
        },
        r.witness.clone(),
    )
}

pub fn make_zero_acc(
    nw: usize,
    lc: usize,
    lm: usize,
    ni: usize,
) -> WarpAccumulator<F, F, F, DIGEST> {
    WarpAccumulator::new(
        WarpAccumulatorInstance {
            commitment_root: [F::ZERO; DIGEST],
            eval_point: vec![F::ZERO; lc],
            eval_claim: F::ZERO,
            pesat_tau: vec![F::ZERO; lm],
            pesat_x: vec![F::ZERO; ni],
            pesat_target: F::ZERO,
        },
        WarpAccumulatorWitness {
            codeword: EvaluationsList::new(vec![F::ZERO; 1 << lc]),
            witness: vec![F::ZERO; nw],
        },
    )
}

#[derive(Debug)]
pub struct LinearizedInstance {
    pub witness: EvaluationsList<F>,
    pub linear: LinearStatement<F, EF>,
}

pub fn spartan_linearize_all(
    shape: &R1CSShape<F>,
    instance: &R1CSInstance<F>,
    total_n: usize,
) -> (Vec<LinearizedInstance>, f64) {
    let spartan = R1CSProver::new();
    let start = Instant::now();
    let mut result = Vec::with_capacity(total_n);
    for i in 0..total_n {
        let p = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(i as u64 + 200));
        let mut ch = MyChallenger::new(p);
        let proof = spartan.prove::<EF, _>(instance, &mut ch);
        let w = spartan.prepare_witness(instance);
        let l = linearized_statement_from_spartan_proof(shape, &proof, EF::from_u64(3));
        result.push(LinearizedInstance {
            witness: w,
            linear: l,
        });
    }
    let us = start.elapsed().as_micros() as f64;
    (result, us)
}

pub fn make_dft() -> Radix2DFTSmallBatch<F> {
    Radix2DFTSmallBatch::<F>::default()
}

pub fn produce_synthetic_r1cs(
    log_size: usize,
) -> (R1CSShape<F>, R1CSInstance<F>, usize, usize, usize, usize) {
    let num_cons = 1 << log_size;
    let num_vars = 1 << log_size;
    let num_inputs = 8;
    let mut rng = SmallRng::seed_from_u64(5);
    let (shape, instance) =
        R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);
    let spartan = R1CSProver::new();
    let sample_w = spartan.prepare_witness(&instance);
    let num_witness = (sample_w.num_evals() - num_inputs).next_power_of_two();
    let witness_num_vars = num_witness.trailing_zeros() as usize;
    let log_code = witness_num_vars + RS_LOG_INV_RATE;
    let log_m = shape
        .num_cons()
        .next_power_of_two()
        .trailing_zeros() as usize;
    (shape, instance, num_witness, num_inputs, log_code, log_m)
}

/// Build the Poseidon2 permutation and circuit config used by recursive IVC paths.
pub fn make_poseidon2_circuit_config() -> (Perm, Poseidon2CircuitConfig<F, 16>) {
    const SBOX_DEGREE: u64 = 3; // KoalaBear
    let seed = 99u64;
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    let (rf, rp) = poseidon2_round_numbers_128::<F>(16, SBOX_DEGREE)
        .expect("unsupported Poseidon2 parameters");
    let config = Poseidon2CircuitConfig::<F, 16>::from_rng(
        rf,
        rp,
        SBOX_DEGREE,
        &mut SmallRng::seed_from_u64(seed),
    );
    (perm, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spartan_linearize_all_returns_correct_count() {
        let (shape, instance, _, _, _, _) = produce_synthetic_r1cs(10);
        let (instances, _us) = spartan_linearize_all(&shape, &instance, 4);
        assert_eq!(instances.len(), 4);
    }
}
