use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PackedValue, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};

use crate::{
    accumulation::{
        accumulator::{Accumulator, AccumulatorInstance, AccumulatorWitness},
        quasar::fresh::{FreshLinearInstance, FreshLinearInstancePublic},
    },
    fiat_shamir::errors::FiatShamirError,
    parameters::ProtocolParameters,
    poly::evals::EvaluationsList,
    spartan::encoding::eq_poly_at_index,
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{InitialClaim, LinearStatement},
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover as WhirProver,
        verifier::{errors::VerifierError, Verifier as WhirVerifier},
    },
};

#[derive(Clone, Debug)]
pub struct QuasarTranscript<F: Field> {
    pub tau_q: Vec<F>,
    pub weights: Vec<F>,
    pub bridge_point: Vec<F>,
    pub bridge_value: F,
}

impl<F: Field> QuasarTranscript<F> {
    pub fn replay<Challenger>(&self, challenger: &mut Challenger)
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let tau = (0..self.tau_q.len())
            .map(|_| challenger.sample())
            .collect::<Vec<_>>();
        assert_eq!(tau, self.tau_q, "quasar tau mismatch");
        let bridge = (0..self.bridge_point.len())
            .map(|_| challenger.sample())
            .collect::<Vec<_>>();
        assert_eq!(bridge, self.bridge_point, "quasar bridge point mismatch");
    }
}

#[derive(Clone, Debug)]
pub struct QuasarFrontendProof<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub transcript: QuasarTranscript<F>,
    pub union_proof: WhirProof<F, EF, W, DIGEST_ELEMS>,
    pub union_claim: InitialClaim<F, EF>,
    pub squashed_proof: WhirProof<F, EF, W, DIGEST_ELEMS>,
    pub squashed_claim: InitialClaim<F, EF>,
}

#[derive(Clone, Debug)]
pub struct QuasarFrontendOutput<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub accumulator: Accumulator<F, EF, W, DIGEST_ELEMS>,
    pub proof: QuasarFrontendProof<F, EF, W, DIGEST_ELEMS>,
}

fn with_num_variables<EF, F, H, C, Challenger>(
    config: &WhirConfig<EF, F, H, C, Challenger>,
    num_variables: usize,
) -> WhirConfig<EF, F, H, C, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    H: Clone,
    C: Clone,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let params = ProtocolParameters {
        starting_log_inv_rate: config.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: config.rs_domain_initial_reduction_factor,
        folding_factor: config.folding_factor,
        soundness_type: config.soundness_type,
        security_level: config.security_level,
        pow_bits: config.max_pow_bits,
        merkle_hash: config.merkle_hash.clone(),
        merkle_compress: config.merkle_compress.clone(),
    };
    WhirConfig::new(num_variables, params)
}

fn sample_tau<F, Challenger>(challenger: &mut Challenger, batch_size: usize) -> Vec<F>
where
    F: Field,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let log_batch = batch_size.trailing_zeros() as usize;
    (0..log_batch).map(|_| challenger.sample()).collect()
}

fn eq_weights<F: Field>(tau_q: &[F], batch_size: usize) -> Vec<F> {
    (0..batch_size)
        .map(|idx| eq_poly_at_index::<F, F>(idx, tau_q))
        .collect()
}

fn eq_linear_claim<F: Field, EF: ExtensionField<F>>(
    point: &[F],
    value: F,
) -> LinearStatement<F, EF> {
    let mut statement = LinearStatement::<F, EF>::initialize(point.len());
    let weights = EvaluationsList::new(
        (0..(1usize << point.len()))
            .map(|idx| eq_poly_at_index::<F, F>(idx, point))
            .map(EF::from)
            .collect(),
    );
    statement.add_constraint(weights, EF::from(value));
    statement
}

fn eval_mle_at_point<F: Field>(poly: &EvaluationsList<F>, point: &[F]) -> F {
    poly.as_slice()
        .iter()
        .enumerate()
        .fold(F::ZERO, |acc, (idx, &w)| {
            acc + w * eq_poly_at_index::<F, F>(idx, point)
        })
}

fn build_union_witness<F: Field, EF: ExtensionField<F>>(
    instances: &[FreshLinearInstance<F, EF>],
) -> EvaluationsList<F> {
    let witness_vars = instances[0].witness_poly.num_variables();
    let batch_vars = instances.len().trailing_zeros() as usize;
    let mut evals = Vec::with_capacity((1usize << witness_vars) * (1usize << batch_vars));
    for instance in instances {
        evals.extend_from_slice(instance.witness_poly.as_slice());
    }
    EvaluationsList::new(evals)
}

fn squash_witnesses<F: Field, EF: ExtensionField<F>>(
    instances: &[FreshLinearInstance<F, EF>],
    weights: &[F],
) -> EvaluationsList<F> {
    let num_variables = instances[0].witness_poly.num_variables();
    let mut squashed = EvaluationsList::zero(num_variables);
    for (instance, &coeff) in instances.iter().zip(weights.iter()) {
        squashed
            .iter_mut()
            .zip(instance.witness_poly.as_slice().iter())
            .for_each(|(acc, &value)| *acc += coeff * value);
    }
    squashed
}

fn build_union_linear_claim<F: Field, EF: ExtensionField<F>>(
    instances: &[FreshLinearInstance<F, EF>],
    weights: &[F],
    bridge_point: &[F],
    bridge_value: F,
) -> LinearStatement<F, EF> {
    let witness_vars = instances[0].linear_claim.num_variables();
    let batch_vars = instances.len().trailing_zeros() as usize;
    let total_vars = witness_vars + batch_vars;
    let block_size = 1 << witness_vars;
    let mut statement = LinearStatement::<F, EF>::initialize(total_vars);

    for (idx, (instance, &coeff_f)) in instances.iter().zip(weights.iter()).enumerate() {
        let coeff = EF::from(coeff_f);
        let (claim_weights, &target) = instance
            .linear_claim
            .iter()
            .next()
            .expect("one linear claim per fresh instance");
        let mut extended = EvaluationsList::zero(total_vars);
        let offset = idx * block_size;
        extended.as_mut_slice()[offset..offset + block_size]
            .copy_from_slice(claim_weights.as_slice());
        extended.as_mut_slice()[offset..offset + block_size]
            .iter_mut()
            .for_each(|w| *w *= coeff);
        statement.add_constraint(extended, coeff * target);
    }

    let _ = bridge_point;
    let _ = bridge_value;
    statement
}

fn add_union_bridge_constraint<F: Field, EF: ExtensionField<F>>(
    statement: &mut LinearStatement<F, EF>,
    tau_q: &[F],
    bridge_point: &[F],
    bridge_value: F,
) {
    let mut full_point = bridge_point.to_vec();
    full_point.extend_from_slice(tau_q);
    let bridge_claim = eq_linear_claim::<F, EF>(&full_point, bridge_value);
    let (weights, &target) = bridge_claim.iter().next().unwrap();
    statement.add_constraint(weights.clone(), target);
}

#[derive(Debug)]
pub struct QuasarFrontendProver<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: Field,
    EF: ExtensionField<F>;

impl<'a, EF, F, H, C, Challenger> QuasarFrontendProver<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    pub fn squash_and_prove<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        challenger: &mut Challenger,
        fresh_instances: &[FreshLinearInstance<F, EF>],
    ) -> Result<QuasarFrontendOutput<F, EF, W, DIGEST_ELEMS>, FiatShamirError>
    where
        Dft: TwoAdicSubgroupDft<F>,
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync
            + Clone,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync
            + Clone,
        Challenger: CanObserve<Hash<F, W, DIGEST_ELEMS>>,
        [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        assert!(!fresh_instances.is_empty());
        assert!(fresh_instances.len().is_power_of_two());
        for instance in fresh_instances {
            assert!(instance.verify());
        }

        let tau_q = sample_tau(challenger, fresh_instances.len());
        let weights = eq_weights(&tau_q, fresh_instances.len());
        let bridge_point = (0..fresh_instances[0].witness_poly.num_variables())
            .map(|_| challenger.sample())
            .collect::<Vec<_>>();

        let squashed_witness = squash_witnesses(fresh_instances, &weights);
        let bridge_value = eval_mle_at_point(&squashed_witness, &bridge_point);
        let squashed_claim = eq_linear_claim::<F, EF>(&bridge_point, bridge_value);

        let union_witness = build_union_witness(fresh_instances);
        let union_num_vars = union_witness.num_variables();
        let mut union_claim =
            build_union_linear_claim(fresh_instances, &weights, &bridge_point, bridge_value);
        add_union_bridge_constraint(&mut union_claim, &tau_q, &bridge_point, bridge_value);

        let union_config = with_num_variables(self.0, union_num_vars);
        let mut union_statement =
            union_config.initial_statement_with_linear(union_witness, union_claim.clone());
        let union_initial_claim = union_statement.normalize_claim();
        let mut union_proof = WhirProof::<F, EF, W, DIGEST_ELEMS>::from_whir_config(&union_config);
        let union_commitment = CommitmentWriter::new(&union_config)
            .commit::<_, P, W, PW, DIGEST_ELEMS>(
                dft,
                &mut union_proof,
                challenger,
                &mut union_statement,
            )?;
        WhirProver(&union_config).prove::<_, P, W, PW, DIGEST_ELEMS>(
            dft,
            &mut union_proof,
            challenger,
            &union_statement,
            union_commitment,
        )?;

        let mut squashed_statement = self
            .0
            .initial_statement_with_linear(squashed_witness.clone(), squashed_claim.clone());
        let squashed_initial_claim = squashed_statement.normalize_claim();
        let mut squashed_proof = WhirProof::<F, EF, W, DIGEST_ELEMS>::from_whir_config(self.0);
        let squashed_commitment = CommitmentWriter::new(self.0)
            .commit::<_, P, W, PW, DIGEST_ELEMS>(
                dft,
                &mut squashed_proof,
                challenger,
                &mut squashed_statement,
            )?;
        WhirProver(self.0).prove::<_, P, W, PW, DIGEST_ELEMS>(
            dft,
            &mut squashed_proof,
            challenger,
            &squashed_statement,
            squashed_commitment,
        )?;

        let accumulator = Accumulator::new(
            AccumulatorInstance {
                commitment_root: squashed_proof.initial_commitment,
                linear_claim: squashed_claim,
                _marker: PhantomData,
            },
            AccumulatorWitness {
                poly: squashed_witness,
            },
        );

        Ok(QuasarFrontendOutput {
            accumulator,
            proof: QuasarFrontendProof {
                transcript: QuasarTranscript {
                    tau_q,
                    weights,
                    bridge_point,
                    bridge_value,
                },
                union_proof,
                union_claim: union_initial_claim,
                squashed_proof,
                squashed_claim: squashed_initial_claim,
            },
        })
    }
}

#[derive(Debug)]
pub struct QuasarFrontendVerifier<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: Field,
    EF: ExtensionField<F>;

impl<'a, EF, F, H, C, Challenger> QuasarFrontendVerifier<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    pub fn verify<P, W, PW, const DIGEST_ELEMS: usize>(
        &self,
        challenger: &mut Challenger,
        fresh_instances: &[FreshLinearInstancePublic<F, EF>],
        output: &QuasarFrontendOutput<F, EF, W, DIGEST_ELEMS>,
    ) -> Result<AccumulatorInstance<F, EF, W, DIGEST_ELEMS>, VerifierError>
    where
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync
            + Clone,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync
            + Clone,
        Challenger: CanObserve<Hash<F, W, DIGEST_ELEMS>>,
        [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        output.proof.transcript.replay(challenger);
        let expected_weights = eq_weights(&output.proof.transcript.tau_q, fresh_instances.len());
        if expected_weights != output.proof.transcript.weights {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "quasar weights mismatch".into(),
            });
        }

        let bridge_target = output.proof.transcript.bridge_value;

        let witness_vars = fresh_instances[0].linear_claim.num_variables();
        let batch_vars = fresh_instances.len().trailing_zeros() as usize;
        let total_vars = witness_vars + batch_vars;
        let block_size = 1 << witness_vars;
        let mut expected_union_claim = LinearStatement::<F, EF>::initialize(total_vars);
        for (idx, (instance, &coeff_f)) in fresh_instances
            .iter()
            .zip(expected_weights.iter())
            .enumerate()
        {
            let coeff = EF::from(coeff_f);
            let (weights, &target) = instance.linear_claim.iter().next().unwrap();
            let mut extended = EvaluationsList::zero(total_vars);
            let offset = idx * block_size;
            extended.as_mut_slice()[offset..offset + block_size]
                .copy_from_slice(weights.as_slice());
            extended.as_mut_slice()[offset..offset + block_size]
                .iter_mut()
                .for_each(|w| *w *= coeff);
            expected_union_claim.add_constraint(extended, coeff * target);
        }
        add_union_bridge_constraint(
            &mut expected_union_claim,
            &output.proof.transcript.tau_q,
            &output.proof.transcript.bridge_point,
            bridge_target,
        );
        if expected_union_claim != output.proof.union_claim.linear_statement {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "quasar union claim mismatch".into(),
            });
        }

        let union_config = with_num_variables(self.0, total_vars);
        let parsed_union = CommitmentReader::new(&union_config)
            .parse_commitment::<W, DIGEST_ELEMS>(&output.proof.union_proof, challenger);
        WhirVerifier::new(&union_config).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &output.proof.union_proof,
            challenger,
            &parsed_union,
            output.proof.union_claim.clone(),
        )?;

        let parsed_sq = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&output.proof.squashed_proof, challenger);
        WhirVerifier::new(self.0).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &output.proof.squashed_proof,
            challenger,
            &parsed_sq,
            output.proof.squashed_claim.clone(),
        )?;

        let expected_sq_claim =
            eq_linear_claim::<F, EF>(&output.proof.transcript.bridge_point, bridge_target);
        if expected_sq_claim != output.accumulator.public_instance.linear_claim {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "quasar squashed claim mismatch".into(),
            });
        }

        Ok(AccumulatorInstance {
            commitment_root: output.accumulator.public_instance.commitment_root,
            linear_claim: output.accumulator.public_instance.linear_claim.clone(),
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;
    use crate::{
        accumulation::{
            linearized::initialize_accumulator_from_spartan,
            scheme::{LinearizedAccumulationProver, LinearizedAccumulationVerifier},
        },
        fiat_shamir::domain_separator::DomainSeparator,
        parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
        spartan::{
            r1cs::{R1CSInstance, R1CSShape, SparseMatEntry},
            r1cs_prover::{R1CSProof, R1CSProver},
        },
    };

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    fn make_shape_and_instance(square: u64) -> (R1CSShape<F>, R1CSInstance<F>) {
        let num_cons = 4usize;
        let num_vars = 4usize;
        let num_inputs = 1usize;
        let shape = R1CSShape::new(
            num_cons,
            num_vars,
            num_inputs,
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 1, F::ONE)],
        );
        let mut witness = vec![F::ZERO; num_vars];
        let root = (square as f64).sqrt() as u64;
        witness[0] = F::from_u64(root);
        witness[1] = F::from_u64(square);
        (
            shape.clone(),
            R1CSInstance::new(shape, vec![F::ZERO], witness),
        )
    }

    fn prove_instance(instance: &R1CSInstance<F>, seed: u64) -> R1CSProof<F, EF> {
        let prover = R1CSProver::new();
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
        let mut challenger = MyChallenger::new(perm);
        prover.prove::<EF, _>(instance, &mut challenger)
    }

    fn make_whir_config(
        num_variables: usize,
    ) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
        let mut rng = SmallRng::seed_from_u64(42);
        let perm = Perm::new_from_rng_128(&mut rng);
        let params = ProtocolParameters {
            security_level: 100,
            pow_bits: 0,
            rs_domain_initial_reduction_factor: 1,
            folding_factor: FoldingFactor::Constant(2),
            merkle_hash: MyHash::new(perm.clone()),
            merkle_compress: MyCompress::new(perm),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        };
        WhirConfig::new(num_variables, params)
    }

    fn seed_challenger(
        config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
        seed: u64,
    ) -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
        let mut challenger = MyChallenger::new(perm);
        let mut domainsep = DomainSeparator::<EF, F>::new(vec![]);
        domainsep.commit_statement::<_, _, _, 8>(config);
        domainsep.add_whir_proof::<_, _, _, 8>(config);
        domainsep.observe_domain_separator(&mut challenger);
        challenger
    }

    #[test]
    fn quasar_frontend_squashes_fresh_instances() {
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();
        let proof0 = prove_instance(&instance0, 1);
        let proof1 = prove_instance(&instance1, 2);
        let fresh0 = FreshLinearInstance::from_spartan_proof(
            &shape,
            &proof0,
            spartan.prepare_witness(&instance0),
            EF::from_u64(3),
        );
        let fresh1 = FreshLinearInstance::from_spartan_proof(
            &shape,
            &proof1,
            spartan.prepare_witness(&instance1),
            EF::from_u64(7),
        );

        let config = make_whir_config(fresh0.witness_poly.num_variables());
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut prover_challenger = seed_challenger(&config, 9);
        let output = QuasarFrontendProver::new(&config)
            .squash_and_prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[fresh0.clone(), fresh1.clone()],
            )
            .unwrap();

        let mut verifier_challenger = seed_challenger(&config, 9);
        let result = QuasarFrontendVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut verifier_challenger,
                &[fresh0.public(), fresh1.public()],
                &output,
            );
        assert!(result.is_ok());
    }

    #[test]
    fn quasar_output_feeds_current_warp_backend() {
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();
        let proof0 = prove_instance(&instance0, 3);
        let proof1 = prove_instance(&instance1, 4);
        let fresh0 = FreshLinearInstance::from_spartan_proof(
            &shape,
            &proof0,
            spartan.prepare_witness(&instance0),
            EF::from_u64(5),
        );
        let fresh1 = FreshLinearInstance::from_spartan_proof(
            &shape,
            &proof1,
            spartan.prepare_witness(&instance1),
            EF::from_u64(7),
        );

        let running_acc = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof0,
            spartan.prepare_witness(&instance0),
            [F::ZERO; 8],
            EF::from_u64(5),
        );

        let config = make_whir_config(running_acc.witness.poly.num_variables());
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut quasar_challenger = seed_challenger(&config, 10);
        let squashed = QuasarFrontendProver::new(&config)
            .squash_and_prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut quasar_challenger,
                &[fresh0, fresh1],
            )
            .unwrap();

        // With random LC codeword batching, the combined poly has the same size as inputs
        let fold_config = make_whir_config(running_acc.witness.poly.num_variables());
        let mut fold_challenger = seed_challenger(&fold_config, 11);
        let (folded, proof) = LinearizedAccumulationProver::new(&fold_config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut fold_challenger,
                &[running_acc.clone(), squashed.accumulator.clone()],
                2,
            )
            .unwrap();

        let mut verify_challenger = seed_challenger(&fold_config, 11);
        let verified = LinearizedAccumulationVerifier::new(&fold_config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut verify_challenger,
                &[
                    running_acc.public_instance.clone(),
                    squashed.accumulator.public_instance.clone(),
                ],
                &proof,
            )
            .unwrap();

        assert_eq!(
            verified.commitment_root,
            folded.public_instance.commitment_root
        );
    }
}
