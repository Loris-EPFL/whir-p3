use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PackedValue, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};

use crate::{
    accumulation::{
        accumulator::{Accumulator, AccumulatorInstance, AccumulatorWitness},
        linearized::decide_linearized_accumulator,
        proof::{AccumulationProof, AccumulationTranscript},
        union_poly::build_union_polynomial,
    },
    fiat_shamir::errors::FiatShamirError,
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{EqStatement, InitialClaim, LinearStatement},
        parameters::WhirConfig,
        prover::Prover as WhirProver,
        verifier::{errors::VerifierError, Verifier as WhirVerifier},
    },
};

fn boolean_point_from_index<F: Field, EF: ExtensionField<F>>(
    index: usize,
    num_variables: usize,
) -> MultilinearPoint<EF> {
    MultilinearPoint::new(
        (0..num_variables)
            .map(|bit| {
                if ((index >> bit) & 1) == 1 {
                    EF::ONE
                } else {
                    EF::ZERO
                }
            })
            .collect(),
    )
}

fn observe_accumulator_instances<F, EF, W, Challenger, const DIGEST_ELEMS: usize>(
    challenger: &mut Challenger,
    accumulators: &[AccumulatorInstance<F, EF, W, DIGEST_ELEMS>],
) where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    W: PackedValue<Value = W> + Eq + Copy,
    Challenger:
        FieldChallenger<F> + GrindingChallenger<Witness = F> + CanObserve<Hash<F, W, DIGEST_ELEMS>>,
{
    for accumulator in accumulators {
        challenger.observe(Hash::from(accumulator.commitment_root));
        for (_, &target) in accumulator.linear_claim.iter() {
            challenger.observe_algebra_element(target);
        }
    }
}

fn public_instances<F: Field, EF: ExtensionField<F>, W, const DIGEST_ELEMS: usize>(
    accumulators: &[Accumulator<F, EF, W, DIGEST_ELEMS>],
) -> Vec<AccumulatorInstance<F, EF, W, DIGEST_ELEMS>>
where
    W: Copy,
{
    accumulators
        .iter()
        .map(|acc| acc.public_instance.clone())
        .collect()
}

fn extend_linear_weights<F: Field, EF: ExtensionField<F>>(
    weights: &EvaluationsList<EF>,
    block_index: usize,
    num_blocks: usize,
) -> EvaluationsList<EF> {
    assert!(num_blocks.is_power_of_two());
    let local_evals = weights.as_slice();
    let local_size = local_evals.len();
    let mut out = vec![EF::ZERO; local_size * num_blocks];
    let start = block_index * local_size;
    out[start..start + local_size].copy_from_slice(local_evals);
    EvaluationsList::new(out)
}

fn batched_union_linear_claim_from_instances<
    F: Field,
    EF: ExtensionField<F>,
    W,
    const DIGEST_ELEMS: usize,
>(
    accumulators: &[AccumulatorInstance<F, EF, W, DIGEST_ELEMS>],
    batching_challenge: F,
) -> LinearStatement<F, EF> {
    assert!(!accumulators.is_empty());
    assert!(accumulators.len().is_power_of_two());
    let num_blocks = accumulators.len();
    let local_vars = accumulators[0].linear_claim.num_variables();
    let total_vars = local_vars + num_blocks.trailing_zeros() as usize;

    let mut statement = LinearStatement::<F, EF>::initialize(total_vars);

    let mut combined_weights = EvaluationsList::zero(total_vars);
    let mut combined_target = EF::ZERO;
    for (idx, accumulator) in accumulators.iter().enumerate() {
        let coeff = EF::from(batching_challenge).exp_u64(idx as u64);
        let (weights, &target) = accumulator
            .linear_claim
            .iter()
            .next()
            .expect("one linear claim per accumulator");
        let extended = extend_linear_weights(weights, idx, num_blocks);
        combined_weights
            .iter_mut()
            .zip(extended.as_slice().iter())
            .for_each(|(acc, &value)| *acc += coeff * value);
        combined_target += coeff * target;
    }
    statement.add_constraint(combined_weights, combined_target);
    statement
}

fn union_polynomial_from_accumulators<
    F: Field,
    EF: ExtensionField<F>,
    W,
    const DIGEST_ELEMS: usize,
>(
    accumulators: &[Accumulator<F, EF, W, DIGEST_ELEMS>],
) -> EvaluationsList<F> {
    build_union_polynomial(
        &accumulators
            .iter()
            .map(|acc| acc.witness.poly.clone())
            .collect::<Vec<_>>(),
    )
}

fn build_public_initial_claim_from_transcript<
    F: Field,
    EF: ExtensionField<F>,
    W,
    const DIGEST_ELEMS: usize,
>(
    accumulators: &[AccumulatorInstance<F, EF, W, DIGEST_ELEMS>],
    transcript: &AccumulationTranscript<F, EF>,
    total_vars: usize,
) -> InitialClaim<F, EF> {
    let mut eq_statement = EqStatement::initialize(total_vars);

    eq_statement.add_evaluated_constraint(transcript.ood_point.clone(), transcript.ood_answer);

    for (&index, &eval) in transcript
        .shift_query_indices
        .iter()
        .zip(transcript.shift_query_answers.iter())
    {
        let point = boolean_point_from_index::<F, EF>(index, total_vars);
        eq_statement.add_evaluated_constraint(point, eval);
    }

    InitialClaim {
        eq_statement,
        linear_statement: batched_union_linear_claim_from_instances(
            accumulators,
            transcript.batching_challenge,
        ),
    }
}

fn build_prover_initial_claim_from_transcript<
    F: Field,
    EF: ExtensionField<F>,
    W,
    const DIGEST_ELEMS: usize,
>(
    accumulators: &[Accumulator<F, EF, W, DIGEST_ELEMS>],
    transcript: &AccumulationTranscript<F, EF>,
) -> InitialClaim<F, EF>
where
    W: Copy,
{
    let union_poly = union_polynomial_from_accumulators(accumulators);
    let claim = build_public_initial_claim_from_transcript(
        &public_instances(accumulators),
        transcript,
        union_poly.num_variables(),
    );
    debug_assert_eq!(
        claim.eq_statement.len(),
        1 + transcript.shift_query_indices.len()
    );
    debug_assert_eq!(
        claim.eq_statement.iter().next().unwrap().1,
        &transcript.ood_answer
    );
    claim
}

#[derive(Debug)]
pub struct LinearizedAccumulationProver<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: Field,
    EF: ExtensionField<F>;

impl<'a, EF, F, H, C, Challenger> LinearizedAccumulationProver<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accumulate<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        challenger: &mut Challenger,
        accumulators: &[Accumulator<F, EF, W, DIGEST_ELEMS>],
        num_shift_queries: usize,
    ) -> Result<
        (
            Accumulator<F, EF, W, DIGEST_ELEMS>,
            AccumulationProof<F, EF, W, DIGEST_ELEMS>,
        ),
        FiatShamirError,
    >
    where
        Dft: TwoAdicSubgroupDft<F>,
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync,
        Challenger: CanObserve<Hash<F, W, DIGEST_ELEMS>>,
        [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        assert!(!accumulators.is_empty());
        assert!(accumulators.len().is_power_of_two());
        for accumulator in accumulators {
            assert!(decide_linearized_accumulator(accumulator));
        }

        observe_accumulator_instances(challenger, &public_instances(accumulators));
        let batching_challenge = challenger.sample();
        let union_poly = union_polynomial_from_accumulators(accumulators);
        let union_vars = union_poly.num_variables();
        let ood_point = MultilinearPoint::new(
            (0..union_vars)
                .map(|_| challenger.sample_algebra_element())
                .collect(),
        );
        let shift_query_indices = (0..num_shift_queries)
            .map(|_| challenger.sample_bits(union_vars))
            .collect::<Vec<_>>();
        let ood_answer = union_poly.evaluate_hypercube_base(&ood_point);
        let shift_query_answers = shift_query_indices
            .iter()
            .map(|&index| {
                union_poly
                    .evaluate_hypercube_base(&boolean_point_from_index::<F, EF>(index, union_vars))
            })
            .collect();
        let transcript = AccumulationTranscript {
            batching_challenge,
            ood_point,
            ood_answer,
            shift_query_indices,
            shift_query_answers,
        };

        let initial_claim = build_prover_initial_claim_from_transcript(accumulators, &transcript);
        let mut statement = self.0.initial_statement_with_linear(
            union_poly.clone(),
            initial_claim.linear_statement.clone(),
        );
        for (point, _) in initial_claim.eq_statement.iter() {
            let _ = statement.evaluate(point);
        }

        let mut whir_proof =
            crate::whir::proof::WhirProof::<F, EF, W, DIGEST_ELEMS>::from_whir_config(self.0);
        let commitment = CommitmentWriter::new(self.0).commit::<_, P, W, PW, DIGEST_ELEMS>(
            dft,
            &mut whir_proof,
            challenger,
            &mut statement,
        )?;
        WhirProver(self.0).prove::<_, P, W, PW, DIGEST_ELEMS>(
            dft,
            &mut whir_proof,
            challenger,
            &statement,
            commitment,
        )?;

        let output_accumulator = Accumulator::new(
            AccumulatorInstance {
                commitment_root: whir_proof.initial_commitment,
                linear_claim: initial_claim.linear_statement,
                _marker: PhantomData,
            },
            AccumulatorWitness { poly: union_poly },
        );

        Ok((
            output_accumulator,
            AccumulationProof {
                transcript,
                whir_proof,
            },
        ))
    }
}

#[derive(Debug)]
pub struct LinearizedAccumulationVerifier<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: Field,
    EF: ExtensionField<F>;

impl<'a, EF, F, H, C, Challenger> LinearizedAccumulationVerifier<'a, EF, F, H, C, Challenger>
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
        inputs: &[AccumulatorInstance<F, EF, W, DIGEST_ELEMS>],
        proof: &AccumulationProof<F, EF, W, DIGEST_ELEMS>,
    ) -> Result<AccumulatorInstance<F, EF, W, DIGEST_ELEMS>, VerifierError>
    where
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync,
        Challenger: CanObserve<Hash<F, W, DIGEST_ELEMS>>,
        [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        assert!(!inputs.is_empty());
        assert!(inputs.len().is_power_of_two());

        observe_accumulator_instances(challenger, inputs);
        let expected_batching = challenger.sample();
        let total_vars =
            inputs[0].linear_claim.num_variables() + inputs.len().trailing_zeros() as usize;
        let expected_ood = MultilinearPoint::new(
            (0..total_vars)
                .map(|_| challenger.sample_algebra_element())
                .collect(),
        );
        let expected_shift_indices = (0..proof.transcript.shift_query_indices.len())
            .map(|_| challenger.sample_bits(expected_ood.num_variables()))
            .collect::<Vec<_>>();

        if expected_batching != proof.transcript.batching_challenge
            || expected_ood != proof.transcript.ood_point
            || expected_shift_indices != proof.transcript.shift_query_indices
        {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "accumulation transcript mismatch".into(),
            });
        }

        let initial_claim =
            build_public_initial_claim_from_transcript(inputs, &proof.transcript, total_vars);
        let parsed_commitment = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&proof.whir_proof, challenger);
        WhirVerifier::new(self.0).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &proof.whir_proof,
            challenger,
            &parsed_commitment,
            initial_claim.clone(),
        )?;

        Ok(AccumulatorInstance {
            commitment_root: proof.whir_proof.initial_commitment,
            linear_claim: initial_claim.linear_statement,
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
        accumulation::linearized::initialize_accumulator_from_spartan,
        fiat_shamir::domain_separator::DomainSeparator,
        parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
        spartan::{
            r1cs::{R1CSInstance, R1CSShape, SparseMatEntry},
            r1cs_prover::R1CSProver,
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

    fn make_whir_config() -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
        let mut rng = SmallRng::seed_from_u64(55);
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
        WhirConfig::new(4, params)
    }

    fn seed_challenger(
        config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    ) -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let mut challenger = MyChallenger::new(perm);
        let mut domainsep = DomainSeparator::<EF, F>::new(vec![]);
        domainsep.commit_statement::<_, _, _, 8>(config);
        domainsep.add_whir_proof::<_, _, _, 8>(config);
        domainsep.observe_domain_separator(&mut challenger);
        challenger
    }

    #[test]
    fn transcripted_accumulation_proves_and_verifies() {
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();

        let mut chal0 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let proof0 = spartan.prove::<EF, _>(&instance0, &mut chal0);
        let mut chal1 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(2)));
        let proof1 = spartan.prove::<EF, _>(&instance1, &mut chal1);

        let acc0 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof0,
            spartan.prepare_witness(&instance0),
            [F::ZERO; 8],
            EF::from_u64(3),
        );
        let acc1 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof1,
            spartan.prepare_witness(&instance1),
            [F::ONE; 8],
            EF::from_u64(3),
        );

        let config = make_whir_config();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut prover_challenger = seed_challenger(&config);
        let (output, proof) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[acc0.clone(), acc1.clone()],
                2,
            )
            .unwrap();

        let mut verifier_challenger = seed_challenger(&config);
        let verified = LinearizedAccumulationVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut verifier_challenger,
                &[acc0.public_instance.clone(), acc1.public_instance.clone()],
                &proof,
            )
            .unwrap();

        assert_eq!(
            verified.commitment_root,
            output.public_instance.commitment_root
        );
        assert_eq!(verified.linear_claim, output.public_instance.linear_claim);
    }

    #[test]
    fn transcript_tampering_is_rejected() {
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();

        let mut chal0 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(11)));
        let proof0 = spartan.prove::<EF, _>(&instance0, &mut chal0);
        let mut chal1 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(12)));
        let proof1 = spartan.prove::<EF, _>(&instance1, &mut chal1);

        let acc0 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof0,
            spartan.prepare_witness(&instance0),
            [F::ZERO; 8],
            EF::from_u64(3),
        );
        let acc1 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof1,
            spartan.prepare_witness(&instance1),
            [F::ONE; 8],
            EF::from_u64(3),
        );

        let config = make_whir_config();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut prover_challenger = seed_challenger(&config);
        let (_output, mut proof) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[acc0.clone(), acc1.clone()],
                2,
            )
            .unwrap();

        proof.transcript.shift_query_answers[0] += EF::ONE;

        let mut verifier_challenger = seed_challenger(&config);
        let result = LinearizedAccumulationVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut verifier_challenger,
                &[acc0.public_instance.clone(), acc1.public_instance.clone()],
                &proof,
            );

        assert!(result.is_err());
    }
}
