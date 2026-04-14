use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Algebra, ExtensionField, Field, PackedValue, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};

use crate::{
    accumulation::{
        accumulator::{Accumulator, AccumulatorInstance, AccumulatorWitness},
        constraint_batch::{constraint_batch_prove, constraint_batch_verify},
        linearized::decide_linearized_accumulator,
        proof::{AccumulationProof, AccumulationTranscript},
        random_lc::random_linear_combination,
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

fn observe_accumulators_public<F, EF, W, Challenger, const DIGEST_ELEMS: usize>(
    challenger: &mut Challenger,
    accumulators: &[Accumulator<F, EF, W, DIGEST_ELEMS>],
) where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    W: PackedValue<Value = W> + Eq + Copy,
    Challenger:
        FieldChallenger<F> + GrindingChallenger<Witness = F> + CanObserve<Hash<F, W, DIGEST_ELEMS>>,
{
    for accumulator in accumulators {
        challenger.observe(Hash::from(accumulator.public_instance.commitment_root));
        for (_, &target) in accumulator.public_instance.linear_claim.iter() {
            challenger.observe_algebra_element(target);
        }
    }
}

/// Extract weight tables and target values from accumulator instances.
fn extract_claims<F, EF, W, const DIGEST_ELEMS: usize>(
    accumulators: &[AccumulatorInstance<F, EF, W, DIGEST_ELEMS>],
) -> (Vec<EvaluationsList<EF>>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
{
    let mut weights = Vec::with_capacity(accumulators.len());
    let mut targets = Vec::with_capacity(accumulators.len());
    for acc in accumulators {
        let (w, &t) = acc
            .linear_claim
            .iter()
            .next()
            .expect("one linear claim per accumulator");
        weights.push(w.clone());
        targets.push(t);
    }
    (weights, targets)
}

/// Build the output accumulator's linear claim as an evaluation constraint.
///
/// The claim `f(r) = y` is expressed as a `LinearStatement` with weight `eq(r, ·)`
/// and target `y`, so that `Σ_b eq(r, b) · f(b) = f(r) = y`.
fn evaluation_claim_as_linear_statement<F: Field, EF: ExtensionField<F>>(
    point: &MultilinearPoint<EF>,
    value: EF,
) -> LinearStatement<F, EF> {
    let num_variables = point.num_variables();
    let eq_weights = EvaluationsList::new_from_point(point.as_slice(), EF::ONE);
    let mut statement = LinearStatement::<F, EF>::initialize(num_variables);
    statement.add_constraint(eq_weights, value);
    statement
}

/// Lightweight accumulation verifier: re-derives Fiat-Shamir challenges, verifies the
/// constraint batching sumcheck, computes the combined evaluation, and checks OOD/shift
/// query consistency.
///
/// This performs the algebraic / transcript checks only — no Merkle proof or WHIR PCS
/// verification. Returns the output `LinearStatement` and the `EqStatement` binding the
/// OOD + shift queries. The caller can then feed these into a WHIR verifier (full verify)
/// or defer to a decider (IVC).
pub fn accumulation_verify_lightweight<F, EF, W, Challenger, const DIGEST_ELEMS: usize>(
    challenger: &mut Challenger,
    inputs: &[AccumulatorInstance<F, EF, W, DIGEST_ELEMS>],
    transcript: &AccumulationTranscript<F, EF>,
) -> Result<(LinearStatement<F, EF>, EqStatement<EF>), VerifierError>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    W: PackedValue<Value = W> + Eq + Copy,
    Challenger:
        FieldChallenger<F> + GrindingChallenger<Witness = F> + CanObserve<Hash<F, W, DIGEST_ELEMS>>,
{
    assert!(!inputs.is_empty());
    assert!(inputs.len().is_power_of_two());

    let num_vars = inputs[0].linear_claim.num_variables();

    // --- Phase 1: Derive constraint batching challenge ---
    observe_accumulator_instances(challenger, inputs);
    let expected_constraint_batching: F = challenger.sample();
    if expected_constraint_batching != transcript.constraint_batching_challenge {
        return Err(VerifierError::StirChallengeFailed {
            challenge_id: 0,
            details: "constraint batching challenge mismatch".into(),
        });
    }

    // --- Phase 2: Verify constraint batching sumcheck ---
    let (weights, targets) = extract_claims::<F, EF, W, DIGEST_ELEMS>(inputs);
    let reduction_point = constraint_batch_verify(
        transcript.constraint_batching_challenge,
        &weights,
        &targets,
        &transcript.constraint_batch_proof,
        challenger,
    )?;

    // --- Phase 3: Derive codeword batching challenge and compute expected eval ---
    let expected_codeword_batching: F = challenger.sample();
    if expected_codeword_batching != transcript.codeword_batching_challenge {
        return Err(VerifierError::StirChallengeFailed {
            challenge_id: 1,
            details: "codeword batching challenge mismatch".into(),
        });
    }

    let combined_eval: EF = {
        let eta_ef = EF::from(transcript.codeword_batching_challenge);
        let mut val = EF::ZERO;
        let mut power = EF::ONE;
        for eval in &transcript.constraint_batch_proof.individual_evals {
            val += power * *eval;
            power *= eta_ef;
        }
        val
    };

    // --- Phase 4: Verify OOD + shift query consistency ---
    let expected_ood = MultilinearPoint::new(
        (0..num_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect(),
    );
    let expected_shift_indices: Vec<usize> = (0..transcript.shift_query_indices.len())
        .map(|_| challenger.sample_bits(num_vars))
        .collect();

    if expected_ood != transcript.ood_point
        || expected_shift_indices != transcript.shift_query_indices
    {
        return Err(VerifierError::StirChallengeFailed {
            challenge_id: 2,
            details: "OOD/shift query challenge mismatch".into(),
        });
    }

    // --- Phase 5: Build output claims ---
    let output_linear_claim = evaluation_claim_as_linear_statement(&reduction_point, combined_eval);

    let mut eq_statement = EqStatement::initialize(num_vars);
    eq_statement.add_evaluated_constraint(transcript.ood_point.clone(), transcript.ood_answer);
    for (&idx, &eval) in transcript
        .shift_query_indices
        .iter()
        .zip(transcript.shift_query_answers.iter())
    {
        let point = boolean_point_from_index::<F, EF>(idx, num_vars);
        eq_statement.add_evaluated_constraint(point, eval);
    }

    Ok((output_linear_claim, eq_statement))
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
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    /// Accumulates multiple accumulators into one using random LC + constraint batching.
    ///
    /// Protocol:
    /// 1. Run constraint batching sumcheck to reduce `ℓ` linear claims to point evaluations.
    /// 2. Combine witness polynomials via random linear combination `f = Σ ηⁱ fᵢ`.
    /// 3. Create evaluation claim `f(r) = Σ ηⁱ fᵢ(r)` linking the combined oracle to the sumcheck.
    /// 4. Add OOD + shift query constraints for binding.
    /// 5. Run WHIR prove on the combined polynomial.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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

        // --- Phase 1: Observe inputs and derive constraint batching challenge ---
        observe_accumulators_public(challenger, accumulators);
        let constraint_batching_challenge: F = challenger.sample();

        // Extract weight tables and targets from each accumulator's linear claim
        let instances: Vec<_> = accumulators
            .iter()
            .map(|a| &a.public_instance)
            .cloned()
            .collect();
        let (weights, targets) = extract_claims::<F, EF, W, DIGEST_ELEMS>(&instances);
        let witness_polys: Vec<&EvaluationsList<F>> =
            accumulators.iter().map(|a| &a.witness.poly).collect();

        // --- Phase 2: Constraint batching sumcheck ---
        let (constraint_batch_proof, reduction_point) = constraint_batch_prove(
            constraint_batching_challenge,
            &weights,
            &targets,
            &witness_polys.iter().map(|&p| p.clone()).collect::<Vec<_>>(),
            challenger,
        );

        // --- Phase 3: Codeword batching via random LC ---
        let codeword_batching_challenge: F = challenger.sample();
        let combined_poly = random_linear_combination(&witness_polys, codeword_batching_challenge);
        let num_vars = combined_poly.num_variables();

        // Compute combined evaluation: f(r) = Σ ηⁱ fᵢ(r)
        let combined_eval: EF = {
            let eta_ef = EF::from(codeword_batching_challenge);
            let mut val = EF::ZERO;
            let mut power = EF::ONE;
            for eval in &constraint_batch_proof.individual_evals {
                val += power * *eval;
                power *= eta_ef;
            }
            val
        };

        // --- Phase 4: OOD + shift queries on the combined polynomial ---
        let ood_point = MultilinearPoint::new(
            (0..num_vars)
                .map(|_| challenger.sample_algebra_element())
                .collect(),
        );
        let ood_answer = combined_poly.evaluate_hypercube_base(&ood_point);

        let shift_query_indices: Vec<usize> = (0..num_shift_queries)
            .map(|_| challenger.sample_bits(num_vars))
            .collect();
        let shift_query_answers: Vec<EF> = shift_query_indices
            .iter()
            .map(|&idx| {
                combined_poly
                    .evaluate_hypercube_base(&boolean_point_from_index::<F, EF>(idx, num_vars))
            })
            .collect();

        // --- Phase 5: Build WHIR statement and prove ---
        // The output accumulator's constraint: evaluation claim f(r) = combined_eval
        let output_linear_claim =
            evaluation_claim_as_linear_statement(&reduction_point, combined_eval);

        let mut statement = self
            .0
            .initial_statement_with_linear(combined_poly.clone(), output_linear_claim.clone());

        // Add OOD and shift query equality constraints
        let _ = statement.evaluate(&ood_point);
        for (&idx, _) in shift_query_indices.iter().zip(shift_query_answers.iter()) {
            let point = boolean_point_from_index::<F, EF>(idx, num_vars);
            let _ = statement.evaluate(&point);
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

        // --- Build output ---
        let transcript = AccumulationTranscript {
            constraint_batching_challenge,
            constraint_batch_proof,
            codeword_batching_challenge,
            ood_point,
            ood_answer,
            shift_query_indices,
            shift_query_answers,
        };

        let output_accumulator = Accumulator::new(
            AccumulatorInstance {
                commitment_root: whir_proof.initial_commitment,
                linear_claim: output_linear_claim,
                _marker: PhantomData,
            },
            AccumulatorWitness {
                poly: combined_poly,
            },
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
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    /// Full verification: lightweight accumulation checks + WHIR PCS verification.
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
        // Phase A: Lightweight algebraic checks (no Merkle/WHIR)
        let (output_linear_claim, eq_statement) =
            accumulation_verify_lightweight::<F, EF, W, Challenger, DIGEST_ELEMS>(
                challenger,
                inputs,
                &proof.transcript,
            )?;

        // Phase B: Full WHIR PCS verification
        let initial_claim = InitialClaim {
            eq_statement,
            linear_statement: output_linear_claim.clone(),
        };

        let parsed_commitment = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&proof.whir_proof, challenger);
        WhirVerifier::new(self.0).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &proof.whir_proof,
            challenger,
            &parsed_commitment,
            initial_claim,
        )?;

        Ok(AccumulatorInstance {
            commitment_root: proof.whir_proof.initial_commitment,
            linear_claim: output_linear_claim,
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

    /// WhirConfig sized for the INPUT polynomial (not union).
    /// With random LC, the combined polynomial has the same size as inputs.
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
        // num_variables = 3 (same as input accumulators, NOT 4 for union)
        WhirConfig::new(3, params)
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

        let mut chal0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(11)));
        let proof0 = spartan.prove::<EF, _>(&instance0, &mut chal0);
        let mut chal1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(12)));
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

        // Tamper with a shift query answer
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

    #[test]
    fn output_accumulator_satisfies_decider() {
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
        let (output, _proof) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[acc0, acc1],
                2,
            )
            .unwrap();

        // The output accumulator should pass the decider check
        assert!(
            decide_linearized_accumulator(&output),
            "output accumulator failed decider"
        );
    }
}
