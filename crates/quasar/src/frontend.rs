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
        proof::{AccumulationProof, AccumulationTranscript},
        random_lc::random_linear_combination,
    },
    fiat_shamir::errors::FiatShamirError,
    fresh::{FreshLinearInstance, FreshLinearInstancePublic},
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{EqStatement, InitialClaim, LinearStatement},
        parameters::WhirConfig,
        prover::Prover as WhirProver,
        verifier::{Verifier as WhirVerifier, errors::VerifierError},
    },
};

#[derive(Clone, Debug)]
pub struct QuasarFrontendOutput<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub accumulator: Accumulator<F, EF, W, DIGEST_ELEMS>,
    pub proof: AccumulationProof<F, EF, W, DIGEST_ELEMS>,
}

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

/// Extract weight tables and target values from fresh instance linear claims.
fn extract_fresh_claims<F, EF>(
    instances: &[FreshLinearInstance<F, EF>],
) -> (Vec<EvaluationsList<EF>>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
{
    let mut weights = Vec::with_capacity(instances.len());
    let mut targets = Vec::with_capacity(instances.len());
    for inst in instances {
        let (w, &t) = inst
            .linear_claim
            .iter()
            .next()
            .expect("one linear claim per fresh instance");
        weights.push(w.clone());
        targets.push(t);
    }
    (weights, targets)
}

fn extract_fresh_claims_public<F, EF>(
    instances: &[FreshLinearInstancePublic<F, EF>],
) -> (Vec<EvaluationsList<EF>>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
{
    let mut weights = Vec::with_capacity(instances.len());
    let mut targets = Vec::with_capacity(instances.len());
    for inst in instances {
        let (w, &t) = inst
            .linear_claim
            .iter()
            .next()
            .expect("one linear claim per fresh instance");
        weights.push(w.clone());
        targets.push(t);
    }
    (weights, targets)
}

fn observe_fresh_claims<F, EF, Challenger>(
    challenger: &mut Challenger,
    instances: &[FreshLinearInstance<F, EF>],
) where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F>,
{
    for inst in instances {
        for (_, &target) in inst.linear_claim.iter() {
            challenger.observe_algebra_element(target);
        }
    }
}

fn observe_fresh_claims_public<F, EF, Challenger>(
    challenger: &mut Challenger,
    instances: &[FreshLinearInstancePublic<F, EF>],
) where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F>,
{
    for inst in instances {
        for (_, &target) in inst.linear_claim.iter() {
            challenger.observe_algebra_element(target);
        }
    }
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
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    /// Squashes `k` fresh linear instances into a single accumulator using constraint
    /// batching sumcheck + random linear combination + a single WHIR proof.
    #[allow(clippy::too_many_lines)]
    pub fn squash_and_prove<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        challenger: &mut Challenger,
        fresh_instances: &[FreshLinearInstance<F, EF>],
        num_shift_queries: usize,
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

        // --- Phase 1: Observe inputs and derive constraint batching challenge ---
        observe_fresh_claims(challenger, fresh_instances);
        let constraint_batching_challenge: F = challenger.sample();

        let (weights, targets) = extract_fresh_claims(fresh_instances);
        let witness_polys: Vec<EvaluationsList<F>> = fresh_instances
            .iter()
            .map(|inst| inst.witness_poly.clone())
            .collect();

        // --- Phase 2: Constraint batching sumcheck ---
        let (constraint_batch_proof, reduction_point) = constraint_batch_prove(
            constraint_batching_challenge,
            &weights,
            &targets,
            &witness_polys,
            challenger,
        );

        // --- Phase 3: Codeword batching via random LC ---
        let codeword_batching_challenge: F = challenger.sample();
        let poly_refs: Vec<&EvaluationsList<F>> = witness_polys.iter().collect();
        let combined_poly = random_linear_combination(&poly_refs, codeword_batching_challenge);
        let num_vars = combined_poly.num_variables();

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
        let output_linear_claim =
            evaluation_claim_as_linear_statement(&reduction_point, combined_eval);

        let mut statement = self
            .0
            .initial_statement_with_linear(combined_poly.clone(), output_linear_claim.clone());

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

        let accumulator = Accumulator::new(
            AccumulatorInstance {
                commitment_root: whir_proof.initial_commitment,
                linear_claim: output_linear_claim,
                _marker: PhantomData,
            },
            AccumulatorWitness {
                poly: combined_poly,
            },
        );

        Ok(QuasarFrontendOutput {
            accumulator,
            proof: AccumulationProof {
                transcript,
                whir_proof,
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
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
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
        assert!(!fresh_instances.is_empty());
        assert!(fresh_instances.len().is_power_of_two());

        let num_vars = fresh_instances[0].linear_claim.num_variables();
        let transcript = &output.proof.transcript;

        // --- Phase 1: Derive constraint batching challenge ---
        observe_fresh_claims_public(challenger, fresh_instances);
        let expected_constraint_batching: F = challenger.sample();
        if expected_constraint_batching != transcript.constraint_batching_challenge {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "constraint batching challenge mismatch".into(),
            });
        }

        // --- Phase 2: Verify constraint batching sumcheck ---
        let (weights, targets) = extract_fresh_claims_public(fresh_instances);
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

        // --- Phase 5: Build output claims and verify WHIR proof ---
        let output_linear_claim =
            evaluation_claim_as_linear_statement(&reduction_point, combined_eval);

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

        let initial_claim = InitialClaim {
            eq_statement,
            linear_statement: output_linear_claim.clone(),
        };

        let parsed_commitment = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&output.proof.whir_proof, challenger);
        WhirVerifier::new(self.0).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &output.proof.whir_proof,
            challenger,
            &parsed_commitment,
            initial_claim,
        )?;

        Ok(AccumulatorInstance {
            commitment_root: output.proof.whir_proof.initial_commitment,
            linear_claim: output_linear_claim,
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::{
        accumulation::{
            linearized::{decide_linearized_accumulator, initialize_accumulator_from_spartan},
            scheme::{LinearizedAccumulationProver, LinearizedAccumulationVerifier},
        },
        fiat_shamir::domain_separator::DomainSeparator,
        parameters::{FoldingFactor, ProtocolParameters, errors::SecurityAssumption},
        spartan::{
            r1cs::{R1CSInstance, R1CSShape, SparseMatEntry},
            r1cs_prover::{R1CSProof, R1CSProver},
        },
    };

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2KoalaBear<16>;
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
        debug_assert_eq!(root * root, square, "integer sqrt was not exact");
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
                2,
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
                2,
            )
            .unwrap();

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

    #[test]
    fn quasar_output_satisfies_decider() {
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
        let mut challenger = seed_challenger(&config, 20);
        let output = QuasarFrontendProver::new(&config)
            .squash_and_prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut challenger,
                &[fresh0, fresh1],
                2,
            )
            .unwrap();

        assert!(
            decide_linearized_accumulator(&output.accumulator),
            "output accumulator failed decider"
        );
    }
}
