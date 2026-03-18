use core::marker::PhantomData;

use alloc::vec::Vec;
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
    spartan::encoding::eq_poly_at_index,
    whir::{
        committer::writer::CommitmentWriter, constraints::statement::LinearStatement,
        parameters::WhirConfig, proof::WhirProof, verifier::errors::VerifierError,
    },
};

#[derive(Clone, Debug)]
pub struct QuasarTranscript<F: Field> {
    pub tau_q: Vec<F>,
    pub weights: Vec<F>,
}

impl<F: Field> QuasarTranscript<F> {
    pub fn replay<Challenger>(&self, challenger: &mut Challenger)
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let sampled = (0..self.tau_q.len())
            .map(|_| challenger.sample())
            .collect::<Vec<_>>();
        assert_eq!(sampled, self.tau_q, "quasar transcript mismatch");
    }
}

#[derive(Clone, Debug)]
pub struct QuasarFrontendOutput<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub accumulator: Accumulator<F, EF, W, DIGEST_ELEMS>,
    pub transcript: QuasarTranscript<F>,
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

fn squash_witnesses<F: Field, EF: ExtensionField<F>>(
    instances: &[FreshLinearInstance<F, EF>],
    weights: &[F],
) -> crate::poly::evals::EvaluationsList<F> {
    let num_variables = instances[0].witness_poly.num_variables();
    let mut squashed = crate::poly::evals::EvaluationsList::zero(num_variables);
    for (instance, &coeff) in instances.iter().zip(weights.iter()) {
        squashed
            .iter_mut()
            .zip(instance.witness_poly.as_slice().iter())
            .for_each(|(acc, &value)| *acc += coeff * value);
    }
    squashed
}

fn squash_linear_claims_shared_support<F: Field, EF: ExtensionField<F>>(
    instances: &[FreshLinearInstance<F, EF>],
    weights: &[F],
) -> LinearStatement<F, EF> {
    let num_variables = instances[0].linear_claim.num_variables();
    let (base_weights, _) = instances[0]
        .linear_claim
        .iter()
        .next()
        .expect("one linear claim per fresh instance");

    let mut combined_target = EF::ZERO;
    for (instance, &coeff_f) in instances.iter().zip(weights.iter()) {
        let coeff = EF::from(coeff_f);
        let (claim_weights, &target) = instance
            .linear_claim
            .iter()
            .next()
            .expect("one linear claim per fresh instance");
        assert_eq!(
            claim_weights.as_slice(),
            base_weights.as_slice(),
            "Quasar frontend currently requires identical linear-claim support across fresh instances"
        );
        combined_target += coeff * target;
    }

    let mut linear_claim = LinearStatement::<F, EF>::initialize(num_variables);
    linear_claim.add_constraint(base_weights.clone(), combined_target);
    linear_claim
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

    pub fn squash_to_accumulator<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
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
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync,
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
        let squashed_witness = squash_witnesses(fresh_instances, &weights);
        let squashed_claim = squash_linear_claims_shared_support(fresh_instances, &weights);
        debug_assert!(squashed_claim.verify(&squashed_witness));

        let mut statement = self
            .0
            .initial_statement_with_linear(squashed_witness.clone(), squashed_claim.clone());
        let mut commit_only_proof = WhirProof::<F, EF, W, DIGEST_ELEMS>::from_whir_config(self.0);
        let _commitment = CommitmentWriter::new(self.0).commit::<_, P, W, PW, DIGEST_ELEMS>(
            dft,
            &mut commit_only_proof,
            challenger,
            &mut statement,
        )?;

        let accumulator = Accumulator::new(
            AccumulatorInstance {
                commitment_root: commit_only_proof.initial_commitment,
                linear_claim: squashed_claim,
                _marker: PhantomData,
            },
            AccumulatorWitness {
                poly: squashed_witness,
            },
        );

        Ok(QuasarFrontendOutput {
            accumulator,
            transcript: QuasarTranscript { tau_q, weights },
        })
    }
}

#[derive(Debug)]
pub struct QuasarFrontendVerifier;

impl QuasarFrontendVerifier {
    pub fn verify<F, EF, W, const DIGEST_ELEMS: usize>(
        fresh_instances: &[FreshLinearInstancePublic<F, EF>],
        output: &QuasarFrontendOutput<F, EF, W, DIGEST_ELEMS>,
        transcript: &QuasarTranscript<F>,
    ) -> Result<AccumulatorInstance<F, EF, W, DIGEST_ELEMS>, VerifierError>
    where
        F: Field,
        EF: ExtensionField<F>,
        W: Copy,
    {
        let expected_weights = eq_weights(&transcript.tau_q, fresh_instances.len());
        if expected_weights != transcript.weights {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "quasar weights mismatch".into(),
            });
        }

        let (base_weights, _) = fresh_instances[0]
            .linear_claim
            .iter()
            .next()
            .expect("one linear claim per fresh instance");
        let mut combined_target = EF::ZERO;
        for (instance, &coeff_f) in fresh_instances.iter().zip(expected_weights.iter()) {
            let coeff = EF::from(coeff_f);
            let (claim_weights, &target) = instance
                .linear_claim
                .iter()
                .next()
                .expect("one linear claim per fresh instance");
            if claim_weights.as_slice() != base_weights.as_slice() {
                return Err(VerifierError::StirChallengeFailed {
                    challenge_id: 0,
                    details: "quasar fresh supports mismatch".into(),
                });
            }
            combined_target += coeff * target;
        }

        let expected_target = output
            .accumulator
            .public_instance
            .linear_claim
            .iter()
            .next()
            .unwrap()
            .1;
        if *expected_target != combined_target {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "quasar squashed target mismatch".into(),
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
        let _proof1 = prove_instance(&instance1, 1);
        let fresh0 = FreshLinearInstance::from_shared_linearization_points(
            &shape,
            spartan.prepare_witness(&instance0),
            &proof0.eval_claims.rx,
            &proof0.eval_claims.ry,
            EF::from_u64(3),
        );
        let fresh1 = FreshLinearInstance::from_shared_linearization_points(
            &shape,
            spartan.prepare_witness(&instance1),
            &proof0.eval_claims.rx,
            &proof0.eval_claims.ry,
            EF::from_u64(3),
        );

        let config = make_whir_config(fresh0.witness_poly.num_variables());
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut prover_challenger = seed_challenger(&config, 9);
        let output = QuasarFrontendProver::new(&config)
            .squash_to_accumulator::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[fresh0.clone(), fresh1.clone()],
            )
            .unwrap();

        let result = QuasarFrontendVerifier::verify(
            &[fresh0.public(), fresh1.public()],
            &output,
            &output.transcript,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn quasar_output_feeds_current_warp_backend() {
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();
        let proof0 = prove_instance(&instance0, 3);
        let _proof1 = prove_instance(&instance1, 3);
        let fresh0 = FreshLinearInstance::from_shared_linearization_points(
            &shape,
            spartan.prepare_witness(&instance0),
            &proof0.eval_claims.rx,
            &proof0.eval_claims.ry,
            EF::from_u64(5),
        );
        let fresh1 = FreshLinearInstance::from_shared_linearization_points(
            &shape,
            spartan.prepare_witness(&instance1),
            &proof0.eval_claims.rx,
            &proof0.eval_claims.ry,
            EF::from_u64(5),
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
            .squash_to_accumulator::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut quasar_challenger,
                &[fresh0, fresh1],
            )
            .unwrap();

        let fold_config = make_whir_config(running_acc.witness.poly.num_variables() + 1);
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
