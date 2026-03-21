//! Terminal Decider for the accumulation scheme.
//!
//! The terminal decider is the final step in the accumulation pipeline. After
//! multiple rounds of folding (Quasar squash + WARP fold), we have a single
//! accumulated instance with claims over a committed polynomial. The decider
//! produces a WHIR proof that these claims are satisfied, allowing verification
//! without access to the witness polynomial.
//!
//! This implements Phase 4 from plan.txt (Section 4.4 - Terminal Decider):
//! - Evaluation claim: `ŵ_final(α_final) = μ_final`
//! - PESAT claim: `P*(β_final, w_final) = η_final`
//!
//! Both claims are encoded in the `LinearStatement` of the accumulator.

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PackedValue, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};

use crate::{
    accumulation::accumulator::{Accumulator, AccumulatorInstance},
    fiat_shamir::errors::FiatShamirError,
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::InitialClaim,
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover as WhirProver,
        verifier::{errors::VerifierError, Verifier as WhirVerifier},
    },
};

/// Result of terminal decision: either acceptance or a verification error.
pub type DeciderResult<T> = Result<T, DeciderError>;

/// Errors that can occur during terminal decision.
#[derive(Debug)]
pub enum DeciderError {
    /// The algebraic claims do not hold against the witness.
    AlgebraicVerificationFailed,
    /// WHIR proof generation failed.
    WhirProverError(FiatShamirError),
    /// WHIR proof verification failed.
    WhirVerifierError(VerifierError),
}

impl From<FiatShamirError> for DeciderError {
    fn from(e: FiatShamirError) -> Self {
        DeciderError::WhirProverError(e)
    }
}

impl From<VerifierError> for DeciderError {
    fn from(e: VerifierError) -> Self {
        DeciderError::WhirVerifierError(e)
    }
}

/// Proof produced by the terminal decider.
///
/// This proof attests that the accumulated linear claims are satisfied by
/// a polynomial committed under the accumulator's Merkle root.
#[derive(Clone, Debug)]
pub struct DeciderProof<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// The WHIR proof demonstrating that the committed polynomial satisfies
    /// all accumulated linear claims.
    pub whir_proof: WhirProof<F, EF, W, DIGEST_ELEMS>,
}

/// Prover for terminal decision.
///
/// Takes a final accumulated instance (with witness) and produces a WHIR proof
/// that the linear claims are satisfied.
#[derive(Debug)]
pub struct TerminalDeciderProver<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: Field,
    EF: ExtensionField<F>;

impl<'a, EF, F, H, C, Challenger> TerminalDeciderProver<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    /// Create a new terminal decider prover with the given WHIR configuration.
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    /// Verify the algebraic claims hold against the witness (debug check).
    ///
    /// This is a sanity check before generating the WHIR proof.
    pub fn verify_algebraic<W, const DIGEST_ELEMS: usize>(
        accumulator: &Accumulator<F, EF, W, DIGEST_ELEMS>,
    ) -> bool
    where
        W: Copy,
    {
        accumulator
            .public_instance
            .linear_claim
            .verify(&accumulator.witness.poly)
    }

    /// Produce a terminal decision proof for the given accumulated instance.
    ///
    /// This generates a WHIR proof that the committed polynomial satisfies
    /// all the linear claims in the accumulator.
    ///
    /// # Arguments
    /// * `dft` - The DFT implementation for polynomial operations
    /// * `challenger` - The Fiat-Shamir challenger
    /// * `accumulator` - The final accumulated instance with witness
    ///
    /// # Returns
    /// A `DeciderProof` containing the WHIR proof, or an error if generation fails.
    pub fn prove<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        challenger: &mut Challenger,
        accumulator: &Accumulator<F, EF, W, DIGEST_ELEMS>,
    ) -> DeciderResult<DeciderProof<F, EF, W, DIGEST_ELEMS>>
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
        // Sanity check: verify algebraic claims hold
        if !Self::verify_algebraic(accumulator) {
            return Err(DeciderError::AlgebraicVerificationFailed);
        }

        // Observe the commitment root to bind the proof to the accumulated instance
        challenger.observe(Hash::from(accumulator.public_instance.commitment_root));

        // Observe the linear claim targets
        for (_, &target) in accumulator.public_instance.linear_claim.iter() {
            challenger.observe_algebra_element(target);
        }

        // Build the initial claim from the accumulator's linear statement
        // The WHIR proof will demonstrate that the committed polynomial
        // satisfies these linear claims
        let initial_claim = InitialClaim {
            eq_statement: crate::whir::constraints::statement::EqStatement::initialize(
                accumulator.witness.poly.num_variables(),
            ),
            linear_statement: accumulator.public_instance.linear_claim.clone(),
        };

        // Create the WHIR statement with the linear claims
        let mut statement = self.0.initial_statement_with_linear(
            accumulator.witness.poly.clone(),
            initial_claim.linear_statement.clone(),
        );

        // Generate the WHIR proof
        let mut whir_proof = WhirProof::<F, EF, W, DIGEST_ELEMS>::from_whir_config(self.0);

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

        Ok(DeciderProof { whir_proof })
    }
}

/// Verifier for terminal decision.
///
/// Verifies a `DeciderProof` against an accumulated public instance,
/// without requiring access to the witness polynomial.
#[derive(Debug)]
pub struct TerminalDeciderVerifier<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: Field,
    EF: ExtensionField<F>;

impl<'a, EF, F, H, C, Challenger> TerminalDeciderVerifier<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    /// Create a new terminal decider verifier with the given WHIR configuration.
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    /// Verify a terminal decision proof.
    ///
    /// This checks that the WHIR proof demonstrates the committed polynomial
    /// (identified by the accumulator's Merkle root) satisfies all linear claims.
    ///
    /// # Arguments
    /// * `challenger` - The Fiat-Shamir challenger (must be seeded identically to prover)
    /// * `instance` - The accumulated public instance (commitment root + linear claims)
    /// * `proof` - The decider proof to verify
    ///
    /// # Returns
    /// `Ok(())` if verification succeeds, or a `DeciderError` if it fails.
    pub fn verify<P, W, PW, const DIGEST_ELEMS: usize>(
        &self,
        challenger: &mut Challenger,
        instance: &AccumulatorInstance<F, EF, W, DIGEST_ELEMS>,
        proof: &DeciderProof<F, EF, W, DIGEST_ELEMS>,
    ) -> DeciderResult<()>
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
        // Observe the commitment root (must match prover's sequence)
        challenger.observe(Hash::from(instance.commitment_root));

        // Observe the linear claim targets
        for (_, &target) in instance.linear_claim.iter() {
            challenger.observe_algebra_element(target);
        }

        // Reconstruct the initial claim from the public instance
        let initial_claim = InitialClaim {
            eq_statement: crate::whir::constraints::statement::EqStatement::initialize(
                instance.linear_claim.num_variables(),
            ),
            linear_statement: instance.linear_claim.clone(),
        };

        // Parse the commitment from the proof
        let parsed_commitment = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&proof.whir_proof, challenger);

        // Verify the WHIR proof with the linear claims
        WhirVerifier::new(self.0).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &proof.whir_proof,
            challenger,
            &parsed_commitment,
            initial_claim,
        )?;

        // Verify that the proof's commitment matches the accumulator's
        if proof.whir_proof.initial_commitment != instance.commitment_root {
            return Err(DeciderError::WhirVerifierError(
                VerifierError::StirChallengeFailed {
                    challenge_id: 0,
                    details: "Commitment root mismatch between proof and accumulator".into(),
                },
            ));
        }

        Ok(())
    }
}

/// Convenience function to decide an accumulator algebraically (without WHIR proof).
///
/// This is the same as `decide_linearized_accumulator` but provided here for
/// module completeness. Use `TerminalDeciderProver` and `TerminalDeciderVerifier`
/// for the full cryptographic decision with WHIR proof.
pub fn decide_algebraic<F, EF, W, const DIGEST_ELEMS: usize>(
    accumulator: &Accumulator<F, EF, W, DIGEST_ELEMS>,
) -> bool
where
    F: Field,
    EF: ExtensionField<F>,
{
    accumulator
        .public_instance
        .linear_claim
        .verify(&accumulator.witness.poly)
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

    fn make_whir_config(
        num_variables: usize,
    ) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
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
        WhirConfig::new(num_variables, params)
    }

    /// Config for single (unfold) accumulators - 3 variables from (2*4).trailing_zeros() = 3
    fn make_whir_config_single() -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
        make_whir_config(3)
    }

    /// Config for folded accumulators - 4 variables (3 + 1 from fold)
    fn make_whir_config_folded() -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
        make_whir_config(4)
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

    fn seed_decider_challenger(
        config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    ) -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
        let mut challenger = MyChallenger::new(perm);
        let mut domainsep = DomainSeparator::<EF, F>::new(vec![]);
        domainsep.commit_statement::<_, _, _, 8>(config);
        domainsep.add_whir_proof::<_, _, _, 8>(config);
        domainsep.observe_domain_separator(&mut challenger);
        challenger
    }

    #[test]
    fn algebraic_decision_works_on_single_accumulator() {
        // This test verifies that algebraic decision (without WHIR proof) works
        // on fresh accumulators. The full terminal decider with WHIR proof
        // requires accumulators with valid WHIR commitments (i.e., after folding).
        let (shape, instance) = make_shape_and_instance(9);
        let spartan = R1CSProver::new();

        let mut chal = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let proof = spartan.prove::<EF, _>(&instance, &mut chal);

        let acc = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof,
            spartan.prepare_witness(&instance),
            [F::ZERO; 8],
            EF::from_u64(3),
        );

        // Algebraic decision (without WHIR proof) works
        assert!(decide_algebraic(&acc));

        // Prover-side check also works
        assert!(TerminalDeciderProver::<
            EF,
            F,
            MyHash,
            MyCompress,
            MyChallenger,
        >::verify_algebraic(&acc));
    }

    // Note: The terminal decider is designed to work with accumulators that have
    // real WHIR commitments (i.e., those that have been through at least one
    // accumulation fold via LinearizedAccumulationProver). Direct use on fresh
    // accumulators from initialize_accumulator_from_spartan is not the intended
    // use case, as those have placeholder commitment roots.
    //
    // The main test for this functionality is terminal_decider_after_accumulation_fold.

    #[test]
    fn terminal_decider_after_accumulation_fold() {
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

        // First: fold the two accumulators - use folded config (4 variables = 3 + 1)
        let config = make_whir_config_folded();
        let dft = Radix2DFTSmallBatch::<F>::default();

        let mut prover_challenger = seed_challenger(&config);
        let (folded_acc, acc_proof) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[acc0.clone(), acc1.clone()],
                2,
            )
            .expect("Accumulation should succeed");

        // Verify the accumulation
        let mut verifier_challenger = seed_challenger(&config);
        let verified_instance = LinearizedAccumulationVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut verifier_challenger,
                &[acc0.public_instance.clone(), acc1.public_instance.clone()],
                &acc_proof,
            )
            .expect("Accumulation verification should succeed");

        assert_eq!(
            verified_instance.commitment_root,
            folded_acc.public_instance.commitment_root
        );

        // Now: terminal decision on the folded accumulator
        let mut decider_prover_challenger = seed_decider_challenger(&config);
        let decider_proof = TerminalDeciderProver::new(&config)
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut decider_prover_challenger,
                &folded_acc,
            )
            .expect("Decider proof generation should succeed");

        // Verify terminal decision
        let mut decider_verifier_challenger = seed_decider_challenger(&config);
        TerminalDeciderVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut decider_verifier_challenger,
                &folded_acc.public_instance,
                &decider_proof,
            )
            .expect("Decider verification should succeed");
    }

    #[test]
    fn terminal_decider_rejects_tampered_commitment_after_fold() {
        // Test that tampering with the commitment in a properly folded accumulator
        // causes verification to fail
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

        let config = make_whir_config_folded();
        let dft = Radix2DFTSmallBatch::<F>::default();

        let mut prover_challenger = seed_challenger(&config);
        let (folded_acc, _acc_proof) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[acc0, acc1],
                2,
            )
            .expect("Accumulation should succeed");

        // Generate decider proof
        let mut decider_prover_challenger = seed_decider_challenger(&config);
        let mut decider_proof = TerminalDeciderProver::new(&config)
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut decider_prover_challenger,
                &folded_acc,
            )
            .expect("Decider proof generation should succeed");

        // Tamper with the commitment
        decider_proof.whir_proof.initial_commitment[0] = F::from_u64(999);

        // Verification should fail
        let mut decider_verifier_challenger = seed_decider_challenger(&config);
        let result = TerminalDeciderVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut decider_verifier_challenger,
                &folded_acc.public_instance,
                &decider_proof,
            );

        assert!(result.is_err());
    }

    #[test]
    fn terminal_decider_rejects_mismatched_instance_after_fold() {
        // Test that using the wrong instance causes verification to fail
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let (_, instance2) = make_shape_and_instance(25);
        let (_, instance3) = make_shape_and_instance(36);
        let spartan = R1CSProver::new();

        let mut chal0 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let proof0 = spartan.prove::<EF, _>(&instance0, &mut chal0);
        let mut chal1 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(2)));
        let proof1 = spartan.prove::<EF, _>(&instance1, &mut chal1);
        let mut chal2 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(3)));
        let proof2 = spartan.prove::<EF, _>(&instance2, &mut chal2);
        let mut chal3 = MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(4)));
        let proof3 = spartan.prove::<EF, _>(&instance3, &mut chal3);

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
        let acc2 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof2,
            spartan.prepare_witness(&instance2),
            [F::from_u64(2); 8],
            EF::from_u64(3),
        );
        let acc3 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof3,
            spartan.prepare_witness(&instance3),
            [F::from_u64(3); 8],
            EF::from_u64(3),
        );

        let config = make_whir_config_folded();
        let dft = Radix2DFTSmallBatch::<F>::default();

        // Fold first pair
        let mut prover_challenger1 = seed_challenger(&config);
        let (folded_acc1, _) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger1,
                &[acc0, acc1],
                2,
            )
            .expect("Accumulation should succeed");

        // Fold second pair
        let mut prover_challenger2 = seed_challenger(&config);
        let (folded_acc2, _) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger2,
                &[acc2, acc3],
                2,
            )
            .expect("Accumulation should succeed");

        // Generate decider proof for first folded accumulator
        let mut decider_prover_challenger = seed_decider_challenger(&config);
        let decider_proof = TerminalDeciderProver::new(&config)
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut decider_prover_challenger,
                &folded_acc1,
            )
            .expect("Decider proof generation should succeed");

        // Try to verify with the second accumulator's instance (wrong one)
        let mut decider_verifier_challenger = seed_decider_challenger(&config);
        let result = TerminalDeciderVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut decider_verifier_challenger,
                &folded_acc2.public_instance, // Wrong instance!
                &decider_proof,
            );

        assert!(result.is_err());
    }
}
