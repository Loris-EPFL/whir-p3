use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Algebra, ExtensionField, Field, PackedValue, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};

use crate::{
    accumulator::Accumulator,
    linearized::decide_linearized_accumulator,
    fiat_shamir::errors::FiatShamirError,
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{EqStatement, InitialClaim},
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover as WhirProver,
        verifier::{errors::VerifierError, Verifier as WhirVerifier},
    },
};

/// Standalone decider for the final accumulated instance in an IVC chain.
///
/// Generates a fresh WHIR PCS proof for the accumulator and verifies it,
/// confirming that the committed polynomial matches the witness and
/// satisfies the accumulated linear claim.
#[derive(Debug)]
pub struct AccumulationDecider<'a, EF, F, H, C, Challenger>(
    &'a WhirConfig<EF, F, H, C, Challenger>,
)
where
    F: TwoAdicField,
    EF: ExtensionField<F>;

/// The standalone decider proof: a fresh WHIR proof over the accumulated polynomial.
#[derive(Clone, Debug)]
pub struct DeciderProof<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub whir_proof: WhirProof<F, EF, W, DIGEST_ELEMS>,
}

impl<'a, EF, F, H, C, Challenger> AccumulationDecider<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub const fn new(config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self(config)
    }

    /// Prove: generate a fresh, standalone WHIR proof for the accumulated polynomial.
    ///
    /// This creates a new commitment and proof with a fresh Fiat-Shamir transcript,
    /// so the resulting proof can be verified independently of any accumulation history.
    pub fn prove<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        challenger: &mut Challenger,
        accumulator: &Accumulator<F, EF, W, DIGEST_ELEMS>,
    ) -> Result<DeciderProof<F, EF, W, DIGEST_ELEMS>, FiatShamirError>
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
        // Build statement: the linear claim as a WHIR initial statement
        let mut statement = self.0.initial_statement_with_linear(
            accumulator.witness.poly.clone(),
            accumulator.public_instance.linear_claim.clone(),
        );

        let mut whir_proof =
            WhirProof::<F, EF, W, DIGEST_ELEMS>::from_whir_config(self.0);
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

    /// Verify: check the standalone decider proof against an accumulator.
    ///
    /// Succinct-verifier mode: checks the proof against `accumulator.public_instance`
    /// only — the `witness` field of `accumulator` is ignored. The caller is expected
    /// to have obtained the public instance through a trusted channel (e.g. the
    /// accumulation verifier that produced it).
    ///
    /// Checks performed:
    /// 1. **Commitment binding** — the WHIR proof's parsed commitment MUST equal
    ///    `accumulator.public_instance.commitment_root`. Without this check a
    ///    prover could commit to any polynomial that happens to satisfy the
    ///    `linear_claim` (trivially constructible for most claims), bypassing
    ///    the accumulator's chain-of-custody.
    /// 2. **WHIR PCS check** — the committed polynomial satisfies the accumulated
    ///    linear claim.
    pub fn verify<P, W, PW, const DIGEST_ELEMS: usize>(
        &self,
        challenger: &mut Challenger,
        instance: &crate::accumulator::AccumulatorInstance<F, EF, W, DIGEST_ELEMS>,
        decider_proof: &DeciderProof<F, EF, W, DIGEST_ELEMS>,
    ) -> Result<(), VerifierError>
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
        let num_vars = instance.linear_claim.num_variables();
        let eq_statement = EqStatement::initialize(num_vars);
        let initial_claim = InitialClaim {
            eq_statement,
            linear_statement: instance.linear_claim.clone(),
        };

        let parsed_commitment = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&decider_proof.whir_proof, challenger);

        // Step 1: commitment binding — fail closed if the decider's WHIR
        // commitment does not match the accumulator's stored commitment_root.
        let expected_root: Hash<F, W, DIGEST_ELEMS> = Hash::from(instance.commitment_root);
        if parsed_commitment.root != expected_root {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "decider commitment_root mismatch: parsed proof is not bound to accumulator".into(),
            });
        }

        // Step 2: WHIR PCS verification with the accumulated linear claim.
        WhirVerifier::new(self.0).verify_with_initial_claim::<P, W, PW, DIGEST_ELEMS>(
            &decider_proof.whir_proof,
            challenger,
            &parsed_commitment,
            initial_claim,
        )?;

        Ok(())
    }

    /// Quick algebraic-only check (no PCS verification).
    pub fn decide_algebraic<W, const DIGEST_ELEMS: usize>(
        accumulator: &Accumulator<F, EF, W, DIGEST_ELEMS>,
    ) -> bool {
        decide_linearized_accumulator(accumulator)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// `whir_traits::TerminalScheme` bridge.
//
// We implement the trait on a zero-sized type `AccumulationTerminal` that
// delegates to the existing `AccumulationDecider`. The `Challenger` is a
// trait-level parameter (same pattern as `p3_commit::Pcs`), so we can
// require `CanObserve<Hash<…>>` on it directly without leaking that bound
// into the trait itself.
//
// The `Error` associated type is `DeciderError` (a new enum that merges
// `FiatShamirError` + `VerifierError`) so that `prove` and `verify` agree
// on a single error type.
// ──────────────────────────────────────────────────────────────────────────

/// Zero-sized bridge type that implements [`whir_traits::TerminalScheme`]
/// by delegating to [`AccumulationDecider`].
#[derive(Debug)]
pub struct AccumulationTerminal<
    EF,
    F,
    H,
    C,
    P,
    W,
    PW,
    const DIGEST_ELEMS: usize,
>(core::marker::PhantomData<fn() -> (EF, F, H, C, P, W, PW)>)
where
    F: Field,
    EF: ExtensionField<F>;

impl<EF, F, H, C, P, W, PW, const DIGEST_ELEMS: usize>
    AccumulationTerminal<EF, F, H, C, P, W, PW, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    #[must_use]
    pub const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<EF, F, H, C, P, W, PW, const DIGEST_ELEMS: usize> Default
    for AccumulationTerminal<EF, F, H, C, P, W, PW, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for the [`AccumulationTerminal`] implementation of
/// [`whir_traits::TerminalScheme`]. Merges the two underlying error types
/// (`FiatShamirError` from `prove`, `VerifierError` from `verify`) so that
/// the associated `Error` type in the trait impl is single-valued.
#[derive(Debug, thiserror::Error)]
pub enum DeciderError {
    /// Fiat-Shamir transcript error (typically from the prover).
    #[error("Fiat-Shamir error: {0}")]
    FiatShamir(#[from] FiatShamirError),
    /// WHIR / accumulator verification error.
    #[error("verification failed: {0:?}")]
    Verify(VerifierError),
}

impl From<VerifierError> for DeciderError {
    fn from(e: VerifierError) -> Self {
        Self::Verify(e)
    }
}

impl<EF, F, H, C, P, W, PW, Ch, const DIGEST_ELEMS: usize>
    whir_traits::TerminalScheme<F, EF, Ch>
    for AccumulationTerminal<EF, F, H, C, P, W, PW, DIGEST_ELEMS>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    P: PackedValue<Value = F> + Eq + Send + Sync,
    W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
    PW: PackedValue<Value = W> + Eq + Send + Sync,
    H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
        + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
        + Sync,
    Ch: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, W, DIGEST_ELEMS>>,
    [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Config = WhirConfig<EF, F, H, C, Ch>;
    type Accumulator = Accumulator<F, EF, W, DIGEST_ELEMS>;
    type AccumulatorInstance = crate::accumulator::AccumulatorInstance<F, EF, W, DIGEST_ELEMS>;
    type TerminalProof = DeciderProof<F, EF, W, DIGEST_ELEMS>;
    type Error = DeciderError;

    fn prove(
        config: &Self::Config,
        challenger: &mut Ch,
        accumulator: &Self::Accumulator,
    ) -> Result<Self::TerminalProof, Self::Error> {
        use p3_dft::Radix2DFTSmallBatch;
        let dft = Radix2DFTSmallBatch::<F>::default();
        AccumulationDecider::new(config)
            .prove::<P, W, PW, _, DIGEST_ELEMS>(&dft, challenger, accumulator)
            .map_err(DeciderError::from)
    }

    fn verify(
        config: &Self::Config,
        challenger: &mut Ch,
        instance: &Self::AccumulatorInstance,
        proof: &Self::TerminalProof,
    ) -> Result<(), Self::Error> {
        AccumulationDecider::new(config)
            .verify::<P, W, PW, DIGEST_ELEMS>(challenger, instance, proof)
            .map_err(DeciderError::from)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;
    use crate::{
        linearized::initialize_accumulator_from_spartan,
        scheme::LinearizedAccumulationProver,
        fiat_shamir::domain_separator::DomainSeparator,
        parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
        spartan::{
            r1cs::{R1CSInstance, R1CSShape, SparseMatEntry},
            r1cs_prover::R1CSProver,
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
        let root = (square as f64).sqrt() as u64;
        debug_assert_eq!(root * root, square, "integer sqrt was not exact");
        let mut witness = vec![F::ZERO; num_vars];
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
    fn decider_prove_and_verify_accepts_valid_accumulator() {
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();

        let mut chal0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let proof0 = spartan.prove::<EF, _>(&instance0, &mut chal0);
        let mut chal1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(2)));
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

        // Accumulate
        let mut prover_challenger = seed_challenger(&config);
        let (output, _acc_proof) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[acc0, acc1],
                2,
            )
            .unwrap();

        // Decider: generate fresh standalone proof
        let decider = AccumulationDecider::new(&config);
        let mut prove_challenger = seed_challenger(&config);
        let decider_proof = decider
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prove_challenger,
                &output,
            )
            .unwrap();

        // Decider: verify with fresh challenger.
        // Succinct verifier consumes only `public_instance`.
        let mut verify_challenger = seed_challenger(&config);
        let result = decider.verify::<
            <F as Field>::Packing,
            F,
            <F as Field>::Packing,
            8,
        >(
            &mut verify_challenger, &output.public_instance, &decider_proof
        );

        assert!(result.is_ok(), "decider rejected valid accumulator: {result:?}");
    }

    #[test]
    fn terminal_scheme_trait_roundtrips() {
        use whir_traits::TerminalScheme;
        type Terminal =
            AccumulationTerminal<EF, F, MyHash, MyCompress, <F as Field>::Packing, F, <F as Field>::Packing, 8>;

        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();

        let mut chal0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let proof0 = spartan.prove::<EF, _>(&instance0, &mut chal0);
        let mut chal1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(2)));
        let proof1 = spartan.prove::<EF, _>(&instance1, &mut chal1);

        let acc0 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape, &proof0, spartan.prepare_witness(&instance0),
            [F::ZERO; 8], EF::from_u64(3),
        );
        let acc1 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape, &proof1, spartan.prepare_witness(&instance1),
            [F::ONE; 8], EF::from_u64(3),
        );

        let config = make_whir_config();
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut prover_challenger = seed_challenger(&config);
        let (output, _) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft, &mut prover_challenger, &[acc0, acc1], 2,
            )
            .unwrap();

        // Prove via the trait.
        let mut prove_chal = seed_challenger(&config);
        let proof = <Terminal as TerminalScheme<F, EF, MyChallenger>>::prove(
            &config, &mut prove_chal, &output,
        )
        .expect("TerminalScheme::prove failed");

        // Verify via the trait.
        let mut verify_chal = seed_challenger(&config);
        <Terminal as TerminalScheme<F, EF, MyChallenger>>::verify(
            &config, &mut verify_chal, &output.public_instance, &proof,
        )
        .expect("TerminalScheme::verify failed");
    }

    #[test]
    fn decider_rejects_tampered_witness() {
        let (shape, instance0) = make_shape_and_instance(9);
        let (_, instance1) = make_shape_and_instance(16);
        let spartan = R1CSProver::new();

        let mut chal0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let proof0 = spartan.prove::<EF, _>(&instance0, &mut chal0);
        let mut chal1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(2)));
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
        let (mut output, _) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prover_challenger,
                &[acc0, acc1],
                2,
            )
            .unwrap();

        // Generate valid decider proof BEFORE tampering
        let decider = AccumulationDecider::new(&config);
        let mut prove_challenger = seed_challenger(&config);
        let decider_proof = decider
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prove_challenger,
                &output,
            )
            .unwrap();

        // Tamper with the public instance's commitment_root. With the
        // bug_013 fix, verify must catch this via the commitment binding check.
        output.public_instance.commitment_root[0] += F::ONE;

        let mut verify_challenger = seed_challenger(&config);
        let result = decider.verify::<
            <F as Field>::Packing,
            F,
            <F as Field>::Packing,
            8,
        >(
            &mut verify_challenger, &output.public_instance, &decider_proof
        );

        assert!(result.is_err(), "decider accepted tampered commitment_root");
    }

    // ── bug_013 regression: substitute-polynomial attack ──────────────────
    //
    // Before the fix the verifier only checked that the *witness* algebraically
    // satisfies the linear claim, not that the WHIR proof was for the *same*
    // polynomial that was committed to. A cheating prover could:
    //   1. Hold a valid accumulator A with commitment_root C_A.
    //   2. Build any polynomial B whose WHIR proof opens successfully against
    //      A's linear_claim (e.g. another honest accumulator's polynomial).
    //   3. Present proof_B with instance_A → old verifier accepted.
    //
    // The fix (commitment binding check) rejects this because the parsed root
    // C_B ≠ C_A. The test below simulates this attack and asserts that the
    // rejection comes from the binding check specifically (not a later PCS
    // check), by matching the exact error details string.
    //
    // Stronger variant (not implemented here): construct a polynomial P' that
    // satisfies A's linear_claim exactly (P' in null(weight)^⊥ of A's claim),
    // so the PCS check would also pass — only the binding check can catch it.
    // That requires direct access to the weight vector in LinearStatement.
    #[test]
    fn decider_rejects_substitute_polynomial_proof() {
        let (shape, instance_a0) = make_shape_and_instance(9);
        let (_, instance_a1) = make_shape_and_instance(16);
        let (_, instance_b0) = make_shape_and_instance(25);
        let (_, instance_b1) = make_shape_and_instance(36);
        let spartan = R1CSProver::new();

        let mut chal_a0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(10)));
        let proof_a0 = spartan.prove::<EF, _>(&instance_a0, &mut chal_a0);
        let mut chal_a1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(11)));
        let proof_a1 = spartan.prove::<EF, _>(&instance_a1, &mut chal_a1);
        let mut chal_b0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(12)));
        let proof_b0 = spartan.prove::<EF, _>(&instance_b0, &mut chal_b0);
        let mut chal_b1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(13)));
        let proof_b1 = spartan.prove::<EF, _>(&instance_b1, &mut chal_b1);

        let acc_a0 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape, &proof_a0, spartan.prepare_witness(&instance_a0),
            [F::ZERO; 8], EF::from_u64(3),
        );
        let acc_a1 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape, &proof_a1, spartan.prepare_witness(&instance_a1),
            [F::ONE; 8], EF::from_u64(3),
        );
        let acc_b0 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape, &proof_b0, spartan.prepare_witness(&instance_b0),
            [F::ZERO; 8], EF::from_u64(5),
        );
        let acc_b1 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape, &proof_b1, spartan.prepare_witness(&instance_b1),
            [F::ONE; 8], EF::from_u64(5),
        );

        let config = make_whir_config();
        let dft = Radix2DFTSmallBatch::<F>::default();

        let mut chal = seed_challenger(&config);
        let (output_a, _) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft, &mut chal, &[acc_a0, acc_a1], 2,
            )
            .unwrap();

        let mut chal = seed_challenger(&config);
        let (output_b, _) = LinearizedAccumulationProver::new(&config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft, &mut chal, &[acc_b0, acc_b1], 2,
            )
            .unwrap();

        // Cheating prover: generate a valid WHIR decider proof for B...
        let decider = AccumulationDecider::new(&config);
        let mut prove_chal = seed_challenger(&config);
        let proof_b = decider
            .prove::<_, F, <F as Field>::Packing, _, 8>(&dft, &mut prove_chal, &output_b)
            .unwrap();

        // ...then present it against A's public instance (C_B ≠ C_A).
        let mut verify_chal = seed_challenger(&config);
        let result = decider.verify::<
            <F as Field>::Packing,
            F,
            <F as Field>::Packing,
            8,
        >(&mut verify_chal, &output_a.public_instance, &proof_b);

        match result {
            Err(VerifierError::StirChallengeFailed { details, .. }) => {
                assert!(
                    details.contains("commitment_root mismatch"),
                    "binding check fired but with unexpected details: {details}"
                );
            }
            Err(e) => panic!(
                "wrong error variant — commitment binding check may be absent: {e:?}"
            ),
            Ok(()) => panic!("decider accepted a WHIR proof for a different polynomial"),
        }
    }

    #[test]
    fn algebraic_decider_accepts_valid() {
        let (shape, instance) = make_shape_and_instance(9);
        let spartan = R1CSProver::new();
        let mut chal =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let proof = spartan.prove::<EF, _>(&instance, &mut chal);

        let acc = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape,
            &proof,
            spartan.prepare_witness(&instance),
            [F::ZERO; 8],
            EF::from_u64(3),
        );

        assert!(AccumulationDecider::<EF, F, MyHash, MyCompress, MyChallenger>::decide_algebraic(
            &acc
        ));
    }
}
