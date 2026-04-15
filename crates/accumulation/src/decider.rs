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
    /// 1. Algebraic check: witness satisfies the linear claim.
    /// 2. WHIR PCS check: the committed polynomial matches.
    pub fn verify<P, W, PW, const DIGEST_ELEMS: usize>(
        &self,
        challenger: &mut Challenger,
        accumulator: &Accumulator<F, EF, W, DIGEST_ELEMS>,
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
        // Step 1: Algebraic check
        if !decide_linearized_accumulator(accumulator) {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "accumulator witness does not satisfy linear claim".into(),
            });
        }

        // Step 2: WHIR PCS verification with fresh transcript
        let num_vars = accumulator.public_instance.linear_claim.num_variables();
        let eq_statement = EqStatement::initialize(num_vars);
        let initial_claim = InitialClaim {
            eq_statement,
            linear_statement: accumulator.public_instance.linear_claim.clone(),
        };

        let parsed_commitment = CommitmentReader::new(self.0)
            .parse_commitment::<W, DIGEST_ELEMS>(&decider_proof.whir_proof, challenger);
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

        // Decider: verify with fresh challenger
        let mut verify_challenger = seed_challenger(&config);
        let result = decider.verify::<
            <F as Field>::Packing,
            F,
            <F as Field>::Packing,
            8,
        >(
            &mut verify_challenger, &output, &decider_proof
        );

        assert!(result.is_ok(), "decider rejected valid accumulator: {result:?}");
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

        // Tamper with the witness after proving
        output.witness.poly.as_mut_slice()[0] += F::ONE;

        let mut verify_challenger = seed_challenger(&config);
        let result = decider.verify::<
            <F as Field>::Packing,
            F,
            <F as Field>::Packing,
            8,
        >(
            &mut verify_challenger, &output, &decider_proof
        );

        assert!(result.is_err(), "decider accepted tampered witness");
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
