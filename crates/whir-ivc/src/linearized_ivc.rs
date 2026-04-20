//! IVC (Incrementally Verifiable Computation) prover and verifier.
//!
//! Orchestrates the full IVC loop:
//! 1. User step circuit → fresh R1CS instance
//! 2. Spartan proof → linearized accumulator
//! 3. WARP fold: accumulate new + running accumulator
//! 4. Carry forward accumulation proof
//! 5. At the end, decider verifies the final accumulator
//!
//! The current implementation performs accumulation verification externally
//! (the verifier re-checks the accumulation transcript at each step).
//! A future extension adds a recursive circuit that verifies accumulation
//! in-circuit, making this a true single-pass IVC.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Algebra, ExtensionField, Field, PackedValue, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, Permutation, PseudoCompressionFunction};

use crate::{
    accumulation::{
        accumulator::{Accumulator, AccumulatorInstance},
        decider::{AccumulationDecider, DeciderProof},
        linearized::{decide_linearized_accumulator, initialize_accumulator_from_spartan},
        proof::AccumulationProof,
        scheme::{LinearizedAccumulationProver, LinearizedAccumulationVerifier},
    },
    circuit::{
        builder::CircuitBuilder,
        poseidon2::Poseidon2CircuitConfig,
        sponge::CircuitChallenger,
    },
    fiat_shamir::errors::FiatShamirError,
    ivc::verifier_circuit::{AccumulationVerifierWitness, synthesize_unified_ivc_circuit},
    spartan::{
        r1cs::{R1CSInstance, R1CSShape},
        r1cs_prover::{R1CSProver},
    },
    whir::parameters::WhirConfig,
};

/// State carried between IVC steps.
#[derive(Clone, Debug)]
pub struct IVCState<F, EF, W, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Current step number (0-indexed, 0 = initial state before any step).
    pub step: usize,
    /// Running accumulator from WARP folding.
    pub accumulator: Accumulator<F, EF, W, DIGEST_ELEMS>,
    /// Proof of the last accumulation step (needed for verification).
    pub last_accumulation_proof: Option<AccumulationProof<F, EF, W, DIGEST_ELEMS>>,
    /// The previous accumulator instance (for verification).
    pub prev_instances: Option<Vec<AccumulatorInstance<F, EF, W, DIGEST_ELEMS>>>,
    /// Current public state.
    pub public_state: Vec<F>,
}

/// IVC prover configuration.
#[derive(Debug)]
pub struct IVCProver<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    whir_config: &'a WhirConfig<EF, F, H, C, Challenger>,
    spartan_prover: R1CSProver<F>,
    num_shift_queries: usize,
    /// Batching challenge for linearizing Spartan proofs.
    linearization_challenge: EF,
}

impl<'a, EF, F, H, C, Challenger> IVCProver<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub fn new(
        whir_config: &'a WhirConfig<EF, F, H, C, Challenger>,
        linearization_challenge: EF,
        num_shift_queries: usize,
    ) -> Self {
        Self {
            whir_config,
            spartan_prover: R1CSProver::new(),
            num_shift_queries,
            linearization_challenge,
        }
    }

    /// Initialize the IVC state from a first R1CS instance (step 0).
    ///
    /// This creates the initial accumulator from a Spartan proof of the first step.
    pub fn init<W, const DIGEST_ELEMS: usize>(
        &self,
        shape: &R1CSShape<F>,
        instance: &R1CSInstance<F>,
        spartan_challenger: &mut Challenger,
        public_state: Vec<F>,
    ) -> IVCState<F, EF, W, DIGEST_ELEMS>
    where
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default,
    {
        // Prove the first instance with Spartan
        let spartan_proof = self.spartan_prover.prove::<EF, _>(instance, spartan_challenger);
        let witness_poly = self.spartan_prover.prepare_witness(instance);

        // Initialize accumulator
        let accumulator = initialize_accumulator_from_spartan::<F, EF, W, DIGEST_ELEMS>(
            shape,
            &spartan_proof,
            witness_poly,
            [W::default(); DIGEST_ELEMS],
            self.linearization_challenge,
        );

        debug_assert!(decide_linearized_accumulator(&accumulator));

        IVCState {
            step: 1,
            accumulator,
            last_accumulation_proof: None,
            prev_instances: None,
            public_state,
        }
    }

    /// Initialize the IVC state using the unified circuit (step + verifier).
    ///
    /// This ensures the initial accumulator's polynomial has the same number of
    /// variables as all subsequent recursive steps, enabling a single accumulation stream.
    #[allow(clippy::too_many_arguments)]
    pub fn init_unified<P, W, PW, Dft, L, Perm2, S, const DIGEST_ELEMS: usize>(
        &self,
        step_circuit: &S,
        step_input_state: &[F],
        spartan_challenger: &mut Challenger,
        poseidon_config: &Poseidon2CircuitConfig<F, 16>,
        poseidon_perm: &Perm2,
        w_param: F,
        target_num_witness: Option<usize>,
        public_state: Vec<F>,
    ) -> IVCState<F, EF, W, DIGEST_ELEMS>
    where
        F: p3_field::PrimeField64,
        Dft: TwoAdicSubgroupDft<F>,
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default + Into<F>,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        L: p3_poseidon2::GenericPoseidon2LinearLayers<16>,
        Perm2: Permutation<[F; 16]>,
        S: crate::ivc::step::StepCircuit<F>,
    {
        // Build the unified circuit (step only, no verifier since it's the first step)
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let mut circuit_challenger = CircuitChallenger::<F, 16, 8>::new(&mut circuit_builder);

        let _output_vars = synthesize_unified_ivc_circuit::<F, L, Perm2, S, 16, 8>(
            &mut circuit_builder,
            &mut circuit_challenger,
            poseidon_config,
            poseidon_perm,
            step_circuit,
            step_input_state,
            None, // No previous accumulation to verify
            w_param,
            target_num_witness,
        );

        let (unified_shape, unified_instance) = circuit_builder.build();
        assert!(
            unified_shape.is_sat(unified_instance.witness(), unified_instance.input()),
            "unified init circuit does not satisfy R1CS",
        );

        let unified_proof =
            self.spartan_prover.prove::<EF, _>(&unified_instance, spartan_challenger);
        let unified_witness = self.spartan_prover.prepare_witness(&unified_instance);

        let accumulator = initialize_accumulator_from_spartan::<F, EF, W, DIGEST_ELEMS>(
            &unified_shape,
            &unified_proof,
            unified_witness,
            [W::default(); DIGEST_ELEMS],
            self.linearization_challenge,
        );
        debug_assert!(decide_linearized_accumulator(&accumulator));

        IVCState {
            step: 1,
            accumulator,
            last_accumulation_proof: None,
            prev_instances: None,
            public_state,
        }
    }

    /// Execute one IVC step: prove a new instance and fold it into the running accumulator.
    ///
    /// This is the non-recursive version: accumulation is verified externally.
    /// Use `prove_step_recursive` for the full recursive IVC.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_step<P, W, PW, Dft, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        shape: &R1CSShape<F>,
        instance: &R1CSInstance<F>,
        spartan_challenger: &mut Challenger,
        accumulation_challenger: &mut Challenger,
        prev_state: &IVCState<F, EF, W, DIGEST_ELEMS>,
        new_public_state: Vec<F>,
    ) -> Result<IVCState<F, EF, W, DIGEST_ELEMS>, FiatShamirError>
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
        // 1. Prove the new instance with Spartan
        let spartan_proof = self.spartan_prover.prove::<EF, _>(instance, spartan_challenger);
        let witness_poly = self.spartan_prover.prepare_witness(instance);

        // 2. Linearize into a fresh accumulator
        let new_acc = initialize_accumulator_from_spartan::<F, EF, W, DIGEST_ELEMS>(
            shape,
            &spartan_proof,
            witness_poly,
            [W::default(); DIGEST_ELEMS],
            self.linearization_challenge,
        );

        debug_assert!(decide_linearized_accumulator(&new_acc));

        // 3. WARP fold: accumulate [prev_accumulator, new_accumulator]
        let accumulators = [prev_state.accumulator.clone(), new_acc];
        let prev_instances: Vec<_> = accumulators
            .iter()
            .map(|a| a.public_instance.clone())
            .collect();

        let (folded_accumulator, accumulation_proof) =
            LinearizedAccumulationProver::new(self.whir_config)
                .accumulate::<P, W, PW, Dft, DIGEST_ELEMS>(
                    dft,
                    accumulation_challenger,
                    &accumulators,
                    self.num_shift_queries,
                )?;

        debug_assert!(decide_linearized_accumulator(&folded_accumulator));

        Ok(IVCState {
            step: prev_state.step + 1,
            accumulator: folded_accumulator,
            last_accumulation_proof: Some(accumulation_proof),
            prev_instances: Some(prev_instances),
            public_state: new_public_state,
        })
    }

    /// Execute one IVC step with recursive proving (unified circuit).
    ///
    /// Builds a unified circuit containing BOTH the step computation AND the
    /// accumulation verifier. This ensures all accumulators have the same
    /// polynomial size, enabling a single accumulation stream.
    ///
    /// The unified circuit is proven with Spartan, linearized into an accumulator,
    /// and folded with the running accumulator using `recursive_whir_config`.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn prove_step_recursive<P, W, PW, Dft, L, Perm2, S, const DIGEST_ELEMS: usize>(
        &self,
        dft: &Dft,
        step_circuit: &S,
        step_input_state: &[F],
        spartan_challenger: &mut Challenger,
        accumulation_challenger: &mut Challenger,
        prev_state: &IVCState<F, EF, W, DIGEST_ELEMS>,
        new_public_state: Vec<F>,
        poseidon_config: &Poseidon2CircuitConfig<F, 16>,
        poseidon_perm: &Perm2,
        w_param: F,
        recursive_whir_config: &WhirConfig<EF, F, H, C, Challenger>,
    ) -> Result<IVCState<F, EF, W, DIGEST_ELEMS>, FiatShamirError>
    where
        F: p3_field::PrimeField64,
        Dft: TwoAdicSubgroupDft<F>,
        P: PackedValue<Value = F> + Eq + Send + Sync,
        W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default + Into<F>,
        PW: PackedValue<Value = W> + Eq + Send + Sync,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
            + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
            + Sync,
        Challenger: CanObserve<Hash<F, W, DIGEST_ELEMS>> + Clone,
        [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
        L: p3_poseidon2::GenericPoseidon2LinearLayers<16>,
        Perm2: Permutation<[F; 16]>,
        S: crate::ivc::step::StepCircuit<F>,
    {
        // Step 1: Build the verifier witness from the PREVIOUS accumulation proof
        let verifier_witness = if let (Some(prev_proof), Some(prev_insts)) = (
            &prev_state.last_accumulation_proof,
            &prev_state.prev_instances,
        ) {
            let num_vars = prev_insts[0].linear_claim.num_variables();
            let roots: Vec<Vec<F>> = prev_insts
                .iter()
                .map(|inst| inst.commitment_root.iter().map(|&w| w.into()).collect())
                .collect();
            let targets: Vec<_> = prev_insts
                .iter()
                .map(|inst| {
                    *inst
                        .linear_claim
                        .iter()
                        .next()
                        .expect("each accumulator instance must have at least one linear claim")
                        .1
                })
                .collect();
            Some(AccumulationVerifierWitness::<F>::from_transcript(
                &prev_proof.transcript,
                roots,
                targets,
                num_vars,
            ))
        } else {
            None
        };

        // Step 2: Synthesize the unified circuit (step + verifier)
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let mut circuit_challenger = CircuitChallenger::<F, 16, 8>::new(&mut circuit_builder);

        let _output_vars = synthesize_unified_ivc_circuit::<F, L, Perm2, S, 16, 8>(
            &mut circuit_builder,
            &mut circuit_challenger,
            poseidon_config,
            poseidon_perm,
            step_circuit,
            step_input_state,
            verifier_witness.as_ref(),
            w_param,
            None, // No padding needed when verifier is present
        );

        let (unified_shape, unified_instance) = circuit_builder.build();
        assert!(
            unified_shape.is_sat(unified_instance.witness(), unified_instance.input()),
            "unified IVC circuit does not satisfy R1CS",
        );

        // Step 3: Prove the unified circuit with Spartan
        let unified_proof =
            self.spartan_prover.prove::<EF, _>(&unified_instance, spartan_challenger);
        let unified_witness = self.spartan_prover.prepare_witness(&unified_instance);

        // Step 4: Linearize into an accumulator
        let new_acc = initialize_accumulator_from_spartan::<F, EF, W, DIGEST_ELEMS>(
            &unified_shape,
            &unified_proof,
            unified_witness,
            [W::default(); DIGEST_ELEMS],
            self.linearization_challenge,
        );
        debug_assert!(decide_linearized_accumulator(&new_acc));

        // Step 5: Fold with running accumulator using recursive_whir_config
        let accumulators = [prev_state.accumulator.clone(), new_acc];
        let fold_instances: Vec<_> = accumulators
            .iter()
            .map(|a| a.public_instance.clone())
            .collect();

        let (folded, fold_proof) =
            LinearizedAccumulationProver::new(recursive_whir_config)
                .accumulate::<P, W, PW, Dft, DIGEST_ELEMS>(
                    dft,
                    accumulation_challenger,
                    &accumulators,
                    self.num_shift_queries,
                )?;
        debug_assert!(decide_linearized_accumulator(&folded));

        Ok(IVCState {
            step: prev_state.step + 1,
            accumulator: folded,
            last_accumulation_proof: Some(fold_proof),
            prev_instances: Some(fold_instances),
            public_state: new_public_state,
        })
    }
}

/// IVC verifier: checks the final state of an IVC chain.
#[derive(Debug)]
pub struct IVCVerifier<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    whir_config: &'a WhirConfig<EF, F, H, C, Challenger>,
    _marker: PhantomData<(EF, F)>,
}

impl<'a, EF, F, H, C, Challenger> IVCVerifier<'a, EF, F, H, C, Challenger>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub fn new(whir_config: &'a WhirConfig<EF, F, H, C, Challenger>) -> Self {
        Self {
            whir_config,
            _marker: PhantomData,
        }
    }

    /// Verify the last accumulation step of the IVC chain.
    pub fn verify_accumulation<P, W, PW, const DIGEST_ELEMS: usize>(
        &self,
        accumulation_challenger: &mut Challenger,
        state: &IVCState<F, EF, W, DIGEST_ELEMS>,
    ) -> Result<(), crate::whir::verifier::errors::VerifierError>
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
        if let (Some(proof), Some(prev_instances)) =
            (&state.last_accumulation_proof, &state.prev_instances)
        {
            let _verified_instance =
                LinearizedAccumulationVerifier::new(self.whir_config)
                    .verify::<P, W, PW, DIGEST_ELEMS>(
                        accumulation_challenger,
                        prev_instances,
                        proof,
                    )?;
        }

        Ok(())
    }

    /// Run the decider: verify a standalone `DeciderProof` against the final accumulator.
    pub fn verify_decider<P, W, PW, const DIGEST_ELEMS: usize>(
        &self,
        decider_challenger: &mut Challenger,
        state: &IVCState<F, EF, W, DIGEST_ELEMS>,
        decider_proof: &DeciderProof<F, EF, W, DIGEST_ELEMS>,
    ) -> Result<(), crate::whir::verifier::errors::VerifierError>
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
        AccumulationDecider::new(self.whir_config).verify::<P, W, PW, DIGEST_ELEMS>(
            decider_challenger,
            &state.accumulator.public_instance,
            decider_proof,
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;
    use crate::{
        fiat_shamir::domain_separator::DomainSeparator,
        ivc::verifier_circuit::synthesize_unified_ivc_circuit,
        parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
        spartan::r1cs::SparseMatEntry,
    };

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2KoalaBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    fn make_square_shape() -> R1CSShape<F> {
        R1CSShape::new(
            4, 4, 1,
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 0, F::ONE)],
            vec![SparseMatEntry::new(0, 1, F::ONE)],
        )
    }

    fn make_square_instance(shape: &R1CSShape<F>, root: u64) -> R1CSInstance<F> {
        let square = root * root;
        let mut witness = vec![F::ZERO; 4];
        witness[0] = F::from_u64(root);
        witness[1] = F::from_u64(square);
        R1CSInstance::new(shape.clone(), vec![F::ZERO], witness)
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
    fn ivc_two_steps() {
        let shape = make_square_shape();
        let config = make_whir_config();
        let dft = Radix2DFTSmallBatch::<F>::default();

        let ivc_prover = IVCProver::<EF, F, MyHash, MyCompress, MyChallenger>::new(
            &config,
            EF::from_u64(3),
            2,
        );

        // Step 0: Initialize with first instance (3^2 = 9)
        let instance0 = make_square_instance(&shape, 3);
        let mut spartan_chal0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1)));
        let state0 = ivc_prover.init::<F, 8>(
            &shape,
            &instance0,
            &mut spartan_chal0,
            vec![F::from_u64(9)],
        );
        assert_eq!(state0.step, 1);

        // Step 1: Fold in second instance (5^2 = 25)
        let instance1 = make_square_instance(&shape, 5);
        let mut spartan_chal1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(2)));
        let mut acc_chal1 = seed_challenger(&config);
        let state1 = ivc_prover
            .prove_step::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &shape,
                &instance1,
                &mut spartan_chal1,
                &mut acc_chal1,
                &state0,
                vec![F::from_u64(25)],
            )
            .unwrap();
        assert_eq!(state1.step, 2);

        // Verify: the final accumulator should pass the decider
        assert!(decide_linearized_accumulator(&state1.accumulator));

        // Verify the accumulation proof
        let mut verify_acc_chal = seed_challenger(&config);
        let verified = LinearizedAccumulationVerifier::new(&config)
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut verify_acc_chal,
                state1.prev_instances.as_ref().unwrap(),
                state1.last_accumulation_proof.as_ref().unwrap(),
            );
        assert!(verified.is_ok(), "accumulation verification failed");
    }

    #[test]
    fn ivc_three_steps_with_decider() {
        let shape = make_square_shape();
        let config = make_whir_config();
        let dft = Radix2DFTSmallBatch::<F>::default();

        let ivc_prover = IVCProver::<EF, F, MyHash, MyCompress, MyChallenger>::new(
            &config,
            EF::from_u64(3),
            2,
        );

        // Step 0: 3^2 = 9
        let instance0 = make_square_instance(&shape, 3);
        let mut chal0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(10)));
        let state0 = ivc_prover.init::<F, 8>(
            &shape,
            &instance0,
            &mut chal0,
            vec![F::from_u64(9)],
        );

        // Step 1: 5^2 = 25
        let instance1 = make_square_instance(&shape, 5);
        let mut chal1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(20)));
        let mut acc_chal1 = seed_challenger(&config);
        let state1 = ivc_prover
            .prove_step::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &shape,
                &instance1,
                &mut chal1,
                &mut acc_chal1,
                &state0,
                vec![F::from_u64(25)],
            )
            .unwrap();

        // Step 2: 7^2 = 49
        let instance2 = make_square_instance(&shape, 7);
        let mut chal2 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(30)));
        let mut acc_chal2 = seed_challenger(&config);
        let state2 = ivc_prover
            .prove_step::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &shape,
                &instance2,
                &mut chal2,
                &mut acc_chal2,
                &state1,
                vec![F::from_u64(49)],
            )
            .unwrap();

        assert_eq!(state2.step, 3);
        assert!(decide_linearized_accumulator(&state2.accumulator));

        // Run decider on final state
        let decider = AccumulationDecider::new(&config);
        let mut decider_prove_chal = seed_challenger(&config);
        let decider_proof = decider
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut decider_prove_chal,
                &state2.accumulator,
            )
            .unwrap();

        let mut decider_verify_chal = seed_challenger(&config);
        let result = decider.verify::<
            <F as Field>::Packing,
            F,
            <F as Field>::Packing,
            8,
        >(
            &mut decider_verify_chal,
            &state2.accumulator.public_instance,
            &decider_proof,
        );

        assert!(result.is_ok(), "decider failed on 3-step IVC: {result:?}");
    }

    #[test]
    #[ignore] // Slow: involves multiple Spartan proofs of ~16K constraint circuits
    fn ivc_recursive_step() {
        use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;

        let config = make_whir_config();
        let dft = Radix2DFTSmallBatch::<F>::default();

        // Recursive WHIR config sized for the unified circuit polynomial (~15 vars)
        let recursive_config = {
            let mut rng = SmallRng::seed_from_u64(55);
            let perm_inner = Perm::new_from_rng_128(&mut rng);
            let params = crate::parameters::ProtocolParameters {
                security_level: 100,
                pow_bits: 0,
                rs_domain_initial_reduction_factor: 1,
                folding_factor: crate::parameters::FoldingFactor::Constant(2),
                merkle_hash: MyHash::new(perm_inner.clone()),
                merkle_compress: MyCompress::new(perm_inner),
                soundness_type: crate::parameters::errors::SecurityAssumption::CapacityBound,
                starting_log_inv_rate: 1,
            };
            WhirConfig::<EF, F, MyHash, MyCompress, MyChallenger>::new(15, params)
        };

        let ivc_prover = IVCProver::<EF, F, MyHash, MyCompress, MyChallenger>::new(
            &config,
            EF::from_u64(3),
            2,
        );

        let acc_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = crate::circuit::poseidon2::Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 20, 3, &mut SmallRng::seed_from_u64(99),
        );
        let step = crate::ivc::step::TrivialStepCircuit::new(1);

        // Pre-compute the target witness count by building one sample circuit with
        // the verifier included (using dummy data that has the right shape).
        let target_witness = {
            use crate::ivc::verifier_circuit::AccumulationVerifierWitness;
            let dummy_witness = AccumulationVerifierWitness {
                input_commitment_roots: alloc::vec![alloc::vec![F::ZERO; 8]; 2],
                input_targets: alloc::vec![[F::ZERO; 4]; 2],
                sumcheck_s0s: alloc::vec![[F::ZERO; 4]; 3],
                sumcheck_s2s: alloc::vec![[F::ZERO; 4]; 3],
                individual_evals: alloc::vec![[F::ZERO; 4]; 2],
                codeword_batching_challenge: F::ZERO,
                ood_point: alloc::vec![[F::ZERO; 4]; 3],
                shift_query_indices: alloc::vec![0; 2],
                num_vars: 3,
            };
            let poseidon_perm_probe = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
            let poseidon_config_probe =
                crate::circuit::poseidon2::Poseidon2CircuitConfig::<F, 16>::from_rng(
                    8, 20, 3, &mut SmallRng::seed_from_u64(99),
                );
            let mut probe_builder = CircuitBuilder::<F>::new();
            let mut probe_challenger = CircuitChallenger::<F, 16, 8>::new(&mut probe_builder);
            let _ = synthesize_unified_ivc_circuit::<
                F,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
                16,
                8,
            >(
                &mut probe_builder,
                &mut probe_challenger,
                &poseidon_config_probe,
                &poseidon_perm_probe,
                &step,
                &[F::ZERO],
                Some(&dummy_witness),
                F::from_u64(3),
                None,
            );
            probe_builder.num_witness_vars()
        };

        // Step 0: Initialize with unified circuit so accumulator has the right poly size
        let mut chal0 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(10)));
        let state0 = ivc_prover
            .init_unified::<
                <F as Field>::Packing,
                F,
                <F as Field>::Packing,
                Radix2DFTSmallBatch<F>,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
                8,
            >(
                &step,
                &[F::from_u64(9)],
                &mut chal0,
                &poseidon_config,
                &poseidon_perm,
                F::from_u64(3),
                Some(target_witness),
                vec![F::from_u64(9)],
            );

        // Step 1: Non-recursive fold using the recursive config (same poly size)
        let mut spartan_chal1 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(20)));
        let mut acc_chal1 = MyChallenger::new(acc_perm.clone());

        // Build a step 1 unified circuit to get matching accumulator
        let mut builder1 = CircuitBuilder::<F>::new();
        let mut chal1_circuit = CircuitChallenger::<F, 16, 8>::new(&mut builder1);
        let _ = synthesize_unified_ivc_circuit::<
            F,
            GenericPoseidon2LinearLayersKoalaBear,
            _,
            _,
            16,
            8,
        >(
            &mut builder1,
            &mut chal1_circuit,
            &poseidon_config,
            &poseidon_perm,
            &step,
            &[F::from_u64(25)],
            None,
            F::from_u64(3),
            Some(target_witness),
        );
        let (shape1, instance1) = builder1.build();
        let proof1 = ivc_prover.spartan_prover.prove::<EF, _>(&instance1, &mut spartan_chal1);
        let witness1 = ivc_prover.spartan_prover.prepare_witness(&instance1);
        let acc1 = initialize_accumulator_from_spartan::<F, EF, F, 8>(
            &shape1, &proof1, witness1, [F::ZERO; 8], EF::from_u64(3),
        );

        let accumulators1 = [state0.accumulator.clone(), acc1];
        let instances1: Vec<_> = accumulators1.iter().map(|a| a.public_instance.clone()).collect();
        let (folded1, fold_proof1) = LinearizedAccumulationProver::new(&recursive_config)
            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                &dft, &mut acc_chal1, &accumulators1, 2,
            )
            .unwrap();
        let state1 = IVCState {
            step: 2,
            accumulator: folded1,
            last_accumulation_proof: Some(fold_proof1),
            prev_instances: Some(instances1),
            public_state: vec![F::from_u64(25)],
        };

        // Step 2: Recursive step — unified circuit verifies step 1's accumulation in-circuit
        let mut spartan_chal2 =
            MyChallenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(30)));
        let mut acc_chal2 = MyChallenger::new(acc_perm.clone());

        let state2 = ivc_prover
            .prove_step_recursive::<
                _,
                F,
                <F as Field>::Packing,
                _,
                GenericPoseidon2LinearLayersKoalaBear,
                _,
                _,
                8,
            >(
                &dft,
                &step,
                &[F::from_u64(49)],
                &mut spartan_chal2,
                &mut acc_chal2,
                &state1,
                vec![F::from_u64(49)],
                &poseidon_config,
                &poseidon_perm,
                F::from_u64(3),
                &recursive_config,
            )
            .unwrap();

        assert_eq!(state2.step, 3);
        assert!(decide_linearized_accumulator(&state2.accumulator));

        // Verify with decider (using recursive config sized for the unified circuit)
        let decider = AccumulationDecider::new(&recursive_config);
        let mut decider_chal = seed_challenger(&config);
        let decider_proof = decider
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut decider_chal,
                &state2.accumulator,
            )
            .unwrap();

        let mut verify_chal = seed_challenger(&config);
        let result = decider.verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
            &mut verify_chal,
            &state2.accumulator.public_instance,
            &decider_proof,
        );
        assert!(result.is_ok(), "decider failed on recursive IVC: {result:?}");
    }

    /// Fast test: verifies unified circuit sizing without Spartan proving.
    /// Checks that init (with padding) and a real verifier circuit produce
    /// the same num_poly_vars, enabling a single WHIR config.
    #[test]
    fn unified_circuit_sizing_matches() {
        use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;

        let poseidon_perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));
        let poseidon_config = crate::circuit::poseidon2::Poseidon2CircuitConfig::<F, 16>::from_rng(
            8, 20, 3, &mut SmallRng::seed_from_u64(99),
        );
        let step = crate::ivc::step::TrivialStepCircuit::new(1);

        // Build circuit WITH verifier (using dummy but structurally correct witness)
        let dummy_witness = crate::ivc::verifier_circuit::AccumulationVerifierWitness {
            input_commitment_roots: alloc::vec![alloc::vec![F::ZERO; 8]; 2],
            input_targets: alloc::vec![[F::ZERO; 4]; 2],
            sumcheck_s0s: alloc::vec![[F::ZERO; 4]; 3],
            sumcheck_s2s: alloc::vec![[F::ZERO; 4]; 3],
            individual_evals: alloc::vec![[F::ZERO; 4]; 2],
            codeword_batching_challenge: F::ZERO,
            ood_point: alloc::vec![[F::ZERO; 4]; 3],
            shift_query_indices: alloc::vec![0; 2],
            num_vars: 3,
        };

        let mut builder_with = CircuitBuilder::<F>::new();
        let mut chal_with = CircuitChallenger::<F, 16, 8>::new(&mut builder_with);
        let _ = synthesize_unified_ivc_circuit::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, _, 16, 8,
        >(
            &mut builder_with, &mut chal_with, &poseidon_config, &poseidon_perm,
            &step, &[F::ZERO], Some(&dummy_witness), F::from_u64(3), None,
        );
        let target = builder_with.num_witness_vars();

        // Build circuit WITHOUT verifier but padded to target
        let mut builder_without = CircuitBuilder::<F>::new();
        let mut chal_without = CircuitChallenger::<F, 16, 8>::new(&mut builder_without);
        let _ = synthesize_unified_ivc_circuit::<
            F, GenericPoseidon2LinearLayersKoalaBear, _, _, 16, 8,
        >(
            &mut builder_without, &mut chal_without, &poseidon_config, &poseidon_perm,
            &step, &[F::ZERO], None, F::from_u64(3), Some(target),
        );

        let (shape_with, _) = builder_with.build();
        let (shape_without, instance_without) = builder_without.build();

        // Both should produce the same num_poly_vars_y (determines WHIR config)
        assert_eq!(
            shape_with.num_poly_vars_y(),
            shape_without.num_poly_vars_y(),
            "padded circuit has different poly vars: with={}, without={}",
            shape_with.num_poly_vars_y(),
            shape_without.num_poly_vars_y(),
        );

        // The padded circuit should satisfy R1CS
        assert!(instance_without.verify(), "padded circuit R1CS not satisfied");
    }
}
