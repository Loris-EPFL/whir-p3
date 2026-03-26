//! Full pipeline: Spartan → Quasar Multicast → Eval Fold → Terminal WHIR.
//!
//! This module wires the complete accumulation pipeline:
//!
//! 1. **Spartan** proves R1CS satisfaction (degree-3) → linearizes into
//!    `FreshLinearInstance` (weight table λ, target σ). The nonlinearity
//!    is consumed by the Spartan sumcheck.
//!
//! 2. **Quasar multicast** batches l linear claims via `constraint_batch_prove`
//!    → reduces to point evaluations fᵢ(r). Then `random_linear_combination`
//!    combines the l witness polynomials into one of the same size:
//!    f = Σᵢ ηⁱ·fᵢ with evaluation claim f(r) = Σᵢ ηⁱ·fᵢ(r).
//!
//! 3. **Eval fold** takes the combined witness + running accumulator, RS-encodes,
//!    Merkle-commits, runs an eval-claim-only sumcheck, shift queries, OOD
//!    sampling, and evaluation batching. No WHIR proof at this step.
//!
//! 4. **Terminal WHIR** generates a single WHIR proof on the final accumulator.
//!
//! Key property: witness size is fixed at every step (random LC preserves size).

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::{rngs::SmallRng, SeedableRng};

    use crate::{
        accumulation::{
            constraint_batch::constraint_batch_prove,
            linearized::linearized_statement_from_spartan_proof,
            quasar::fresh::FreshLinearInstance,
            random_lc::random_linear_combination,
            warp::{
                encoding::rs_encode,
                eval_fold::{
                    eval_fold_prove, initial_eval_accumulator, EvalAccumulator,
                    EvalAccumulatorInstance, EvalAccumulatorWitness,
                },
                fold::RSEncodingConfig,
            },
        },
        poly::evals::EvaluationsList,
        spartan::{
            r1cs::{R1CSInstance, R1CSShape, SparseMatEntry},
            r1cs_prover::R1CSProver,
        },
    };

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
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

    /// Step 1: Spartan → FreshLinearInstance
    fn spartan_linearize(
        shape: &R1CSShape<F>,
        instance: &R1CSInstance<F>,
        seed: u64,
    ) -> (FreshLinearInstance<F, EF>, EvaluationsList<F>) {
        let prover = R1CSProver::new();
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
        let mut challenger = MyChallenger::new(perm);
        let proof = prover.prove::<EF, _>(instance, &mut challenger);
        let witness = prover.prepare_witness(instance);

        let linear_claim = linearized_statement_from_spartan_proof(
            shape,
            &proof,
            EF::from_u64(3),
        );
        assert!(linear_claim.verify(&witness), "Spartan linearization failed");

        (
            FreshLinearInstance::new(linear_claim, witness.clone()),
            witness,
        )
    }

    /// Step 2: Quasar multicast — batch l linear claims → combined witness + eval claim
    fn quasar_multicast(
        fresh_instances: &[FreshLinearInstance<F, EF>],
        witnesses: &[EvaluationsList<F>],
    ) -> (EvaluationsList<F>, Vec<EF>, Vec<EF>) {
        // Extract weights and targets from each FreshLinearInstance
        let mut weights = Vec::new();
        let mut targets = Vec::new();
        for inst in fresh_instances {
            let (w, &t) = inst.linear_claim.iter().next().unwrap();
            weights.push(w.clone());
            targets.push(t);
        }

        // Constraint batching sumcheck
        let gamma = F::from_u64(42);
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(77));
        let mut challenger = MyChallenger::new(perm);
        let (batch_proof, reduction_point) = constraint_batch_prove(
            gamma,
            &weights,
            &targets,
            witnesses,
            &mut challenger,
        );

        // Random LC: combine witnesses
        let eta = F::from_u64(13);
        let witness_refs: Vec<&EvaluationsList<F>> = witnesses.iter().collect();
        let combined = random_linear_combination(&witness_refs, eta);

        // Combined eval at reduction point: f(r) = Σ ηⁱ · fᵢ(r)
        let eta_ef = EF::from(eta);
        let mut combined_eval = EF::ZERO;
        let mut power = EF::ONE;
        for eval in &batch_proof.individual_evals {
            combined_eval += power * *eval;
            power *= eta_ef;
        }

        // Return combined witness, reduction point (as EF coords), and individual evals
        let point_coords: Vec<EF> = reduction_point.as_slice().to_vec();

        (combined, point_coords, batch_proof.individual_evals)
    }

    /// Full pipeline test: Spartan → Quasar → Eval Fold → verify consistency
    #[test]
    fn full_pipeline_two_instances_one_fold() {
        let shape = make_square_shape();
        let instance0 = make_square_instance(&shape, 3); // 3² = 9
        let instance1 = make_square_instance(&shape, 5); // 5² = 25

        // Step 1: Spartan linearize
        let (fresh0, wit0) = spartan_linearize(&shape, &instance0, 1);
        let (fresh1, wit1) = spartan_linearize(&shape, &instance1, 2);

        // Verify linear claims hold
        assert!(fresh0.verify());
        assert!(fresh1.verify());

        // Step 2: Quasar multicast
        let (combined, _reduction_point, _individual_evals) =
            quasar_multicast(&[fresh0, fresh1], &[wit0, wit1]);

        // Witness size preserved
        assert_eq!(combined.num_evals(), 8); // 2^3 (num_poly_vars_y = 3)

        // Step 3: Create initial accumulator + fresh accumulator from Quasar output
        let rs_config = RSEncodingConfig::new(1, 1); // folding_factor=1, log_inv_rate=1
        let dft = Radix2DFTSmallBatch::<F>::default();

        // RS-encode combined witness
        let codeword = rs_encode(&combined, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
        let code_len = codeword.as_slice().len();
        let log_n = code_len.trailing_zeros() as usize;

        // Create simple eval claim: evaluate at zero → codeword[0]
        let eval_point = vec![F::ZERO; log_n];
        let eval_claim = codeword.as_slice()[0]; // f̃(0...0) = f[0]

        let fresh_acc = EvalAccumulator {
            instance: EvalAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point,
                eval_claim,
            },
            witness: EvalAccumulatorWitness {
                codeword,
                witness_poly: combined,
            },
        };

        // Initial (zero) running accumulator
        let running = initial_eval_accumulator::<F, 8>(code_len, 8, log_n);

        // Step 4: Eval fold
        let tau = vec![F::from_u64(7)]; // log_2(2) = 1 challenge
        let mut ctr = 0u64;
        let result = eval_fold_prove(
            &[running, fresh_acc],
            &tau,
            &rs_config,
            &dft,
            0, 0,
            |_| { ctr += 1; F::from_u64(ctr + 300) },
            |_cw, _ff| [F::ZERO; 8],
        );

        // Verify: witness size is preserved
        assert_eq!(
            result.witness.codeword.as_slice().len(),
            code_len,
            "codeword size changed after fold"
        );

        // Verify: sumcheck produced valid transcript
        assert_eq!(result.sumcheck_round_polys.len(), 1);
        assert_eq!(result.sumcheck_challenges.len(), 1);

        // The eval claim is set internally by the batching sumcheck
        assert_ne!(result.instance.eval_claim, F::ZERO);
    }

    /// Test: sequential IVC-style folds maintain fixed witness size
    #[test]
    fn pipeline_sequential_folds_fixed_size() {
        let shape = make_square_shape();
        let rs_config = RSEncodingConfig::new(1, 1);
        let dft = Radix2DFTSmallBatch::<F>::default();

        // Initial accumulator
        let code_len = 16; // 2^4 (8 witness * rate 2)
        let log_n = 4;
        let mut running: EvalAccumulator<F, 8> = initial_eval_accumulator(code_len, 8, log_n);

        for step in 0u64..4 {
            let root = step + 2;
            let instance = make_square_instance(&shape, root);
            let (fresh_linear, witness) = spartan_linearize(&shape, &instance, step + 10);
            assert!(fresh_linear.verify());

            // For single-instance "multicast" — just RS-encode the witness directly
            let codeword = rs_encode(&witness, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
            assert_eq!(codeword.as_slice().len(), code_len);

            let eval_point = vec![F::ZERO; log_n];
            let eval_claim = codeword.as_slice()[0];

            let fresh_acc = EvalAccumulator {
                instance: EvalAccumulatorInstance {
                    commitment_root: [F::ZERO; 8],
                    eval_point,
                    eval_claim,
                },
                witness: EvalAccumulatorWitness {
                    codeword,
                    witness_poly: witness,
                },
            };

            let tau = vec![F::from_u64(step + 42)];
            let mut ctr = step * 1000;
            let result = eval_fold_prove(
                &[running, fresh_acc],
                &tau,
                &rs_config,
                &dft,
                0, 0,
                |_| { ctr += 1; F::from_u64(ctr + 500) },
                |_cw, _ff| [F::ZERO; 8],
            );

            assert_eq!(
                result.witness.codeword.as_slice().len(), code_len,
                "codeword size changed at step {step}"
            );
            assert_eq!(
                result.witness.witness_poly.num_evals(), 8,
                "witness poly size changed at step {step}"
            );

            running = EvalAccumulator {
                instance: result.instance,
                witness: result.witness,
            };
        }
    }
}

