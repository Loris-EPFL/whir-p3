//! Full pipeline: Spartan → Batch Reduction → Eval Fold → Terminal WHIR.
//!
//! This module wires the complete accumulation pipeline:
//!
//! 1. **Spartan** proves R1CS satisfaction (degree-3) → linearizes into
//!    `FreshLinearInstance` (weight table λ, target σ). The nonlinearity
//!    is consumed by the Spartan sumcheck.
//!
//! 2. **Batch reduction** batches l linear claims via `constraint_batch_prove`
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
                    EvalAccumulatorInstance, EvalAccumulatorWitness, EvalDecider,
                },
                fold::RSEncodingConfig,
            },
        },
        fiat_shamir::domain_separator::DomainSeparator,
        parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
        poly::evals::EvaluationsList,
        spartan::{
            r1cs::{R1CSInstance, R1CSShape, SparseMatEntry},
            r1cs_prover::R1CSProver,
        },
        whir::parameters::WhirConfig,
    };

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
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

    /// Step 2: Batch reduction — batch l linear claims → combined witness + eval claim
    fn batch_reduce(
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

    /// Full pipeline test: Spartan → Batch Reduction → Eval Fold → verify consistency
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

        // Step 2: Batch reduction
        let (combined, _reduction_point, _individual_evals) =
            batch_reduce(&[fresh0, fresh1], &[wit0, wit1]);

        // Witness size preserved
        assert_eq!(combined.num_evals(), 8); // 2^3 (num_poly_vars_y = 3)

        // Step 3: Create initial accumulator + fresh accumulator from batch reduction output
        let rs_config = RSEncodingConfig::new(1, 1); // folding_factor=1, log_inv_rate=1
        let dft = Radix2DFTSmallBatch::<F>::default();

        // RS-encode combined witness
        let codeword = rs_encode(&combined, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
        let code_len = codeword.as_slice().len();
        let log_n = code_len.trailing_zeros() as usize;

        // Create eval claim on the WITNESS polynomial (not codeword).
        // Evaluate at zero → witness[0] = f̃_wit(0...0)
        let witness_num_vars = combined.num_variables();
        let eval_point = vec![F::ZERO; witness_num_vars];
        let eval_claim = combined.as_slice()[0]; // f̃_wit(0...0) = f[0]

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

        // Initial (zero) running accumulator — eval_point in witness domain
        let running = initial_eval_accumulator::<F, 8>(code_len, 1 << witness_num_vars, witness_num_vars);

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

        // Initial accumulator — eval claims are on witness (3 vars), codewords are 2x (4 vars)
        let witness_num_vars = 3; // 2^3 = 8
        let code_len = 16; // 2^4 (8 witness * rate 2)
        let mut running: EvalAccumulator<F, 8> = initial_eval_accumulator(code_len, 8, witness_num_vars);

        for step in 0u64..4 {
            let root = step + 2;
            let instance = make_square_instance(&shape, root);
            let (fresh_linear, witness) = spartan_linearize(&shape, &instance, step + 10);
            assert!(fresh_linear.verify());

            // RS-encode the witness for the codeword
            let codeword = rs_encode(&witness, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
            assert_eq!(codeword.as_slice().len(), code_len);

            // Eval claim on WITNESS polynomial (not codeword)
            let eval_point = vec![F::ZERO; witness_num_vars];
            let eval_claim = witness.as_slice()[0]; // f̃_wit(0..0) = f[0]

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

    // ── WHIR helpers ─────────────────────────────────────────────────

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

    fn seed_whir_challenger(
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

    // ── End-to-end test: Spartan → Batch Reduction → EvalFold → WHIR ─────────

    /// Full pipeline with terminal WHIR proof:
    /// 1. Spartan proves 4 R1CS instances
    /// 2. Batch reduction batches them (2 at a time)
    /// 3. Eval fold accumulates over 2 steps
    /// 4. Terminal WHIR prove + verify on the final accumulator
    #[test]
    fn full_pipeline_spartan_batch_evalfold_whir() {
        let shape = make_square_shape();
        let rs_config = RSEncodingConfig::new(1, 1); // rate 1/2
        let dft = Radix2DFTSmallBatch::<F>::default();

        // ── Spartan: prove 4 R1CS instances ──
        let instances: Vec<R1CSInstance<F>> = (2..6u64)
            .map(|root| make_square_instance(&shape, root))
            .collect();

        let linearized: Vec<(FreshLinearInstance<F, EF>, EvaluationsList<F>)> = instances
            .iter()
            .enumerate()
            .map(|(i, inst)| spartan_linearize(&shape, inst, i as u64 + 100))
            .collect();

        for (fresh, _) in &linearized {
            assert!(fresh.verify(), "Spartan linearization failed");
        }

        // ── First fold step: multicast instances 0,1 → fold with initial acc ──
        let (combined_01, _pt01, _evals01) = batch_reduce(
            &[linearized[0].0.clone(), linearized[1].0.clone()],
            &[linearized[0].1.clone(), linearized[1].1.clone()],
        );
        let witness_num_vars = combined_01.num_variables(); // 3

        let cw01 = rs_encode(&combined_01, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
        let code_len = cw01.as_slice().len();
        let log_n = code_len.trailing_zeros() as usize;

        // Eval claim on WITNESS polynomial
        let fresh_acc_01 = EvalAccumulator {
            instance: EvalAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: vec![F::ZERO; witness_num_vars],
                eval_claim: combined_01.as_slice()[0], // f̃_wit(0..0)
            },
            witness: EvalAccumulatorWitness {
                codeword: cw01,
                witness_poly: combined_01,
            },
        };

        let mut running: EvalAccumulator<F, 8> = initial_eval_accumulator(code_len, 1 << witness_num_vars, witness_num_vars);

        let tau1 = vec![F::from_u64(7)];
        let mut ctr = 0u64;
        let result1 = eval_fold_prove(
            &[running, fresh_acc_01],
            &tau1, &rs_config, &dft, 0, 0,
            |_| { ctr += 1; F::from_u64(ctr + 300) },
            |_cw, _ff| [F::ZERO; 8],
        );
        running = EvalAccumulator { instance: result1.instance, witness: result1.witness };

        // ── Second fold step: multicast instances 2,3 → fold ──
        let (combined_23, _pt23, _evals23) = batch_reduce(
            &[linearized[2].0.clone(), linearized[3].0.clone()],
            &[linearized[2].1.clone(), linearized[3].1.clone()],
        );

        let cw23 = rs_encode(&combined_23, rs_config.folding_factor, rs_config.log_inv_rate, &dft);
        assert_eq!(cw23.as_slice().len(), code_len);

        let fresh_acc_23 = EvalAccumulator {
            instance: EvalAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: vec![F::ZERO; witness_num_vars],
                eval_claim: combined_23.as_slice()[0],
            },
            witness: EvalAccumulatorWitness {
                codeword: cw23,
                witness_poly: combined_23,
            },
        };

        let tau2 = vec![F::from_u64(11)];
        let result2 = eval_fold_prove(
            &[running, fresh_acc_23],
            &tau2, &rs_config, &dft, 0, 0,
            |_| { ctr += 1; F::from_u64(ctr + 600) },
            |_cw, _ff| [F::ZERO; 8],
        );
        running = EvalAccumulator { instance: result2.instance, witness: result2.witness };

        // Verify witness size stayed fixed
        assert_eq!(running.witness.codeword.as_slice().len(), code_len);
        assert_eq!(running.witness.witness_poly.num_evals(), 1 << witness_num_vars);

        // ── Terminal WHIR proof ──
        // WHIR operates on the witness polynomial (not codeword)
        let whir_config = make_whir_config(witness_num_vars);
        let decider = EvalDecider::<EF, F, MyHash, MyCompress, MyChallenger>::new(&whir_config);

        // Prove
        let mut prove_challenger = seed_whir_challenger(&whir_config, 999);
        let decider_proof = decider
            .prove::<_, F, <F as Field>::Packing, _, 8>(
                &dft,
                &mut prove_challenger,
                &running,
            )
            .expect("terminal WHIR prove failed");

        // Verify
        let mut verify_challenger = seed_whir_challenger(&whir_config, 999);
        let verify_result = decider
            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &mut verify_challenger,
                &running,
                &decider_proof,
            );

        assert!(
            verify_result.is_ok(),
            "terminal WHIR verify failed: {verify_result:?}"
        );
    }
}

