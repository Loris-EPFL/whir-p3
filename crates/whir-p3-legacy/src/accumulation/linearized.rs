use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

use crate::{
    accumulation::accumulator::{Accumulator, AccumulatorInstance, AccumulatorWitness},
    accumulation::union_poly::build_union_polynomial,
    poly::evals::EvaluationsList,
    spartan::{
        encoding::eq_poly_at_index,
        r1cs::R1CSShape,
        r1cs_prover::{R1CSProof, R1CSProver},
    },
    whir::constraints::statement::LinearStatement,
};

fn dense_matrix_row_combination<F: Field>(
    shape: &R1CSShape<F>,
    rx: &[F],
) -> (Vec<F>, Vec<F>, Vec<F>) {
    let num_y = 1usize << shape.num_poly_vars_y();
    let mut a_vals = vec![F::ZERO; num_y];
    let mut b_vals = vec![F::ZERO; num_y];
    let mut c_vals = vec![F::ZERO; num_y];

    for entry in shape.a().entries() {
        let eq_row = eq_poly_at_index::<F, F>(entry.row, rx);
        a_vals[entry.col] += entry.val * eq_row;
    }
    for entry in shape.b().entries() {
        let eq_row = eq_poly_at_index::<F, F>(entry.row, rx);
        b_vals[entry.col] += entry.val * eq_row;
    }
    for entry in shape.c().entries() {
        let eq_row = eq_poly_at_index::<F, F>(entry.row, rx);
        c_vals[entry.col] += entry.val * eq_row;
    }

    (a_vals, b_vals, c_vals)
}

fn lift_evals<F: Field, EF: ExtensionField<F>>(evals: Vec<F>) -> EvaluationsList<EF> {
    EvaluationsList::new(evals.into_iter().map(EF::from).collect())
}

fn combine_weights<F: Field, EF: ExtensionField<F>>(
    weights: &[EvaluationsList<EF>],
    batching_challenge: EF,
) -> EvaluationsList<EF> {
    let num_variables = weights[0].num_variables();
    let mut combined = EvaluationsList::zero(num_variables);
    for (weight, coeff) in weights.iter().zip(batching_challenge.powers()) {
        combined
            .iter_mut()
            .zip(weight.as_slice().iter())
            .for_each(|(acc, &value)| *acc += coeff * value);
    }
    combined
}

fn linearized_components<F: Field, EF: ExtensionField<F>>(
    shape: &R1CSShape<F>,
    proof: &R1CSProof<F, EF>,
) -> [(EvaluationsList<EF>, EF); 4] {
    let (a_vals, b_vals, c_vals) = dense_matrix_row_combination(shape, &proof.eval_claims.rx);
    let ry_ef: Vec<_> = proof.eval_claims.ry.iter().copied().map(EF::from).collect();
    let eq_ry = EvaluationsList::new(
        (0..(1usize << shape.num_poly_vars_y()))
            .map(|idx| eq_poly_at_index::<EF, F>(idx, &ry_ef))
            .collect(),
    );

    [
        (eq_ry, EF::from(proof.eval_claims.z_eval)),
        (
            lift_evals::<F, EF>(a_vals),
            EF::from(proof.eval_claims.a_eval),
        ),
        (
            lift_evals::<F, EF>(b_vals),
            EF::from(proof.eval_claims.b_eval),
        ),
        (
            lift_evals::<F, EF>(c_vals),
            EF::from(proof.eval_claims.c_eval),
        ),
    ]
}

/// Builds a single accumulated linearized witness claim from a Spartan proof.
pub fn linearized_statement_from_spartan_proof<F: Field, EF: ExtensionField<F>>(
    shape: &R1CSShape<F>,
    proof: &R1CSProof<F, EF>,
    batching_challenge: EF,
) -> LinearStatement<F, EF> {
    let num_variables = shape.num_poly_vars_y();
    let components = linearized_components(shape, proof);
    let weights: Vec<_> = components
        .iter()
        .map(|(weights, _)| weights.clone())
        .collect();
    let expected = components
        .iter()
        .map(|(_, value)| *value)
        .zip(batching_challenge.powers())
        .fold(EF::ZERO, |acc, (value, coeff)| acc + coeff * value);

    let mut statement = LinearStatement::<F, EF>::initialize(num_variables);
    statement.add_constraint(combine_weights(&weights, batching_challenge), expected);
    statement
}

/// Initializes an accumulator from a Spartan proof and witness polynomial.
pub fn initialize_accumulator_from_spartan<F, EF, W, const DIGEST_ELEMS: usize>(
    shape: &R1CSShape<F>,
    proof: &R1CSProof<F, EF>,
    witness_poly: EvaluationsList<F>,
    commitment_root: [W; DIGEST_ELEMS],
    batching_challenge: EF,
) -> Accumulator<F, EF, W, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let linear_claim = linearized_statement_from_spartan_proof(shape, proof, batching_challenge);
    let public_instance = AccumulatorInstance {
        commitment_root,
        linear_claim,
        _marker: PhantomData,
    };
    let witness = AccumulatorWitness { poly: witness_poly };
    Accumulator::new(public_instance, witness)
}

/// Verifies the algebraic part of an accumulator against the explicit witness polynomial.
#[must_use]
pub fn decide_linearized_accumulator<F, EF, W, const DIGEST_ELEMS: usize>(
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

/// Pseudo-batches two accumulators using a single affine-combination challenge.
pub fn accumulate_pair<F, EF, W, const DIGEST_ELEMS: usize>(
    left: &Accumulator<F, EF, W, DIGEST_ELEMS>,
    right: &Accumulator<F, EF, W, DIGEST_ELEMS>,
    gamma: F,
    commitment_root: [W; DIGEST_ELEMS],
) -> Accumulator<F, EF, W, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
    W: Copy,
{
    assert_eq!(
        left.witness.poly.num_variables(),
        right.witness.poly.num_variables()
    );
    assert_eq!(left.public_instance.linear_claim.len(), 1);
    assert_eq!(right.public_instance.linear_claim.len(), 1);

    let gamma_ef = EF::from(gamma);
    let one_minus_gamma_ef = EF::ONE - gamma_ef;
    let left_weight = left.public_instance.linear_claim.weights[0].as_slice();
    let right_weight = right.public_instance.linear_claim.weights[0].as_slice();
    let zero_pad = vec![EF::ZERO; left_weight.len()];
    let left_extended = EvaluationsList::new(
        left_weight
            .iter()
            .copied()
            .chain(zero_pad.iter().copied())
            .collect(),
    );
    let right_extended = EvaluationsList::new(
        zero_pad
            .iter()
            .copied()
            .chain(right_weight.iter().copied())
            .collect(),
    );
    let combined_weight = EvaluationsList::new(
        left_extended
            .as_slice()
            .iter()
            .zip(right_extended.as_slice().iter())
            .map(|(&l, &r)| one_minus_gamma_ef * l + gamma_ef * r)
            .collect(),
    );
    let left_target = *left.public_instance.linear_claim.iter().next().unwrap().1;
    let right_target = *right.public_instance.linear_claim.iter().next().unwrap().1;
    let combined_target = one_minus_gamma_ef * left_target + gamma_ef * right_target;

    let mut linear_claim =
        LinearStatement::<F, EF>::initialize(left.witness.poly.num_variables() + 1);
    linear_claim.add_constraint(combined_weight, combined_target);

    let witness_poly =
        build_union_polynomial(&[left.witness.poly.clone(), right.witness.poly.clone()]);

    Accumulator::new(
        AccumulatorInstance {
            commitment_root,
            linear_claim,
            _marker: PhantomData,
        },
        AccumulatorWitness { poly: witness_poly },
    )
}

/// Convenience helper for tests and demos.
pub fn witness_polynomial_from_instance<F: Field>(
    prover: &R1CSProver<F>,
    instance: &crate::spartan::r1cs::R1CSInstance<F>,
) -> EvaluationsList<F> {
    prover.prepare_witness(instance)
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
        fiat_shamir::domain_separator::DomainSeparator,
        parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
        spartan::r1cs::{R1CSInstance, SparseMatEntry},
        whir::{
            committer::{reader::CommitmentReader, writer::CommitmentWriter},
            parameters::WhirConfig,
            proof::WhirProof,
            prover::Prover as WhirProver,
            verifier::Verifier as WhirVerifier,
        },
    };

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type Challenger = DuplexChallenger<F, Perm, 16, 8>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    fn make_square_instance(square: u64) -> (R1CSShape<F>, R1CSInstance<F>) {
        let num_cons = 4usize;
        let num_vars = 4usize;
        let num_inputs = 1usize;
        let a_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let b_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
        let c_entries = vec![SparseMatEntry::new(0, 1, F::ONE)];
        let shape = R1CSShape::new(
            num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
        );

        let root = (square as f64).sqrt() as u64;
        let mut witness = vec![F::ZERO; num_vars];
        witness[0] = F::from_u64(root);
        witness[1] = F::from_u64(square);
        let input = vec![F::ZERO];
        (shape.clone(), R1CSInstance::new(shape, input, witness))
    }

    fn prove_instance(instance: &R1CSInstance<F>) -> R1CSProof<F, EF> {
        let prover = R1CSProver::new();
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);
        prover.prove::<EF, _>(instance, &mut challenger)
    }

    fn make_whir_config() -> (
        WhirConfig<EF, F, MyHash, MyCompress, Challenger>,
        ProtocolParameters<MyHash, MyCompress>,
    ) {
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
        (WhirConfig::new(3, params.clone()), params)
    }

    #[test]
    fn linearized_statement_matches_spartan_witness() {
        let (shape, instance) = make_square_instance(9);
        let prover = R1CSProver::new();
        let witness = prover.prepare_witness(&instance);
        let proof = prove_instance(&instance);

        for (idx, (weights, expected)) in linearized_components(&shape, &proof)
            .into_iter()
            .enumerate()
        {
            let mut statement = LinearStatement::<F, EF>::initialize(shape.num_poly_vars_y());
            statement.add_constraint(weights, expected);
            assert!(
                statement.verify(&witness),
                "component {idx} does not verify"
            );
        }

        let statement = linearized_statement_from_spartan_proof(&shape, &proof, EF::from_u64(11));
        assert!(statement.verify(&witness));
    }

    #[test]
    fn accumulator_decider_rejects_tampered_target() {
        let (shape, instance) = make_square_instance(9);
        let prover = R1CSProver::new();
        let witness = prover.prepare_witness(&instance);
        let proof = prove_instance(&instance);

        let mut acc = initialize_accumulator_from_spartan::<F, EF, u64, 1>(
            &shape,
            &proof,
            witness,
            [1],
            EF::from_u64(13),
        );
        assert!(decide_linearized_accumulator(&acc));

        acc.public_instance.linear_claim = {
            let mut claim = acc.public_instance.linear_claim.clone();
            claim.add_constraint(EvaluationsList::new(vec![EF::ZERO; 8]), EF::ONE);
            claim
        };
        assert!(!decide_linearized_accumulator(&acc));
    }

    #[test]
    fn pair_accumulation_preserves_batched_linear_claim() {
        let (shape, instance_left) = make_square_instance(9);
        let (_, instance_right) = make_square_instance(16);

        let prover = R1CSProver::new();
        let proof_left = prove_instance(&instance_left);
        let proof_right = prove_instance(&instance_right);
        let acc_left = initialize_accumulator_from_spartan::<F, EF, u64, 1>(
            &shape,
            &proof_left,
            prover.prepare_witness(&instance_left),
            [1],
            EF::from_u64(3),
        );
        let acc_right = initialize_accumulator_from_spartan::<F, EF, u64, 1>(
            &shape,
            &proof_right,
            prover.prepare_witness(&instance_right),
            [2],
            EF::from_u64(3),
        );
        assert!(decide_linearized_accumulator(&acc_left));
        assert!(decide_linearized_accumulator(&acc_right));

        let combined = accumulate_pair(&acc_left, &acc_right, F::from_u64(7), [3]);
        let (weights, expected) = combined.public_instance.linear_claim.iter().next().unwrap();
        let actual = combined
            .witness
            .poly
            .as_slice()
            .iter()
            .zip(weights.as_slice().iter())
            .fold(EF::ZERO, |acc, (&poly_eval, &weight)| {
                acc + EF::from(poly_eval) * weight
            });
        assert_eq!(
            actual, *expected,
            "combined accumulator does not satisfy its linear claim"
        );
    }

    #[test]
    fn whir_proves_and_verifies_linearized_accumulator_claim() {
        let (shape, instance) = make_square_instance(9);
        let spartan_proof = prove_instance(&instance);
        let witness_poly = R1CSProver::new().prepare_witness(&instance);
        let linear_claim =
            linearized_statement_from_spartan_proof(&shape, &spartan_proof, EF::from_u64(5));

        let (whir_config, whir_params) = make_whir_config();
        let mut statement =
            whir_config.initial_statement_with_linear(witness_poly.clone(), linear_claim);
        let verifier_claim = statement.normalize_claim();

        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut whir_proof = WhirProof::<F, EF, F, 8>::from_protocol_parameters(
            &whir_params,
            witness_poly.num_variables(),
        );

        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(9));
        let mut prover_challenger = Challenger::new(perm.clone());
        let mut domainsep = DomainSeparator::<EF, F>::new(vec![]);
        domainsep.commit_statement::<_, _, _, 8>(&whir_config);
        domainsep.add_whir_proof::<_, _, _, 8>(&whir_config);
        domainsep.observe_domain_separator(&mut prover_challenger);

        let commitment = CommitmentWriter::new(&whir_config)
            .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &dft,
                &mut whir_proof,
                &mut prover_challenger,
                &mut statement,
            )
            .unwrap();
        WhirProver(&whir_config)
            .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &dft,
                &mut whir_proof,
                &mut prover_challenger,
                &statement,
                commitment,
            )
            .unwrap();

        let mut verifier_challenger = Challenger::new(perm);
        let mut verifier_domainsep = DomainSeparator::<EF, F>::new(vec![]);
        verifier_domainsep.commit_statement::<_, _, _, 8>(&whir_config);
        verifier_domainsep.add_whir_proof::<_, _, _, 8>(&whir_config);
        verifier_domainsep.observe_domain_separator(&mut verifier_challenger);
        let parsed_commitment = CommitmentReader::new(&whir_config)
            .parse_commitment::<F, 8>(&whir_proof, &mut verifier_challenger);

        let result = WhirVerifier::new(&whir_config)
            .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                &whir_proof,
                &mut verifier_challenger,
                &parsed_commitment,
                verifier_claim,
            );
        assert!(
            result.is_ok(),
            "WHIR failed on linearized accumulator claim"
        );
    }
}
