use alloc::vec;
use alloc::vec::Vec;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::fiat_shamir::domain_separator::DomainSeparator;
use crate::parameters::{FoldingFactor, ProtocolParameters, errors::SecurityAssumption};
use crate::poly::evals::EvaluationsList;
use crate::spartan::r1cs::{R1CSInstance, R1CSShape, SparseMatEntry};
use crate::spartan::r1cs_prover::{R1CSProver, R1CSVerifier};
use crate::whir::{
    committer::{reader::CommitmentReader, writer::CommitmentWriter},
    parameters::{SumcheckStrategy, WhirConfig},
    proof::WhirProof,
    prover::Prover as WhirProver,
    verifier::Verifier as WhirVerifier,
};

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

#[test]
fn test_r1cs_whir_integration() {
    // 1. Setup R1CS Instance (w^2 = y)
    // --------------------------------
    let num_cons = 4usize;
    let num_vars = 4usize;
    let num_inputs = 1usize;

    // Constraint: w[0] * w[0] - w[1] = 0
    let a_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
    let b_entries = vec![SparseMatEntry::new(0, 0, F::ONE)];
    let c_entries = vec![SparseMatEntry::new(0, 1, F::ONE)];

    let shape = R1CSShape::new(
        num_cons, num_vars, num_inputs, a_entries, b_entries, c_entries,
    );

    // Witness: w[0] = 3, w[1] = 9
    let mut witness = vec![F::ZERO; num_vars];
    witness[0] = F::from_u64(3);
    witness[1] = F::from_u64(9);
    let input = vec![F::ZERO]; // Dummy public input

    let instance = R1CSInstance::new(shape.clone(), input.clone(), witness.clone());

    // 2. Setup WHIR Config
    // --------------------
    let mut rng = SmallRng::seed_from_u64(42);
    let perm = Perm::new_from_rng_128(&mut rng);
    let merkle_hash = MyHash::new(perm.clone());
    let merkle_compress = MyCompress::new(perm.clone());

    let whir_params = ProtocolParameters {
        security_level: 100,
        pow_bits: 10,
        rs_domain_initial_reduction_factor: 1,
        folding_factor: FoldingFactor::Constant(2),
        merkle_hash,
        merkle_compress,
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
    };

    let r1cs_prover = R1CSProver::new();
    let witness_evals = r1cs_prover.prepare_witness(&instance);
    let witness_vec = witness_evals.as_slice().to_vec();

    let num_vars_z = 3;
    let witness_poly = EvaluationsList::new(witness_vec.clone());

    let whir_config =
        WhirConfig::<EF, F, MyHash, MyCompress, MyChallenger>::new(num_vars_z, whir_params.clone());

    // 3. Run Spartan Prover (Phase 1: Sumcheck)
    // -----------------------------------------
    // Create challenger for Spartan
    let mut rng_chal = SmallRng::seed_from_u64(123);
    let perm_chal = Perm::new_from_rng_128(&mut rng_chal);
    let mut spartan_challenger = MyChallenger::new(perm_chal.clone());

    let r1cs_proof = r1cs_prover.prove::<EF, _>(&instance, &mut spartan_challenger);

    // 4. WHIR Commitment to Witness (Phase 2)
    // ---------------------------------------
    let committer = CommitmentWriter::new(&whir_config);
    let dft = Radix2DFTSmallBatch::<F>::default();

    let mut whir_proof =
        WhirProof::<F, EF, F, 8>::from_protocol_parameters(&whir_params, num_vars_z);

    let mut whir_challenger = MyChallenger::new(perm_chal.clone());

    // Domain separator for WHIR
    let mut domainsep = DomainSeparator::<EF, F>::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_config);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_config);
    domainsep.observe_domain_separator(&mut whir_challenger);

    let mut statement = whir_config.initial_statement(witness_poly, SumcheckStrategy::Classic);

    // 5. Calculate query point from Spartan ry and add to statement
    // ------------------------------------------------------------
    let ry = &r1cs_proof.eval_claims.ry;
    let mut ry_padded = ry.clone();
    while ry_padded.len() < num_vars_z {
        ry_padded.push(F::ZERO);
    }

    let mut ry_ef: Vec<EF> = ry_padded.iter().map(|&x| EF::from(x)).collect();
    ry_ef.reverse(); // Match WHIR endianness (MSB first)

    let query_point = crate::poly::multilinear::MultilinearPoint::new(ry_ef.clone());
    let _claimed_val_z = statement.evaluate(&query_point);

    // Normalize statement before commit adds OOD samples
    let verifier_statement = statement.normalize();

    // 4. WHIR Commitment to Witness (Phase 2)
    // ---------------------------------------
    let witness_commitment = committer
        .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
            &dft,
            &mut whir_proof,
            &mut whir_challenger,
            &mut statement,
        )
        .expect("Commitment failed");

    // 5. WHIR Prover
    // --------------------------------
    let whir_prover_struct = WhirProver(&whir_config);
    whir_prover_struct
        .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
            &dft,
            &mut whir_proof,
            &mut whir_challenger,
            &statement,
            witness_commitment,
        )
        .expect("WHIR proving failed");

    // 6. Verification
    // ---------------

    // Verify Spartan Proof
    let verifier = R1CSVerifier::new();
    let mut spartan_verifier_challenger = MyChallenger::new(perm_chal.clone()); // Same seed as prover
    let r1cs_result = verifier.verify::<EF, _>(
        &shape,
        &input,
        &r1cs_proof,
        &mut spartan_verifier_challenger,
    );
    assert!(
        r1cs_result.is_ok(),
        "Spartan verification failed: {:?}",
        r1cs_result.err()
    );

    // Verify WHIR Proof
    let commitment_reader = CommitmentReader::new(&whir_config);
    let whir_verifier = WhirVerifier::new(&whir_config);
    let mut whir_verifier_challenger = MyChallenger::new(perm_chal.clone()); // Same seed

    // Replay domain separator
    let mut domainsep_v = DomainSeparator::<EF, F>::new(vec![]);
    domainsep_v.commit_statement::<_, _, _, 8>(&whir_config);
    domainsep_v.add_whir_proof::<_, _, _, 8>(&whir_config);
    domainsep_v.observe_domain_separator(&mut whir_verifier_challenger);

    let parsed_commitment =
        commitment_reader.parse_commitment::<F, 8>(&whir_proof, &mut whir_verifier_challenger);

    let whir_result = whir_verifier.verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
        &whir_proof,
        &mut whir_verifier_challenger,
        &parsed_commitment,
        verifier_statement,
    );

    assert!(
        whir_result.is_ok(),
        "WHIR verification failed: {:?}",
        whir_result.err()
    );
}
