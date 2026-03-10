use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{rngs::SmallRng, SeedableRng};
use whir_p3::{
    accumulation::{
        linearized::{
            initialize_accumulator_from_spartan, linearized_statement_from_spartan_proof,
        },
        scheme::{LinearizedAccumulationProver, LinearizedAccumulationVerifier},
    },
    fiat_shamir::domain_separator::DomainSeparator,
    parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
    spartan::{
        r1cs::R1CSInstance,
        r1cs_prover::{R1CSProver, R1CSVerifier},
    },
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
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

#[derive(Clone)]
struct ClaimMaterial {
    shape: whir_p3::spartan::r1cs::R1CSShape<F>,
    instance: R1CSInstance<F>,
    spartan_proof: whir_p3::spartan::r1cs_prover::R1CSProof<F, EF>,
    witness_poly: whir_p3::poly::evals::EvaluationsList<F>,
}

fn make_whir_config(
    num_variables: usize,
) -> (
    WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
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
    (WhirConfig::new(num_variables, params.clone()), params)
}

fn make_domain_sep(
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
) -> DomainSeparator<EF, F> {
    let mut domainsep = DomainSeparator::<EF, F>::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(config);
    domainsep.add_whir_proof::<_, _, _, 8>(config);
    domainsep
}

fn seed_challenger(seed: u64, domainsep: &DomainSeparator<EF, F>) -> MyChallenger {
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(seed));
    let mut challenger = MyChallenger::new(perm);
    domainsep.observe_domain_separator(&mut challenger);
    challenger
}

fn prepare_material(size_log2: usize) -> ClaimMaterial {
    let num_cons = 1 << size_log2;
    let num_vars = 1 << size_log2;
    let num_inputs = 8;
    let mut rng = SmallRng::seed_from_u64(5);
    let (shape, instance) =
        R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);

    let spartan_prover = R1CSProver::new();
    let witness_poly = spartan_prover.prepare_witness(&instance);
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(9));
    let mut challenger = MyChallenger::new(perm);
    let spartan_proof = spartan_prover.prove::<EF, _>(&instance, &mut challenger);

    ClaimMaterial {
        shape,
        instance,
        spartan_proof,
        witness_poly,
    }
}

fn prove_regular_pipeline(
    material: &ClaimMaterial,
    num_claims: usize,
) -> Vec<(
    WhirProof<F, EF, F, 8>,
    whir_p3::whir::constraints::statement::InitialClaim<F, EF>,
)> {
    let (config, _whir_params) = make_whir_config(material.witness_poly.num_variables());
    let dft = Radix2DFTSmallBatch::<F>::default();
    let domainsep = make_domain_sep(&config);

    (0..num_claims)
        .map(|i| {
            let linear_claim = linearized_statement_from_spartan_proof(
                &material.shape,
                &material.spartan_proof,
                EF::from(F::from_u64((i + 3) as u64)),
            );
            let mut statement =
                config.initial_statement_with_linear(material.witness_poly.clone(), linear_claim);
            let verifier_claim = statement.normalize_claim();

            let mut proof = WhirProof::<F, EF, F, 8>::from_whir_config(&config);
            let mut challenger = seed_challenger(100 + i as u64, &domainsep);
            let commitment = CommitmentWriter::new(&config)
                .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                    &dft,
                    &mut proof,
                    &mut challenger,
                    &mut statement,
                )
                .unwrap();
            WhirProver(&config)
                .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, 8>(
                    &dft,
                    &mut proof,
                    &mut challenger,
                    &statement,
                    commitment,
                )
                .unwrap();
            (proof, verifier_claim)
        })
        .collect()
}

fn verify_regular_pipeline(
    material: &ClaimMaterial,
    proofs: &[(
        WhirProof<F, EF, F, 8>,
        whir_p3::whir::constraints::statement::InitialClaim<F, EF>,
    )],
) {
    let (config, _) = make_whir_config(material.witness_poly.num_variables());
    let domainsep = make_domain_sep(&config);
    let spartan_verifier = R1CSVerifier::new();

    for (i, (proof, claim)) in proofs.iter().enumerate() {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(9));
        let mut spartan_challenger = MyChallenger::new(perm);
        spartan_verifier
            .verify::<EF, _>(
                &material.shape,
                material.instance.input(),
                &material.spartan_proof,
                &mut spartan_challenger,
            )
            .unwrap();

        let mut challenger = seed_challenger(100 + i as u64, &domainsep);
        let parsed =
            CommitmentReader::new(&config).parse_commitment::<F, 8>(proof, &mut challenger);
        WhirVerifier::new(&config)
            .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                proof,
                &mut challenger,
                &parsed,
                claim.clone(),
            )
            .unwrap();
    }
}

fn bench_regular_vs_accumulated(c: &mut Criterion) {
    let mut group = c.benchmark_group("spartan_whir_vs_warp");
    group.sample_size(10);

    for size_log2 in [8usize, 10usize] {
        let material = prepare_material(size_log2);
        let dft = Radix2DFTSmallBatch::<F>::default();

        for &num_claims in &[2usize, 4usize] {
            group.bench_with_input(
                BenchmarkId::new("regular_prove", format!("2^{size_log2}/k={num_claims}")),
                &num_claims,
                |b, &k| {
                    b.iter(|| {
                        let _ = prove_regular_pipeline(&material, k);
                    });
                },
            );

            let regular_proofs = prove_regular_pipeline(&material, num_claims);
            group.bench_with_input(
                BenchmarkId::new("regular_verify", format!("2^{size_log2}/k={num_claims}")),
                &num_claims,
                |b, _| {
                    b.iter(|| verify_regular_pipeline(&material, &regular_proofs));
                },
            );

            let accumulators = (0..num_claims)
                .map(|i| {
                    initialize_accumulator_from_spartan::<F, EF, F, 8>(
                        &material.shape,
                        &material.spartan_proof,
                        material.witness_poly.clone(),
                        [F::from_u64(i as u64); 8],
                        EF::from(F::from_u64((i + 3) as u64)),
                    )
                })
                .collect::<Vec<_>>();

            let union_num_vars =
                material.witness_poly.num_variables() + num_claims.trailing_zeros() as usize;
            let (accum_config, _) = make_whir_config(union_num_vars);
            let accum_domainsep = make_domain_sep(&accum_config);

            group.bench_with_input(
                BenchmarkId::new("accumulated_prove", format!("2^{size_log2}/k={num_claims}")),
                &num_claims,
                |b, _| {
                    b.iter(|| {
                        let mut challenger =
                            seed_challenger(1000 + num_claims as u64, &accum_domainsep);
                        let _ = LinearizedAccumulationProver::new(&accum_config)
                            .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                                &dft,
                                &mut challenger,
                                &accumulators,
                                2,
                            )
                            .unwrap();
                    });
                },
            );

            let mut prover_challenger = seed_challenger(1000 + num_claims as u64, &accum_domainsep);
            let (_output, accumulation_proof) = LinearizedAccumulationProver::new(&accum_config)
                .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                    &dft,
                    &mut prover_challenger,
                    &accumulators,
                    2,
                )
                .unwrap();
            let public_inputs = accumulators
                .iter()
                .map(|acc| acc.public_instance.clone())
                .collect::<Vec<_>>();

            group.bench_with_input(
                BenchmarkId::new(
                    "accumulated_verify",
                    format!("2^{size_log2}/k={num_claims}"),
                ),
                &num_claims,
                |b, _| {
                    b.iter(|| {
                        let mut challenger =
                            seed_challenger(1000 + num_claims as u64, &accum_domainsep);
                        LinearizedAccumulationVerifier::new(&accum_config)
                            .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                                &mut challenger,
                                &public_inputs,
                                &accumulation_proof,
                            )
                            .unwrap();
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_regular_vs_accumulated);
criterion_main!(benches);
