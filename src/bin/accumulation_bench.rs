use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::Path,
    time::Instant,
};

use clap::Parser;
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
        r1cs_prover::{R1CSProof, R1CSProver, R1CSVerifier},
    },
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::InitialClaim,
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

#[derive(Parser, Debug)]
#[command(author, version, about = "Configurable accumulation benchmark runner")]
struct Args {
    #[arg(long, default_value = "8,10", help = "Comma-separated log2 sizes")]
    sizes: String,

    #[arg(long, default_value = "2,4", help = "Comma-separated claim counts")]
    claims: String,

    #[arg(
        long,
        default_value_t = 10,
        help = "Number of timed repetitions per case"
    )]
    repeats: usize,

    #[arg(
        long,
        default_value_t = 2,
        help = "Shift queries for folded accumulation"
    )]
    shift_queries: usize,

    #[arg(long, default_value_t = 2, help = "WHIR folding factor")]
    folding_factor: usize,

    #[arg(
        long,
        help = "Optional folding schedule. Use 'k' for constant folding or 'k0,k' for a different first-round folding factor. Overrides --folding-factor when set"
    )]
    folding_schedule: Option<String>,

    #[arg(long, default_value_t = 1, help = "WHIR starting log inverse rate")]
    starting_log_inv_rate: usize,

    #[arg(long, default_value_t = 1, help = "Initial RS domain reduction factor")]
    rs_domain_initial_reduction_factor: usize,

    #[arg(long, default_value_t = 100, help = "Security level in bits")]
    security_level: usize,

    #[arg(
        long,
        default_value = "output/benchmarks/accumulation/custom_metrics.csv"
    )]
    out: String,
}

#[derive(Clone)]
struct ClaimMaterial {
    shape: whir_p3::spartan::r1cs::R1CSShape<F>,
    instance: R1CSInstance<F>,
    spartan_proof: R1CSProof<F, EF>,
    witness_poly: whir_p3::poly::evals::EvaluationsList<F>,
}

fn parse_csv_usize(input: &str) -> Vec<usize> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("invalid usize in CSV list"))
        .collect()
}

fn parse_folding_factor(args: &Args) -> FoldingFactor {
    match &args.folding_schedule {
        None => FoldingFactor::Constant(args.folding_factor),
        Some(schedule) => {
            let values = parse_csv_usize(schedule);
            match values.as_slice() {
                [factor] => FoldingFactor::Constant(*factor),
                [first_round, later_round] => {
                    FoldingFactor::ConstantFromSecondRound(*first_round, *later_round)
                }
                _ => panic!("invalid --folding-schedule; expected 'k' or 'k0,k', got {schedule}"),
            }
        }
    }
}

fn make_whir_config(
    num_variables: usize,
    args: &Args,
) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
    let mut rng = SmallRng::seed_from_u64(42);
    let perm = Perm::new_from_rng_128(&mut rng);
    let params = ProtocolParameters {
        security_level: args.security_level,
        pow_bits: 0,
        rs_domain_initial_reduction_factor: args.rs_domain_initial_reduction_factor,
        folding_factor: parse_folding_factor(args),
        merkle_hash: MyHash::new(perm.clone()),
        merkle_compress: MyCompress::new(perm),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: args.starting_log_inv_rate,
    };
    WhirConfig::new(num_variables, params)
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
    args: &Args,
) -> Vec<(WhirProof<F, EF, F, 8>, InitialClaim<F, EF>)> {
    let config = make_whir_config(material.witness_poly.num_variables(), args);
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
    proofs: &[(WhirProof<F, EF, F, 8>, InitialClaim<F, EF>)],
    args: &Args,
) {
    let config = make_whir_config(material.witness_poly.num_variables(), args);
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

fn average_ms<FN: FnMut()>(repeats: usize, mut f: FN) -> f64 {
    let start = Instant::now();
    for _ in 0..repeats {
        f();
    }
    start.elapsed().as_secs_f64() * 1000.0 / repeats as f64
}

fn main() {
    let args = Args::parse();
    let sizes = parse_csv_usize(&args.sizes);
    let claims = parse_csv_usize(&args.claims);
    let out_path = Path::new(&args.out);
    if let Some(parent) = out_path.parent() {
        create_dir_all(parent).expect("create output directory");
    }
    let mut out = File::create(out_path).expect("create output csv");
    writeln!(
        out,
        "log_size,claims,folding_schedule,starting_log_inv_rate,rs_domain_initial_reduction_factor,regular_prove_ms,regular_verify_ms,folded_prove_ms,folded_verify_ms"
    )
    .unwrap();

    let folding_schedule_label = match &args.folding_schedule {
        Some(schedule) => schedule.clone(),
        None => args.folding_factor.to_string(),
    };

    for size_log2 in sizes {
        let material = prepare_material(size_log2);
        println!("size=2^{size_log2}");
        for &num_claims in &claims {
            assert!(num_claims.is_power_of_two(), "claims must be power of two");
            let regular_prove_ms = average_ms(args.repeats, || {
                let _ = prove_regular_pipeline(&material, num_claims, &args);
            });

            let regular_proofs = prove_regular_pipeline(&material, num_claims, &args);
            let regular_verify_ms = average_ms(args.repeats, || {
                verify_regular_pipeline(&material, &regular_proofs, &args);
            });

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
            let accum_config = make_whir_config(union_num_vars, &args);
            let accum_domainsep = make_domain_sep(&accum_config);
            let dft = Radix2DFTSmallBatch::<F>::default();

            let folded_prove_ms = average_ms(args.repeats, || {
                let mut challenger = seed_challenger(1000 + num_claims as u64, &accum_domainsep);
                let _ = LinearizedAccumulationProver::new(&accum_config)
                    .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                        &dft,
                        &mut challenger,
                        &accumulators,
                        args.shift_queries,
                    )
                    .unwrap();
            });

            let mut prover_challenger = seed_challenger(1000 + num_claims as u64, &accum_domainsep);
            let (_output, accumulation_proof) = LinearizedAccumulationProver::new(&accum_config)
                .accumulate::<_, F, <F as Field>::Packing, _, 8>(
                    &dft,
                    &mut prover_challenger,
                    &accumulators,
                    args.shift_queries,
                )
                .unwrap();
            let public_inputs = accumulators
                .iter()
                .map(|acc| acc.public_instance.clone())
                .collect::<Vec<_>>();

            let folded_verify_ms = average_ms(args.repeats, || {
                let mut challenger = seed_challenger(1000 + num_claims as u64, &accum_domainsep);
                LinearizedAccumulationVerifier::new(&accum_config)
                    .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
                        &mut challenger,
                        &public_inputs,
                        &accumulation_proof,
                    )
                    .unwrap();
            });

            println!(
                "  k={num_claims}: regular_prove={regular_prove_ms:.3} ms, regular_verify={regular_verify_ms:.3} ms, folded_prove={folded_prove_ms:.3} ms, folded_verify={folded_verify_ms:.3} ms"
            );
            writeln!(
                out,
                "{size_log2},{num_claims},{},{},{},{regular_prove_ms:.6},{regular_verify_ms:.6},{folded_prove_ms:.6},{folded_verify_ms:.6}",
                folding_schedule_label,
                args.starting_log_inv_rate,
                args.rs_domain_initial_reduction_factor,
            )
            .unwrap();
        }
    }

    println!("wrote results to {}", out_path.display());
}
