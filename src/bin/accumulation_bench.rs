use std::{
    fs::{create_dir_all, File},
    io::Write,
    mem::size_of,
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
        accumulator::{Accumulator, AccumulatorInstance},
        linearized::{
            initialize_accumulator_from_spartan, linearized_statement_from_spartan_proof,
        },
        proof::{AccumulationProof, AccumulationTranscript},
        scheme::{LinearizedAccumulationProver, LinearizedAccumulationVerifier},
    },
    fiat_shamir::domain_separator::DomainSeparator,
    parameters::{errors::SecurityAssumption, FoldingFactor, ProtocolParameters},
    poly::evals::EvaluationsList,
    spartan::{
        r1cs::{R1CSInstance, R1CSShape},
        r1cs_prover::{R1CSProof, R1CSProver, R1CSVerifier},
    },
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{InitialClaim, LinearStatement},
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

const DIGEST_ELEMS: usize = 8;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Normalized accumulation benchmark runner with size and memory proxies"
)]
struct Args {
    #[arg(
        long,
        default_value = "8,10",
        help = "Comma-separated witness log2 sizes"
    )]
    sizes: String,

    #[arg(
        long,
        default_value = "2,4",
        help = "Comma-separated claim counts (batch sizes). This is the number of claims being aggregated, not the WHIR folding factor"
    )]
    claims: String,

    #[arg(
        long,
        default_value_t = 10,
        help = "Number of timed repetitions per case"
    )]
    repeats: usize,

    #[arg(long, default_value_t = 2, help = "Shift queries for the WARP backend")]
    shift_queries: usize,

    #[arg(long, default_value_t = 2, help = "WHIR folding factor")]
    folding_factor: usize,

    #[arg(
        long,
        help = "Optional folding schedule. Use 'k' for constant folding or 'k0,k' for a different first-round folding factor. Overrides --folding-factor when set"
    )]
    folding_schedule: Option<String>,

    #[arg(
        long,
        default_value_t = 1,
        help = "Default WHIR starting log inverse rate when --starting-log-inv-rates is not set"
    )]
    starting_log_inv_rate: usize,

    #[arg(
        long,
        help = "Comma-separated sweep for WHIR starting log inverse rate"
    )]
    starting_log_inv_rates: Option<String>,

    #[arg(
        long,
        default_value_t = 1,
        help = "Default initial RS domain reduction factor when --initial-rs-reductions is not set"
    )]
    rs_domain_initial_reduction_factor: usize,

    #[arg(
        long,
        help = "Comma-separated sweep for the initial RS domain reduction factor"
    )]
    initial_rs_reductions: Option<String>,

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
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    spartan_proof: R1CSProof<F, EF>,
    witness_poly: EvaluationsList<F>,
}

#[derive(Clone)]
struct PreparedCase {
    material: ClaimMaterial,
    regular_linear_claims: Vec<LinearStatement<F, EF>>,
    raw_fold_accumulators: Vec<Accumulator<F, EF, F, DIGEST_ELEMS>>,
    raw_fold_public_inputs: Vec<AccumulatorInstance<F, EF, F, DIGEST_ELEMS>>,
    witness_bytes: usize,
    num_claims: usize,
}

#[derive(Clone, Copy)]
struct SweepConfig {
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
}

#[derive(Clone, Copy)]
struct TimingMetrics {
    prove_ms: f64,
    verify_ms: f64,
}

#[derive(Clone, Copy)]
struct ArtifactMetrics {
    proof_bytes: usize,
    transcript_bytes: usize,
    explicit_poly_bytes: usize,
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

fn parse_sweep_configs(args: &Args) -> Vec<SweepConfig> {
    let starting_rates = args
        .starting_log_inv_rates
        .as_deref()
        .map(parse_csv_usize)
        .unwrap_or_else(|| vec![args.starting_log_inv_rate]);
    let initial_reductions = args
        .initial_rs_reductions
        .as_deref()
        .map(parse_csv_usize)
        .unwrap_or_else(|| vec![args.rs_domain_initial_reduction_factor]);

    let mut out = Vec::new();
    for &starting_log_inv_rate in &starting_rates {
        for &rs_domain_initial_reduction_factor in &initial_reductions {
            out.push(SweepConfig {
                starting_log_inv_rate,
                rs_domain_initial_reduction_factor,
            });
        }
    }
    out
}

fn make_whir_config(
    num_variables: usize,
    args: &Args,
    sweep: SweepConfig,
) -> WhirConfig<EF, F, MyHash, MyCompress, MyChallenger> {
    let mut rng = SmallRng::seed_from_u64(42);
    let perm = Perm::new_from_rng_128(&mut rng);
    let params = ProtocolParameters {
        security_level: args.security_level,
        pow_bits: 0,
        rs_domain_initial_reduction_factor: sweep.rs_domain_initial_reduction_factor,
        folding_factor: parse_folding_factor(args),
        merkle_hash: MyHash::new(perm.clone()),
        merkle_compress: MyCompress::new(perm),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: sweep.starting_log_inv_rate,
    };
    WhirConfig::new(num_variables, params)
}

fn make_domain_sep(
    config: &WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
) -> DomainSeparator<EF, F> {
    let mut domainsep = DomainSeparator::<EF, F>::new(vec![]);
    domainsep.commit_statement::<_, _, _, DIGEST_ELEMS>(config);
    domainsep.add_whir_proof::<_, _, _, DIGEST_ELEMS>(config);
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

fn witness_bytes(poly: &EvaluationsList<F>) -> usize {
    poly.as_slice().len() * size_of::<F>()
}

fn prepare_case(material: &ClaimMaterial, num_claims: usize) -> PreparedCase {
    let regular_linear_claims = (0..num_claims)
        .map(|i| {
            linearized_statement_from_spartan_proof(
                &material.shape,
                &material.spartan_proof,
                EF::from(F::from_u64((i + 3) as u64)),
            )
        })
        .collect::<Vec<_>>();

    let raw_fold_accumulators = (0..num_claims)
        .map(|i| {
            initialize_accumulator_from_spartan::<F, EF, F, DIGEST_ELEMS>(
                &material.shape,
                &material.spartan_proof,
                material.witness_poly.clone(),
                [F::from_u64(i as u64); DIGEST_ELEMS],
                EF::from(F::from_u64((i + 3) as u64)),
            )
        })
        .collect::<Vec<_>>();
    let raw_fold_public_inputs = raw_fold_accumulators
        .iter()
        .map(|acc| acc.public_instance.clone())
        .collect::<Vec<_>>();

    PreparedCase {
        material: material.clone(),
        regular_linear_claims,
        raw_fold_accumulators,
        raw_fold_public_inputs,
        witness_bytes: witness_bytes(&material.witness_poly),
        num_claims,
    }
}

fn prove_regular_pipeline(
    case: &PreparedCase,
    args: &Args,
    sweep: SweepConfig,
) -> Vec<(WhirProof<F, EF, F, DIGEST_ELEMS>, InitialClaim<F, EF>)> {
    let config = make_whir_config(case.material.witness_poly.num_variables(), args, sweep);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let domainsep = make_domain_sep(&config);

    case.regular_linear_claims
        .iter()
        .enumerate()
        .map(|(i, linear_claim)| {
            let mut statement = config.initial_statement_with_linear(
                case.material.witness_poly.clone(),
                linear_claim.clone(),
            );
            let verifier_claim = statement.normalize_claim();
            let mut proof = WhirProof::<F, EF, F, DIGEST_ELEMS>::from_whir_config(&config);
            let mut challenger = seed_challenger(100 + i as u64, &domainsep);
            let commitment = CommitmentWriter::new(&config)
                .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST_ELEMS>(
                    &dft,
                    &mut proof,
                    &mut challenger,
                    &mut statement,
                )
                .unwrap();
            WhirProver(&config)
                .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST_ELEMS>(
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
    case: &PreparedCase,
    proofs: &[(WhirProof<F, EF, F, DIGEST_ELEMS>, InitialClaim<F, EF>)],
    args: &Args,
    sweep: SweepConfig,
) {
    let config = make_whir_config(case.material.witness_poly.num_variables(), args, sweep);
    let domainsep = make_domain_sep(&config);
    let spartan_verifier = R1CSVerifier::new();

    for (i, (proof, claim)) in proofs.iter().enumerate() {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(9));
        let mut spartan_challenger = MyChallenger::new(perm);
        spartan_verifier
            .verify::<EF, _>(
                &case.material.shape,
                case.material.instance.input(),
                &case.material.spartan_proof,
                &mut spartan_challenger,
            )
            .unwrap();

        let mut challenger = seed_challenger(100 + i as u64, &domainsep);
        let parsed = CommitmentReader::new(&config)
            .parse_commitment::<F, DIGEST_ELEMS>(proof, &mut challenger);
        WhirVerifier::new(&config)
            .verify_with_initial_claim::<
                <F as Field>::Packing,
                F,
                <F as Field>::Packing,
                DIGEST_ELEMS,
            >(proof, &mut challenger, &parsed, claim.clone())
            .unwrap();
    }
}

fn prove_raw_fold_pipeline(
    case: &PreparedCase,
    args: &Args,
    sweep: SweepConfig,
) -> (
    Accumulator<F, EF, F, DIGEST_ELEMS>,
    AccumulationProof<F, EF, F, DIGEST_ELEMS>,
) {
    let union_num_vars =
        case.material.witness_poly.num_variables() + case.num_claims.trailing_zeros() as usize;
    let config = make_whir_config(union_num_vars, args, sweep);
    let domainsep = make_domain_sep(&config);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let mut challenger = seed_challenger(1000 + case.num_claims as u64, &domainsep);
    LinearizedAccumulationProver::new(&config)
        .accumulate::<_, F, <F as Field>::Packing, _, DIGEST_ELEMS>(
            &dft,
            &mut challenger,
            &case.raw_fold_accumulators,
            args.shift_queries,
        )
        .unwrap()
}

fn verify_raw_fold_pipeline(
    case: &PreparedCase,
    args: &Args,
    sweep: SweepConfig,
    proof: &AccumulationProof<F, EF, F, DIGEST_ELEMS>,
) {
    let union_num_vars =
        case.material.witness_poly.num_variables() + case.num_claims.trailing_zeros() as usize;
    let config = make_whir_config(union_num_vars, args, sweep);
    let domainsep = make_domain_sep(&config);
    let mut challenger = seed_challenger(1000 + case.num_claims as u64, &domainsep);
    LinearizedAccumulationVerifier::new(&config)
        .verify::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST_ELEMS>(
            &mut challenger,
            &case.raw_fold_public_inputs,
            proof,
        )
        .unwrap();
}

fn average_ms<FN: FnMut()>(repeats: usize, mut f: FN) -> f64 {
    let start = Instant::now();
    for _ in 0..repeats {
        f();
    }
    start.elapsed().as_secs_f64() * 1000.0 / repeats as f64
}

fn accumulation_transcript_size_bytes(transcript: &AccumulationTranscript<F, EF>) -> usize {
    size_of::<F>()
        + transcript.ood_point.as_slice().len() * size_of::<EF>()
        + size_of::<EF>()
        + transcript.shift_query_indices.len() * size_of::<usize>()
        + transcript.shift_query_answers.len() * size_of::<EF>()
}

fn human_bytes(bytes: usize) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f >= MIB {
        format!("{:.2} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.2} KiB", bytes_f / KIB)
    } else {
        format!("{} B", bytes)
    }
}

fn measure_no_fold(
    case: &PreparedCase,
    args: &Args,
    sweep: SweepConfig,
) -> (TimingMetrics, ArtifactMetrics) {
    let prove_ms = average_ms(args.repeats, || {
        let _ = prove_regular_pipeline(case, args, sweep);
    });

    let proofs = prove_regular_pipeline(case, args, sweep);
    let verify_ms = average_ms(args.repeats, || {
        verify_regular_pipeline(case, &proofs, args, sweep);
    });

    let proof_bytes = proofs
        .iter()
        .map(|(proof, _)| {
            bincode::serialize(proof)
                .expect("serialize regular proof")
                .len()
        })
        .sum();

    (
        TimingMetrics {
            prove_ms,
            verify_ms,
        },
        ArtifactMetrics {
            proof_bytes,
            transcript_bytes: 0,
            explicit_poly_bytes: case.num_claims * case.witness_bytes,
        },
    )
}

fn measure_raw_fold(
    case: &PreparedCase,
    args: &Args,
    sweep: SweepConfig,
) -> (TimingMetrics, ArtifactMetrics) {
    let prove_ms = average_ms(args.repeats, || {
        let _ = prove_raw_fold_pipeline(case, args, sweep);
    });

    let (_folded, proof) = prove_raw_fold_pipeline(case, args, sweep);
    let verify_ms = average_ms(args.repeats, || {
        verify_raw_fold_pipeline(case, args, sweep, &proof);
    });

    let transcript_bytes = accumulation_transcript_size_bytes(&proof.transcript);
    let whir_bytes = bincode::serialize(&proof.whir_proof)
        .expect("serialize raw-fold WHIR proof")
        .len();

    (
        TimingMetrics {
            prove_ms,
            verify_ms,
        },
        ArtifactMetrics {
            proof_bytes: whir_bytes + transcript_bytes,
            transcript_bytes,
            explicit_poly_bytes: 2 * case.num_claims * case.witness_bytes,
        },
    )
}

fn measure_quasar_warp(case: &PreparedCase) -> (TimingMetrics, ArtifactMetrics) {
    let _ = case;
    (
        TimingMetrics {
            prove_ms: f64::NAN,
            verify_ms: f64::NAN,
        },
        ArtifactMetrics {
            proof_bytes: 0,
            transcript_bytes: 0,
            explicit_poly_bytes: 0,
        },
    )
}

fn main() {
    let args = Args::parse();
    let sizes = parse_csv_usize(&args.sizes);
    let claims = parse_csv_usize(&args.claims);
    let sweep_configs = parse_sweep_configs(&args);

    let out_path = Path::new(&args.out);
    if let Some(parent) = out_path.parent() {
        create_dir_all(parent).expect("create output directory");
    }
    let mut out = File::create(out_path).expect("create output csv");
    writeln!(
        out,
        "log_size,claims,folding_schedule,starting_log_inv_rate,rs_domain_initial_reduction_factor,shift_queries,no_fold_prove_ms,no_fold_verify_ms,no_fold_prove_ms_per_claim,no_fold_verify_ms_per_claim,no_fold_proof_bytes,no_fold_transcript_bytes,no_fold_explicit_poly_bytes,raw_fold_prove_ms,raw_fold_verify_ms,raw_fold_prove_ms_per_claim,raw_fold_verify_ms_per_claim,raw_fold_proof_bytes,raw_fold_transcript_bytes,raw_fold_explicit_poly_bytes,raw_fold_prove_speedup_vs_no_fold,raw_fold_verify_speedup_vs_no_fold,quasar_warp_prove_ms,quasar_warp_verify_ms,quasar_warp_prove_ms_per_claim,quasar_warp_verify_ms_per_claim,quasar_warp_proof_bytes,quasar_warp_transcript_bytes,quasar_warp_explicit_poly_bytes,quasar_warp_prove_speedup_vs_no_fold,quasar_warp_verify_speedup_vs_no_fold"
    )
    .unwrap();

    let folding_schedule_label = match &args.folding_schedule {
        Some(schedule) => schedule.clone(),
        None => args.folding_factor.to_string(),
    };

    println!(
        "Benchmark semantics: `claims` is batch size; `explicit_poly_bytes` is a deterministic memory proxy for materialized evaluation tables, not RSS."
    );

    for size_log2 in sizes {
        let material = prepare_material(size_log2);
        println!("size=2^{size_log2}");

        for &num_claims in &claims {
            assert!(num_claims.is_power_of_two(), "claims must be power of two");
            let case = prepare_case(&material, num_claims);

            for sweep in &sweep_configs {
                let (no_fold_time, no_fold_artifacts) = measure_no_fold(&case, &args, *sweep);
                let (raw_fold_time, raw_fold_artifacts) = measure_raw_fold(&case, &args, *sweep);
                let (quasar_time, quasar_artifacts) = measure_quasar_warp(&case);

                let claims_f64 = num_claims as f64;
                let raw_fold_prove_speedup = no_fold_time.prove_ms / raw_fold_time.prove_ms;
                let raw_fold_verify_speedup = no_fold_time.verify_ms / raw_fold_time.verify_ms;
                let quasar_prove_speedup = no_fold_time.prove_ms / quasar_time.prove_ms;
                let quasar_verify_speedup = no_fold_time.verify_ms / quasar_time.verify_ms;

                println!(
                    "  claims={num_claims}, rate=2^-{}, init_red={}: no_fold=({:.3},{:.3}) ms [{} proof, {} aux, {} poly] | raw_fold=({:.3},{:.3}) ms [{} proof, {} aux, {} poly] | quasar_warp=(unavailable on this branch)",
                    sweep.starting_log_inv_rate,
                    sweep.rs_domain_initial_reduction_factor,
                    no_fold_time.prove_ms,
                    no_fold_time.verify_ms,
                    human_bytes(no_fold_artifacts.proof_bytes),
                    human_bytes(no_fold_artifacts.transcript_bytes),
                    human_bytes(no_fold_artifacts.explicit_poly_bytes),
                    raw_fold_time.prove_ms,
                    raw_fold_time.verify_ms,
                    human_bytes(raw_fold_artifacts.proof_bytes),
                    human_bytes(raw_fold_artifacts.transcript_bytes),
                    human_bytes(raw_fold_artifacts.explicit_poly_bytes),
                );

                writeln!(
                    out,
                    "{size_log2},{num_claims},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{},{},{},{:.6},{:.6},{:.6},{:.6},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{},{:.6},{:.6}",
                    folding_schedule_label,
                    sweep.starting_log_inv_rate,
                    sweep.rs_domain_initial_reduction_factor,
                    args.shift_queries,
                    no_fold_time.prove_ms,
                    no_fold_time.verify_ms,
                    no_fold_time.prove_ms / claims_f64,
                    no_fold_time.verify_ms / claims_f64,
                    no_fold_artifacts.proof_bytes,
                    no_fold_artifacts.transcript_bytes,
                    no_fold_artifacts.explicit_poly_bytes,
                    raw_fold_time.prove_ms,
                    raw_fold_time.verify_ms,
                    raw_fold_time.prove_ms / claims_f64,
                    raw_fold_time.verify_ms / claims_f64,
                    raw_fold_artifacts.proof_bytes,
                    raw_fold_artifacts.transcript_bytes,
                    raw_fold_artifacts.explicit_poly_bytes,
                    raw_fold_prove_speedup,
                    raw_fold_verify_speedup,
                    quasar_time.prove_ms,
                    quasar_time.verify_ms,
                    quasar_time.prove_ms / claims_f64,
                    quasar_time.verify_ms / claims_f64,
                    quasar_artifacts.proof_bytes,
                    quasar_artifacts.transcript_bytes,
                    quasar_artifacts.explicit_poly_bytes,
                    quasar_prove_speedup,
                    quasar_verify_speedup,
                )
                .unwrap();
            }
        }
    }

    println!("wrote results to {}", out_path.display());
}
