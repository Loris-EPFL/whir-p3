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
        quasar::{FreshLinearInstance, QuasarFrontendProver, QuasarFrontendVerifier},
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

fn build_fresh_instances(
    material: &ClaimMaterial,
    num_claims: usize,
) -> Vec<FreshLinearInstance<F, EF>> {
    let rx = material.spartan_proof.eval_claims.rx.clone();
    let ry = material.spartan_proof.eval_claims.ry.clone();
    (0..num_claims)
        .map(|_| {
            FreshLinearInstance::from_shared_linearization_points(
                &material.shape,
                material.witness_poly.clone(),
                &rx,
                &ry,
                EF::from(F::from_u64(3)),
            )
        })
        .collect()
}

fn prove_raw_fold_pipeline(
    material: &ClaimMaterial,
    num_claims: usize,
    args: &Args,
) -> (
    whir_p3::accumulation::accumulator::Accumulator<F, EF, F, 8>,
    whir_p3::accumulation::proof::AccumulationProof<F, EF, F, 8>,
) {
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
    // Random LC keeps the same number of variables as the inputs
    let config = make_whir_config(material.witness_poly.num_variables(), args);
    let domainsep = make_domain_sep(&config);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let mut challenger = seed_challenger(1000 + num_claims as u64, &domainsep);
    LinearizedAccumulationProver::new(&config)
        .accumulate::<_, F, <F as Field>::Packing, _, 8>(
            &dft,
            &mut challenger,
            &accumulators,
            args.shift_queries,
        )
        .unwrap()
}

fn verify_raw_fold_pipeline(
    material: &ClaimMaterial,
    num_claims: usize,
    args: &Args,
    proof: &whir_p3::accumulation::proof::AccumulationProof<F, EF, F, 8>,
) {
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
    let public_inputs = accumulators
        .iter()
        .map(|acc| acc.public_instance.clone())
        .collect::<Vec<_>>();
    // Random LC keeps the same number of variables as the inputs
    let config = make_whir_config(material.witness_poly.num_variables(), args);
    let domainsep = make_domain_sep(&config);
    let mut challenger = seed_challenger(1000 + num_claims as u64, &domainsep);
    LinearizedAccumulationVerifier::new(&config)
        .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
            &mut challenger,
            &public_inputs,
            proof,
        )
        .unwrap();
}

fn prove_quasar_warp_pipeline(
    material: &ClaimMaterial,
    num_claims: usize,
    args: &Args,
) -> (
    whir_p3::accumulation::quasar::QuasarFrontendOutput<F, EF, F, 8>,
    whir_p3::accumulation::accumulator::Accumulator<F, EF, F, 8>,
    whir_p3::accumulation::proof::AccumulationProof<F, EF, F, 8>,
) {
    let fresh_instances = build_fresh_instances(material, num_claims);
    let quasar_config = make_whir_config(material.witness_poly.num_variables(), args);
    let quasar_domainsep = make_domain_sep(&quasar_config);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let mut quasar_challenger = seed_challenger(2000 + num_claims as u64, &quasar_domainsep);
    let squashed = QuasarFrontendProver::new(&quasar_config)
        .squash_and_prove::<_, F, <F as Field>::Packing, _, 8>(
            &dft,
            &mut quasar_challenger,
            &fresh_instances,
        )
        .unwrap();

    let running_acc = initialize_accumulator_from_spartan::<F, EF, F, 8>(
        &material.shape,
        &material.spartan_proof,
        material.witness_poly.clone(),
        [F::from_u64(999); 8],
        EF::from(F::from_u64(3)),
    );
    // Random LC keeps the same number of variables as the inputs
    let fold_config = make_whir_config(material.witness_poly.num_variables(), args);
    let fold_domainsep = make_domain_sep(&fold_config);
    let mut fold_challenger = seed_challenger(3000 + num_claims as u64, &fold_domainsep);
    let (folded, proof) = LinearizedAccumulationProver::new(&fold_config)
        .accumulate::<_, F, <F as Field>::Packing, _, 8>(
            &dft,
            &mut fold_challenger,
            &[running_acc.clone(), squashed.accumulator.clone()],
            args.shift_queries,
        )
        .unwrap();
    (squashed, folded, proof)
}

fn verify_quasar_warp_pipeline(
    material: &ClaimMaterial,
    num_claims: usize,
    args: &Args,
    squashed: &whir_p3::accumulation::quasar::QuasarFrontendOutput<F, EF, F, 8>,
    fold_proof: &whir_p3::accumulation::proof::AccumulationProof<F, EF, F, 8>,
) {
    let quasar_config = make_whir_config(material.witness_poly.num_variables(), args);
    let quasar_domainsep = make_domain_sep(&quasar_config);
    let mut quasar_challenger = seed_challenger(2000 + num_claims as u64, &quasar_domainsep);
    let fresh_public = build_fresh_instances(material, num_claims)
        .into_iter()
        .map(|fresh| fresh.public())
        .collect::<Vec<_>>();
    QuasarFrontendVerifier::new(&quasar_config)
        .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
            &mut quasar_challenger,
            &fresh_public,
            squashed,
        )
        .unwrap();

    let running_acc = initialize_accumulator_from_spartan::<F, EF, F, 8>(
        &material.shape,
        &material.spartan_proof,
        material.witness_poly.clone(),
        [F::from_u64(999); 8],
        EF::from(F::from_u64(3)),
    );
    // Random LC keeps the same number of variables as the inputs
    let fold_config = make_whir_config(material.witness_poly.num_variables(), args);
    let fold_domainsep = make_domain_sep(&fold_config);
    let mut fold_challenger = seed_challenger(3000 + num_claims as u64, &fold_domainsep);
    LinearizedAccumulationVerifier::new(&fold_config)
        .verify::<<F as Field>::Packing, F, <F as Field>::Packing, 8>(
            &mut fold_challenger,
            &[
                running_acc.public_instance.clone(),
                squashed.accumulator.public_instance.clone(),
            ],
            fold_proof,
        )
        .unwrap();
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
        "log_size,claims,folding_schedule,starting_log_inv_rate,rs_domain_initial_reduction_factor,no_fold_prove_ms,no_fold_verify_ms,raw_fold_prove_ms,raw_fold_verify_ms,quasar_warp_prove_ms,quasar_warp_verify_ms"
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
            let no_fold_prove_ms = average_ms(args.repeats, || {
                let _ = prove_regular_pipeline(&material, num_claims, &args);
            });

            let regular_proofs = prove_regular_pipeline(&material, num_claims, &args);
            let no_fold_verify_ms = average_ms(args.repeats, || {
                verify_regular_pipeline(&material, &regular_proofs, &args);
            });
            let raw_fold_prove_ms = average_ms(args.repeats, || {
                let _ = prove_raw_fold_pipeline(&material, num_claims, &args);
            });
            let (_raw_folded, raw_fold_proof) =
                prove_raw_fold_pipeline(&material, num_claims, &args);
            let raw_fold_verify_ms = average_ms(args.repeats, || {
                verify_raw_fold_pipeline(&material, num_claims, &args, &raw_fold_proof);
            });

            let quasar_warp_prove_ms = average_ms(args.repeats, || {
                let _ = prove_quasar_warp_pipeline(&material, num_claims, &args);
            });
            let (quasar_output, _folded, quasar_fold_proof) =
                prove_quasar_warp_pipeline(&material, num_claims, &args);
            let quasar_warp_verify_ms = average_ms(args.repeats, || {
                verify_quasar_warp_pipeline(
                    &material,
                    num_claims,
                    &args,
                    &quasar_output,
                    &quasar_fold_proof,
                );
            });

            println!(
                "  k={num_claims}: no_fold=({no_fold_prove_ms:.3},{no_fold_verify_ms:.3}) ms, raw_fold=({raw_fold_prove_ms:.3},{raw_fold_verify_ms:.3}) ms, quasar_warp=({quasar_warp_prove_ms:.3},{quasar_warp_verify_ms:.3}) ms"
            );
            writeln!(
                out,
                "{size_log2},{num_claims},{},{},{},{no_fold_prove_ms:.6},{no_fold_verify_ms:.6},{raw_fold_prove_ms:.6},{raw_fold_verify_ms:.6},{quasar_warp_prove_ms:.6},{quasar_warp_verify_ms:.6}",
                folding_schedule_label,
                args.starting_log_inv_rate,
                args.rs_domain_initial_reduction_factor,
            )
            .unwrap();
        }
    }

    println!("wrote results to {}", out_path.display());
}
