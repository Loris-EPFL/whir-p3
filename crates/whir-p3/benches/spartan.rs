use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use p3_challenger::DuplexChallenger;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use rand::{SeedableRng, rngs::SmallRng};
use whir_p3::spartan::{
    r1cs::R1CSInstance,
    r1cs_prover::{R1CSProver, R1CSVerifier},
};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Poseidon16 = Poseidon2KoalaBear<16>;
type MyChallenger = DuplexChallenger<F, Poseidon16, 16, 8>;

fn bench_spartan_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("Spartan_Prove");
    group.sample_size(10);

    // Benchmark for matrix sizes 2^10, 2^12, 2^14, etc.
    for size_log2 in [8, 10] {
        let num_cons = 1 << size_log2;
        let num_vars = 1 << size_log2;
        let num_inputs = 10;

        let mut rng = SmallRng::seed_from_u64(0);
        let (_shape, instance) =
            R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);

        let prover = R1CSProver::new();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_cons),
            &instance,
            |b, inst| {
                b.iter(|| {
                    // We use a fresh challenger for each iteration
                    let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
                    let mut spartan_challenger = MyChallenger::new(poseidon16);

                    prover.prove::<EF, _>(inst, &mut spartan_challenger)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_spartan_prove, bench_spartan_verify);
criterion_main!(benches);

fn bench_spartan_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Spartan_Verify");
    group.sample_size(10);

    for size_log2 in [8, 10] {
        let num_cons = 1 << size_log2;
        let num_vars = 1 << size_log2;
        let num_inputs = 10;

        let mut rng = SmallRng::seed_from_u64(0);
        let (shape, instance) =
            R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);

        let prover = R1CSProver::new();
        let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
        let mut spartan_challenger = MyChallenger::new(poseidon16.clone());
        let proof = prover.prove::<EF, _>(&instance, &mut spartan_challenger);

        let verifier = R1CSVerifier::new();

        group.bench_with_input(BenchmarkId::from_parameter(num_cons), &proof, |b, prf| {
            b.iter(|| {
                let mut verifier_challenger = MyChallenger::new(poseidon16.clone());
                verifier
                    .verify::<EF, _>(&shape, instance.input(), prf, &mut verifier_challenger)
                    .unwrap()
            });
        });
    }
    group.finish();
}
