//! Profiling binary: isolates Spartan prover at configurable sizes.
//!
//! Usage with samply:
//!   cargo build --release --bin profile_spartan
//!   samply record target/release/profile_spartan <log_size> <num_iters>
//!
//! Examples:
//!   samply record target/release/profile_spartan 20 4    # 4 iterations at 2^20 constraints
//!   samply record target/release/profile_spartan 18 8    # 8 iterations at 2^18 constraints

use std::{env, hint::black_box, time::Instant};

use p3_challenger::DuplexChallenger;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use rand::{SeedableRng, rngs::SmallRng};

use whir_p3::spartan::{r1cs::R1CSInstance, r1cs_prover::R1CSProver};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = p3_koala_bear::Poseidon2KoalaBear<16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

fn main() {
    let args: Vec<String> = env::args().collect();
    let log_size: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(18);
    let num_iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);

    let num_cons = 1usize << log_size;
    let num_vars = 1usize << log_size;
    let num_inputs = 8;

    println!(
        "Profiling Spartan prover: log2={log_size} ({num_cons} constraints), {num_iters} iterations"
    );

    // Generate synthetic R1CS
    let mut rng = SmallRng::seed_from_u64(42);
    let (shape, instance) =
        R1CSInstance::<F>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs, &mut rng);
    println!(
        "  Shape: {} constraints, {} vars, {} inputs",
        shape.num_cons(),
        num_vars,
        num_inputs
    );

    let spartan = R1CSProver::new();
    let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(99));

    // Warmup
    {
        let mut chal = MyChallenger::new(perm.clone());
        let _ = black_box(spartan.prove::<EF, _>(&instance, &mut chal));
    }

    // Profiled iterations
    let t_start = Instant::now();
    for i in 0..num_iters {
        let mut chal = MyChallenger::new(perm.clone());
        let proof = black_box(spartan.prove::<EF, _>(&instance, &mut chal));
        black_box(proof);
        if (i + 1) % 2 == 0 || i + 1 == num_iters {
            let elapsed = t_start.elapsed().as_millis();
            let per_iter = elapsed / (i + 1) as u128;
            println!("  [{}/{}] {per_iter} ms/iter", i + 1, num_iters);
        }
    }

    let total = t_start.elapsed().as_millis();
    println!(
        "\nTotal: {total} ms for {num_iters} iterations ({} ms/iter)",
        total / num_iters as u128
    );
}
