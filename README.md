# whir-p3

A version of https://github.com/WizardOfMenlo/whir/ which uses the Plonky3 library.

## Usage

Spartan implementation on branch `feat/spartan`,  `feat/spartan-v1` and benchmarks on branch `feat/spartan-v1-benchmarks`.

Implemented from https://github.com/Microsoft/Spartan
## Testing and Benchmarking

### Running Tests
To run the full suite of unit and integration tests (including Spartan's arithmetic verification tests):
```bash
cargo test
```

### Benchmarking Spartan
We have implemented a native synthetic R1CS generator for benchmarking the Spartan sumcheck prover and verifier. The benchmark automatically tests multiple constraint sizes (e.g. $2^8$, $2^{10}$).

To run the entire benchmark suite:
```bash
cargo bench --bench spartan
```

**Filtering Benchmarks:**
If you want to run the benchmark for a specific matrix size (e.g., only $2^{10} = 1024$ constraints) without waiting for the others, you can pass a filter argument directly to the Criterion test harness:
```bash
cargo bench --bench spartan -- "1024"
```

To run only the prover or only the verifier benchmarks, use their respective group names:
```bash
cargo bench --bench spartan -- "Spartan_Prove"
cargo bench --bench spartan -- "Spartan_Verify"
```
