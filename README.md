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

### Benchmarking Regular vs Accumulated Folding

To compare the regular Spartan+WHIR pipeline against the accumulated folded WARP-style path:

```bash
cargo bench --bench accumulation
```

This benchmark reports four families of measurements across several instance sizes and claim counts:
- `regular_prove`
- `regular_verify`
- `accumulated_prove`
- `accumulated_verify`

You can filter to a specific sub-benchmark, for example:

```bash
cargo bench --bench accumulation -- "accumulated_verify"
cargo bench --bench accumulation -- "2^10/k=4"
```

#### Recommended Process For Stable Results

Criterion already supports command-line tuning, so you do not need to modify the code in order to run longer benchmarks.

For quick exploratory runs:

```bash
cargo bench --bench accumulation
```

For more stable measurements, use a larger sample size and longer measurement window:

```bash
cargo bench --bench accumulation -- --sample-size 30 --warm-up-time 3 --measurement-time 10
```

For final comparison runs, use an even longer configuration:

```bash
cargo bench --bench accumulation -- --sample-size 50 --warm-up-time 5 --measurement-time 20
```

You can combine those with filters. For example:

```bash
cargo bench --bench accumulation -- "accumulated_verify" --sample-size 50 --warm-up-time 5 --measurement-time 20
cargo bench --bench accumulation -- "2^10/k=4" --sample-size 50 --warm-up-time 5 --measurement-time 20
```

#### How To Read Criterion Output

- The `time: [low mid high]` line is the important line for comparing folded vs non-folded.
- The `change:` line compares against previous saved Criterion runs of the same benchmark name; it does **not** compare regular vs folded.
- So for the algorithmic comparison, compare:
  - `regular_prove` vs `accumulated_prove`
  - `regular_verify` vs `accumulated_verify`

#### Practical Benchmark Checklist

For better reproducibility:

- close heavy background applications
- keep the machine plugged in
- use a performance CPU governor if available
- avoid running other builds during measurement
- run the full benchmark suite at least 3 times before drawing conclusions

#### Suggested Benchmark Matrix

At minimum, compare these cases:

- `2^8, k=2`
- `2^8, k=4`
- `2^10, k=2`
- `2^10, k=4`

For stronger evidence, extend to larger instances and batches:

- `2^12, k=2`
- `2^12, k=4`
- `2^12, k=8`

#### Generating A Report And Plots

To generate a markdown summary and SVG speedup plots from the Criterion results:

```bash
cargo run --bin accumulation_report
```

This writes report artifacts under `output/benchmarks/accumulation/`.

Generated plots now include both:
- absolute runtime plots for regular vs folded paths
- relative speedup plots

Main report files:

- `output/benchmarks/accumulation/summary.md`
- `output/benchmarks/accumulation/prove_times.svg`
- `output/benchmarks/accumulation/verify_times.svg`
- `output/benchmarks/accumulation/prove_speedup.svg`
- `output/benchmarks/accumulation/verify_speedup.svg`
