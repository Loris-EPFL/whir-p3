# whir-p3

A Plonky3-based implementation of [WHIR](https://eprint.iacr.org/2024/1586) (Reed-Solomon proximity testing with super-fast verification) with a [WARP](https://eprint.iacr.org/2025/753)-style accumulation scheme for fixed-size IVC.

Built on top of [whir](https://github.com/WizardOfMenlo/whir/) and the [Plonky3](https://github.com/Plonky3/Plonky3) library.

## Overview

This codebase implements a complete IVC (Incrementally Verifiable Computation) pipeline over BabyBear (31-bit prime field):

```
N R1CS instances
  |
  v
Spartan prove each (degree-3 R1CS -> linear claims)
  |
  v
[If batch > 1] Batch reduction
  constraint_batch sumcheck + random linear combination
  (reduces batch instances to 1, witness size preserved)
  |
  v
WARP fold with running accumulator
  RS encode -> Merkle commit -> twin-constraint sumcheck
  -> shift queries -> OOD sampling -> eval batching sumcheck
  (no WHIR proof at this step)
  |
  v
WarpAccumulator (fixed size, regardless of IVC depth)
  |
  v
[repeat for each IVC step]
  |
  v
Terminal: single WHIR proof on final accumulated witness
  |
  v
Accept / Reject
```

Key properties:
- **Fixed-size accumulator**: witness size never grows regardless of IVC step count
- **Single WHIR proof**: expensive PCS proof generated only once at the end
- **Batch reduction**: when multiple instances arrive per step, they are combined into one via constraint batching sumcheck + random LC before folding
- **Recursive IVC**: optional in-circuit fold verification via Poseidon2 Fiat-Shamir

## Benchmark Results

At `log2(constraints)=16, batch=8, N=128 instances`:

| Path | Time | Speedup vs baseline |
|------|------|-------------------|
| Independent WHIR (N separate proofs) | 7,875ms | 1.00x (baseline) |
| Direct fold (8-arity per step + 1 WHIR) | 3,430ms | **2.30x** |
| Batch reduce + fold (reduce 8->1 + fold + 1 WHIR) | 1,468ms | **5.36x** |

The batch reduction gives an additional **2.34x** over direct fold by replacing 7 RS encodings + Merkle commits with a single constraint_batch sumcheck + random linear combination.

All paths start from Spartan-linearized witnesses (same cost, excluded from comparison).

## Running Benchmarks

### Fair 4-way comparison (recommended)

```bash
cargo run --release --bin compare_bench -- <log_sizes> <num_steps> <repeats> <batch>
```

Arguments:
- `log_sizes`: comma-separated log2 of constraint count (e.g., `"14"` = 2^14 constraints)
- `num_steps`: comma-separated step counts (total instances = steps x batch)
- `repeats`: repetitions for median timing
- `batch`: instances per step (1 = no batch reduction, 8 = reduce 8 to 1 before fold)

Examples:

```bash
# Quick test
cargo run --release --bin compare_bench -- "10,12" "4,8" 3 1

# Show batch reduction benefit (batch=8)
cargo run --release --bin compare_bench -- "12,14" "4,8,16" 3 8

# Large scale
cargo run --release --bin compare_bench -- "14,15,16" "4,8,16,32" 5 8
```

Output columns:
- `spartan`: Spartan linearization time (common to all paths, for reference only)
- `independent`: N separate WHIR proofs (baseline)
- `direct_fold`: batch-arity WARP fold per step + 1 terminal WHIR
- `batch+fold`: batch reduce to 1 + fold(l=2) per step + 1 terminal WHIR
- `fold/ind`: speedup of direct fold over independent WHIR
- `batch/ind`: speedup of batch+fold over independent WHIR
- `batch/fold`: speedup of batch reduction over direct fold (>1 = batch reduction helps)

### Circuit size measurement

```bash
cargo test -p whir-ivc --features bench-timing \
  warp_ivc::tests::measure_recursive_circuit_size -- --nocapture
```

Shows the recursive IVC circuit breakdown: step circuit vs WARP fold verifier (Poseidon2 Fiat-Shamir + sumcheck verification). Current circuit: 5,293 constraints, dominated by Poseidon2 hashing.

### CP-SNARK + Quasar comparison (4-way apples-to-apples)

Compares recursive IVC variants with Symphony deferred hashing and Quasar union commitment:

```bash
cargo run --release --features symphony --bin cp_snark_bench -- <log_sizes> <num_steps> <repeats> <step_muls> <arity>
```

Arguments:
- `log_sizes`: comma-separated log2 of synthetic R1CS constraint count
- `num_steps`: comma-separated total instance counts (benchmark amortizes over these)
- `repeats`: repetitions for median timing
- `step_muls`: multiplication gates in the recursive step circuit (application workload)
- `arity`: union fold arity (ℓ, power of 2)

Produces three tables:
- **Table 1**: Per-step breakdown for l=2 paths (Regular IVC vs CP-SNARK)
- **Table 2**: Apples-to-apples 4-way IVC prover comparison
  - `reg_tot`: Regular IVC, l=2, Poseidon2 in-circuit (baseline)
  - `cp_tot`: CP-SNARK IVC, l=2, Symphony deferred hashing
  - `pu_tot`: Poseidon2 Union IVC, l=arity, no Symphony (pure WARP + Quasar)
  - `ru_tot`: Symphony Recursive Union IVC, l=arity, deferred hashing
- **Table 3**: Standalone verifier benchmark — Quasar's sublinear O(1) vs O(ℓ) claim

Examples:

```bash
# Aggregation sweet spot (small step circuit → CP-SNARK/Union shine)
cargo run --release --features symphony --bin cp_snark_bench -- "10,12" "32,64,128" 3 100 4

# Realistic rollup-scale workload
cargo run --release --features symphony --bin cp_snark_bench -- "16,18" "8,16,32,64" 3 5000 4

# High-load zkVM-like (large step circuit)
cargo run --release --features symphony --bin cp_snark_bench -- "18,20" "8,16,32" 3 50000 4

# Higher arity to stress Quasar's sublinear verifier benefit
cargo run --release --features symphony --bin cp_snark_bench -- "12" "64,128,256" 3 500 8
```

### Verifier scaling (Quasar sublinear claim)

Table 3 at the end of `cp_snark_bench` directly demonstrates Quasar's O(log ℓ) verifier cost vs O(ℓ) for the standard WARP verifier:

```bash
# Any cp_snark_bench invocation ends with Table 3 showing arity scaling from ℓ=2 to 64
cargo run --release --features symphony --bin cp_snark_bench -- "10" "8" 1 100 4
```

Sample output (log_code=16, 1000 iterations per measurement):

```
 arity |   nonunion_us      union_us |     nu/un | saved_absorb
----------------------------------------------------------------------
     2 |       6.09 us       4.68 us |    1.30x |           18
     4 |      10.44 us       4.88 us |    2.14x |           70
     8 |      18.62 us       5.37 us |    3.47x |          174
    16 |      35.33 us       6.00 us |    5.89x |          382
    32 |      69.11 us       6.86 us |   10.07x |          798
    64 |     136.12 us       7.38 us |   18.44x |         1630
```

Non-union verifier time doubles as ℓ doubles (O(ℓ)). Union verifier time grows only with log₂ℓ (O(log ℓ)). At ℓ=64, the union verifier is **18x faster**.

### Arity micro-benchmark (prover-side fold costs at varying arity)

```bash
cargo run --release --bin arity_bench -- <log_sizes> <num_instances> <repeats>
```

Compares WARP fold prover costs across arities ℓ ∈ {2, 4, 8, 16} at varying synthetic R1CS sizes.

### Step-size sweep (per-phase IVC cost breakdown)

```bash
cargo run --release --bin step_size_bench -- <num_ivc_steps> <repeats>
```

Sweeps step circuit sizes and reports where time is spent: circuit build, Spartan prove, RS encode, Merkle commit, WARP fold.

### Spartan / SPARK micro-benchmarks

```bash
cargo run --release --bin profile_spartan
cargo run --release --bin spartan_spark_bench
cargo run --release --bin spartan_spark_report   # post-process spark bench output
cargo run --release --bin accumulation_report    # post-process criterion accumulation runs
```

### Criterion benches

```bash
cargo bench -p whir-p3 --bench whir
cargo bench -p whir-p3 --bench spartan
cargo bench -p whir-p3 --bench sumcheck
cargo bench -p whir-p3 --bench accumulation
cargo bench -p whir-p3 --bench evaluate
cargo bench -p whir-p3 --bench eval_multilinear
cargo bench -p whir-p3 --bench stir_queries
```

## Testing

```bash
cargo test                                       # All tests across the workspace
cargo test -p warp                               # WARP fold tests (twin-constraint, encoding, eval fold)
cargo test -p accumulation                       # Pipeline, constraint batch, random LC, linearized
cargo test -p whir-ivc                           # IVC tests (init, step, batch, recursive, terminal WHIR)
cargo test -p whir-ivc warp_fold_verifier        # Recursive in-circuit fold verifier
cargo test -p whir-pcs                           # WHIR PCS end-to-end
cargo test -p whir-spartan                       # Spartan R1CS prover
```

## Architecture

The codebase is a Cargo workspace (`crates/*`). All library crates are `#![no_std]` + alloc, edition 2024, MSRV 1.93. The Plonky3 `rev` pin is single-sourced in the root `Cargo.toml`.

### Workspace Layout

| Crate | Role |
|-------|------|
| **`whir-core`** | Foundation: `parameters/`, `fiat_shamir/`, `poly/`, constants, utilities |
| **`whir-circuit`** | R1CS circuit builder, Poseidon2, duplex sponge, BabyBear⁴ extension-field arithmetic, bit gadgets |
| **`whir-pcs`** | WHIR polynomial commitment scheme + sumcheck (Svo + Classic strategies) |
| **`whir-spartan`** | Spartan R1CS prover (SPARK compiler, table-based O(n) per sumcheck round) |
| **`warp`** | WARP fold: RS encoding, Merkle commit, twin-constraint sumcheck, shift/OOD queries, eval batch, accumulator types, terminal WHIR decider |
| **`accumulation`** | Constraint-batching sumcheck, random linear combination, pipeline, linearized claims, v2 accumulation scheme, compact instance, union poly |
| **`quasar`** | Quasar frontend (squash via WHIR-backed accumulation) — `fresh.rs`, `frontend.rs`, `scheme.rs` |
| **`whir-ivc`** | WARP IVC (init / step / step_batch / step_recursive_union), in-circuit fold verifier, eval-only verifier, linearized IVC, unified IVC |
| **`whir-cp-snark`** | CP-SNARK compiler + terminal (Symphony deferred hashing; `symphony`-gated) |
| **`whir-p3`** | Umbrella crate re-exporting all of the above; hosts binaries and criterion benches |

### Crate Highlights

- `warp/src/fold.rs` — WARP fold prover (RS encode + Merkle + twin-constraint + shift/OOD + eval batch)
- `warp/src/twin_constraint.rs` — twin-constraint sumcheck (degree-2, base field)
- `warp/src/accumulator.rs` — `WarpAccumulator{,Instance,Witness}` (fixed-size)
- `warp/src/quasar_adapter.rs` — bridge from Spartan into WARP format
- `warp/src/terminal_whir.rs` — terminal WHIR decider
- `accumulation/src/constraint_batch.rs` — reduces ℓ linear claims to point evaluations
- `accumulation/src/random_lc.rs` — random linear combination (witness size preserved)
- `accumulation/src/pipeline.rs` — end-to-end Spartan → batch reduce → fold → WHIR tests
- `whir-ivc/src/warp_ivc.rs` — WARP IVC driver
- `whir-ivc/src/warp_fold_verifier_circuit.rs` — in-circuit fold verifier (Poseidon2 + sumcheck)
- `whir-ivc/src/unified.rs` — unified IVC entry point
- `whir-p3/src/bin/` — `compare_bench`, `cp_snark_bench`, `arity_bench`, `step_size_bench`, `profile_spartan`, `spartan_spark_bench`, `spartan_spark_report`, `accumulation_report`, `main`

### Feature Flags

- `parallel` (default) — Rayon parallelism across all library crates
- `cli` — bin-only deps (`clap`, `tracing-subscriber`, `tracing-forest`, `bincode`) for `main`
- `bench-timing` — per-phase timing prints; forwarded to `whir-pcs`
- `symphony` — enables `whir-cp-snark` + Symphony deferred hashing (required by `cp_snark_bench`)

### WARP Accumulator (Fixed-Size)

The accumulator carries scalar claims that never grow:

```
WarpAccumulatorInstance:
  commitment_root   [F; 8]     Merkle root of RS codeword
  eval_point        Vec<F>     alpha (log_n elements)
  eval_claim        F          mu = f_hat(alpha)
  pesat_tau         Vec<F>     PESAT constraint point (log_M elements)
  pesat_x           Vec<F>     public input
  pesat_target      F          eta = P*(beta, z)

WarpAccumulatorWitness:
  codeword          Vec<F>     RS-encoded polynomial (n elements)
  witness           Vec<F>     raw witness (k elements)
```

### How the Fold Keeps Size Fixed

The twin-constraint sumcheck runs over `log_l` rounds (1 round for l=2) and simultaneously verifies:
1. **Codeword proximity**: folded codeword is consistent with evaluation claims
2. **R1CS satisfaction**: folded witness satisfies the bundled constraints (PESAT)

After the sumcheck, all tables (codewords, witnesses, eval points, PESAT points) are reduced to single vectors at the original size via eq-weighted linear combination. No concatenation, no growth.

### Batch Reduction

When multiple instances arrive per step, the batch reduction:
1. Runs `constraint_batch_prove` to reduce l linearized claims to point evaluations
2. Runs `random_linear_combination` to combine l witnesses into 1 of the same size
3. The combined witness enters the WARP fold as a single FreshInstance

This replaces `batch-1` RS encodings + Merkle commits with a cheaper constraint_batch sumcheck + random LC, giving 1.5-2.3x additional speedup over direct fold at batch=8.

## Research Papers

| Paper | Role |
|-------|------|
| [WHIR](https://eprint.iacr.org/2024/1586) (Arnon, Chiesa, Fenzi, Yogev 2024) | PCS layer |
| [WARP](https://eprint.iacr.org/2025/753) (Bunz, Chiesa, Fenzi, Wang 2025) | Accumulation framework |
| [Spartan](https://eprint.iacr.org/2019/550) (Setty 2020) | R1CS prover |

Reference implementation: [compsec-epfl/warp](https://github.com/compsec-epfl/warp/) (arkworks-based).
