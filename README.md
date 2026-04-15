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

All IVC benchmarks are driven by the `whir-bench` crate via TOML config files.

### Quick smoke test

```bash
cd crates/whir-bench
cargo run --release -p whir-bench --features whir-bench/symphony --bin bench -- configs/smoke.toml
```

### Full benchmark (4-way recursive IVC comparison)

```bash
cd crates/whir-bench
cargo run --release -p whir-bench --features whir-bench/symphony --bin bench -- configs/thesis.toml
```

This runs 4 schemes that correspond to the recursive IVC paths:

| Scheme | Pipeline | Fold arity |
|--------|----------|------------|
| `pure_warp` | `warp_ivc_init` + `warp_ivc_step` — non-recursive WARP fold | l=2 |
| `quasar_warp` | `warp_ivc_init_recursive_union` + `warp_ivc_step_recursive_union` — Poseidon2 recursive circuit + union fold | l=arity |
| `symphony` | `warp_ivc_init_cp` + `warp_ivc_step_recursive_cp` — algebraic recursive circuit + CP-SNARK transcripts | l=2 |
| `quasar_symphony` | `warp_ivc_init_recursive_union_cp` + `warp_ivc_step_recursive_union_cp` — algebraic recursive circuit + union fold + CP-SNARK | l=arity |

Symphony schemes require `--features whir-bench/symphony`. Without it they are skipped.

### TOML config reference

```toml
schemes = ["pure_warp", "quasar_warp", "symphony", "quasar_symphony"]
warmup = 1
repeats = 5
output = "output/results.jsonl"

[axes]
log_n = [10, 12, 14]      # log2(constraints) for synthetic R1CS
arity = [2, 4]             # fold arity (union paths need >=4)
batch = [1]                # unused by current schemes (reserved)
ivc_steps = [6, 12]        # total circuits to prove (must be divisible by arity-1 for union paths)
step_muls = [100]          # multiplications in the WorkloadStepCircuit
seed = 42
```

The harness iterates the cartesian product of all axes, runs each scheme for `warmup + repeats` iterations, and emits one JSONL row per (scheme, axes, run) triple.

### Plotting results

```bash
# Setup (once)
python3 -m venv .venv && .venv/bin/pip install matplotlib pandas numpy

# Aggregate table
.venv/bin/python crates/whir-bench/scripts/plot.py crates/whir-bench/output/thesis.jsonl --aggregate

# PDF plots
.venv/bin/python crates/whir-bench/scripts/plot.py crates/whir-bench/output/thesis.jsonl \
  --figure time_vs_steps --out thesis_steps.pdf
```

Available `--figure` types: `time_vs_log_n`, `verifier_vs_arity`, `batch_speedup`, `time_vs_steps`.

### Circuit size measurement

```bash
cargo test -p whir-ivc --features bench-timing \
  warp_ivc::tests::measure_recursive_circuit_size -- --nocapture
```

### Spartan / SPARK micro-benchmarks

```bash
cargo run --release --bin profile_spartan
cargo run --release --bin spartan_spark_bench
cargo run --release --bin spartan_spark_report
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
- `whir-p3/src/bin/` — `profile_spartan`, `spartan_spark_bench`, `spartan_spark_report`, `main`
- `whir-bench/` — unified benchmark crate: `bench` binary, TOML configs, plot script

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
