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
cargo test --lib --features bench-timing \
  ivc::warp_ivc::tests::measure_recursive_circuit_size -- --nocapture
```

Shows the recursive IVC circuit breakdown: step circuit vs WARP fold verifier (Poseidon2 Fiat-Shamir + sumcheck verification). Current circuit: 5,293 constraints, dominated by Poseidon2 hashing.

### Legacy benchmarks

```bash
cargo run --release --bin warp_bench -- "14" "4,8,16" 3 8     # Includes recursive IVC path
cargo run --release --bin pipeline_bench -- "10,12" "4,8" 3 1  # Eval-fold pipeline
```

## Testing

```bash
cargo test                                # All tests (389 tests)
cargo test accumulation::warp             # WARP fold tests
cargo test accumulation::pipeline         # Full pipeline: Spartan -> batch reduce -> fold -> WHIR
cargo test ivc::warp_ivc                  # IVC tests (init, step, batch, recursive, terminal WHIR)
cargo test ivc::warp_fold_verifier_circuit  # Recursive verifier circuit
```

## Architecture

### Module Layout

```
src/
  whir/                 # WHIR PCS (polynomial commitment scheme)
  spartan/              # Spartan R1CS prover (table-based, O(n) per sumcheck round)
  sumcheck/             # Sumcheck protocol (Svo + Classic strategies)
  accumulation/
    warp/
      fold.rs           # WARP fold prover (RS encode + Merkle + twin-constraint + shift/OOD + eval batch)
      twin_constraint.rs  # Twin-constraint sumcheck (degree-2, base field)
      encoding.rs       # RS encoding via DFT + Merkle commitment
      accumulator.rs    # WarpAccumulator types (fixed-size)
      decider.rs        # Algebraic decider
      eval_fold.rs      # Eval-only fold variant (no PESAT)
      quasar_adapter.rs # Bridge from Spartan to WARP format
    constraint_batch.rs # Constraint batching sumcheck (reduces l linear claims to point evals)
    random_lc.rs        # Random linear combination (witness size preserved)
    pipeline.rs         # End-to-end pipeline tests
    linearized.rs       # Spartan -> linearized claims conversion
    scheme.rs           # v2 accumulation (WHIR per step, for comparison)
    quasar/             # Quasar frontend (squash via WHIR-backed accumulation)
    decider.rs          # Terminal WHIR decider
  ivc/
    warp_ivc.rs         # WARP IVC: init, step, step_recursive, step_batch
    warp_fold_verifier_circuit.rs  # In-circuit fold verifier (Poseidon2 + sumcheck)
    eval_fold_verifier_circuit.rs  # Alternative eval-only verifier circuit
    step.rs             # StepCircuit trait
    ivc.rs              # v2 IVC (WHIR per step, for comparison)
    verifier_circuit.rs # v2 verifier circuit (for comparison)
  circuit/
    builder.rs          # R1CS circuit builder
    poseidon2.rs        # Poseidon2 as R1CS constraints
    sponge.rs           # Duplex sponge challenger as R1CS
    ext_field.rs        # BabyBear^4 extension field as R1CS
    bits.rs             # Bit decomposition gadgets
  poly/                 # Polynomial representations
  fiat_shamir/          # Fiat-Shamir transcript
  parameters/           # Protocol parameters
  bin/
    compare_bench.rs    # Fair 4-way comparison benchmark
    warp_bench.rs       # WARP benchmark with recursive IVC
    pipeline_bench.rs   # Eval-fold pipeline benchmark
```

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
