# whir-p3

A Plonky3-based implementation of [WHIR](https://eprint.iacr.org/2024/1586) (Reed-Solomon proximity testing with super-fast verification) with a [WARP](https://eprint.iacr.org/2025/753)-style accumulation scheme for fixed-size IVC.

Built on top of [whir](https://github.com/WizardOfMenlo/whir/) and the [Plonky3](https://github.com/Plonky3/Plonky3) library.

## Overview

This codebase implements a complete IVC (Incrementally Verifiable Computation) pipeline:

```
                        Spartan R1CS Prover
                              |
                     FreshInstance (witness + public input)
                              |
                   [optional: Quasar squash l instances -> 1]
                              |
                  +---------------------------+
                  |     WARP Fold Prover       |
                  |  (twin-constraint sumcheck |
                  |   + ProtoGalaxy folding)   |
                  +---------------------------+
                              |
                    WarpAccumulator (fixed size!)
                              |
                       [repeat N times]
                              |
                  +---------------------------+
                  |    Terminal Decider        |
                  |   (algebraic checks +     |
                  |    WHIR proof [planned])   |
                  +---------------------------+
                              |
                         Accept / Reject
```

The key property: **the accumulator witness size stays fixed regardless of how many IVC steps are performed**. This is achieved by using a twin-constraint sumcheck (from the WARP paper) that *reduces* instances rather than *concatenating* them.

## Architecture

### Module Layout

```
src/
  whir/               # WHIR PCS (polynomial commitment scheme) - untouched
  spartan/            # Spartan R1CS prover - untouched
  sumcheck/           # Sumcheck protocol infrastructure
  accumulation/
    protogalaxy.rs    # ProtoGalaxy binary fold primitive (UnivariatePoly, fold)
    warp/
      accumulator.rs  # WARP accumulator types (fixed-size claims)
      fold.rs         # WARP fold prover + verifier (twin-constraint sumcheck)
      twin_constraint.rs  # Twin-constraint round polynomial computation
      decider.rs      # Terminal decider (algebraic checks)
      quasar_adapter.rs   # Bridge from Quasar/Spartan to WARP format
    # Legacy (pre-WARP, witness grows with depth):
    accumulator.rs    # Old LinearStatement-based accumulator
    scheme.rs         # Old union-polynomial fold (WHIR proof per step)
    linearized.rs     # Spartan -> linearized claims conversion
    union_poly.rs     # Union polynomial concatenation (deprecated)
    quasar/           # Quasar multi-instance squash frontend
    decider.rs        # Old terminal decider
  bin/
    warp_bench.rs     # WARP fixed-size IVC benchmark
    accumulation_bench.rs  # Legacy accumulation benchmark (requires --features cli)
    main.rs           # WHIR PCS benchmark
```

### WARP Accumulator (Fixed-Size)

The WARP accumulator carries scalar claims that do NOT grow with IVC depth:

```
WarpAccumulatorInstance:
  commitment_root   [W; DIGEST_ELEMS]  Merkle root of codeword     (constant)
  eval_point        Vec<F>             alpha in F^{log_n}           (fixed: log_n elements)
  eval_claim        F                  mu = f_hat(alpha)            (fixed: 1 element)
  pesat_tau         Vec<F>             PESAT zerocheck randomness   (fixed: log_M elements)
  pesat_x           Vec<F>             public input                 (fixed: num_inputs elements)
  pesat_target      F                  eta = P*(beta, z)            (fixed: 1 element)

WarpAccumulatorWitness:
  codeword          EvaluationsList<F> f = encode(w)                (fixed: n elements)
  witness           Vec<F>             private witness w            (fixed: k elements)
```

Compare with the old accumulator which stored `LinearStatement` weight vectors of size `2^num_variables` that doubled at every fold step.

### How the Fold Keeps Size Fixed

The WARP fold uses a **twin-constraint sumcheck** over `log_l` rounds that simultaneously verifies:

1. **Codeword proximity**: the folded codeword is consistent with evaluation claims
2. **R1CS satisfaction**: the folded witness satisfies the bundled constraints

At each sumcheck round, the `twin_constraint_round_poly` function combines:
- `f_i(X)` = ProtoGalaxy-fold of `(alpha_evals, codeword_evals)`
- `p_i(X)` = ProtoGalaxy-fold of `(beta_evals, Az*Bz - Cz)`
- Combined: `h(X) = Sum_i (f_i(X) + omega * p_i(X)) * eq(tau, i, X)`

After `log_l` rounds, all tables reduce to **single vectors at the original size**. No concatenation, no growth.

### Terminal Decider

The decider checks 3 conditions on the final accumulated instance:

1. **Evaluation claim**: `f_hat(alpha) = mu`
2. **PESAT satisfaction**: `P*(beta, z) = eta` (bundled R1CS)
3. **Codeword validity**: `f = encode(w)` (identity encoding for now)

### Research Papers

This implementation draws from 14 papers. Key ones:

| Paper | Role in this codebase |
|-------|----------------------|
| [WHIR](https://eprint.iacr.org/2024/1586) (Arnon, Chiesa, Fenzi, Yogev 2024) | PCS layer (`src/whir/`) |
| [WARP](https://eprint.iacr.org/2025/753) (Bunz, Chiesa, Fenzi, Wang 2025) | Accumulation framework (`src/accumulation/warp/`) |
| [ProtoGalaxy](https://eprint.iacr.org/2023/1106) (Eagen, Gabizon 2024) | Fold primitive inside sumcheck |
| [Quasar](https://eprint.iacr.org/2025/1912) (Zheng, Gao, Guo, Xiao) | Multi-instance squash (`src/accumulation/quasar/`) |
| [Spartan](https://eprint.iacr.org/2019/550) (Setty 2020) | R1CS prover (`src/spartan/`) |

Reference implementation: [compsec-epfl/warp](https://github.com/compsec-epfl/warp/) (arkworks-based).

## Testing

Run the full test suite (51 tests across all modules):

```bash
cargo test
```

Run only the WARP accumulation tests (36 tests):

```bash
cargo test --lib accumulation::warp
```

Run tests for specific modules:

```bash
cargo test --lib accumulation::warp::fold          # Fold prover + verifier (11 tests)
cargo test --lib accumulation::warp::decider       # Terminal decider (7 tests)
cargo test --lib accumulation::warp::twin_constraint  # Sumcheck (6 tests)
cargo test --lib accumulation::protogalaxy         # ProtoGalaxy fold (7 tests)
cargo test --lib accumulation::warp::quasar_adapter   # Quasar bridge (3 tests)
```

### Key Tests

- `warp_fold_sequential_preserves_size` - Runs 4 sequential folds, asserts witness NEVER grows
- `decider_fixed_size_across_ivc_steps` - 5 sequential folds + decider accepts at each step
- `warp_fold_verifier_rejects_tampered_sumcheck` - Verifier catches tampered proof
- `quasar_then_warp_sequential_pipeline` - Full pipeline: Spartan -> WARP fold -> decider

## Benchmarking

### WARP Fixed-Size IVC Benchmark

The primary benchmark for the WARP accumulation pipeline:

```bash
cargo run --release --bin warp_bench
```

This runs with defaults: `sizes=8,10`, `steps=4,8`, `repeats=3`, `batch=1`.

Arguments (positional):

```bash
cargo run --release --bin warp_bench -- <sizes> <steps> <repeats> <batch>
```

Examples:

```bash
# Quick test: small witness, few steps
cargo run --release --bin warp_bench -- "8" "4" 3 1

# Medium: 2^10 witness, up to 16 IVC steps
cargo run --release --bin warp_bench -- "10" "4,8,16" 5 1

# Large: 2^12-2^14 witness, 8 steps, batch of 2 instances per step
cargo run --release --bin warp_bench -- "12,14" "8" 5 2

# Stress test: many IVC steps to verify size never grows
cargo run --release --bin warp_bench -- "10" "32,64,128" 3 1
```

Sample output:

```
WARP Fixed-Size IVC Accumulation Benchmark
==========================================
Field: BabyBear (31-bit)
Batch size per step: 1
Repeats: 3

--- log2(witness) = 10 (num_vars=2048, num_cons=1024) ---
  steps=  4: prove=   493us  verify=     0us  decide=    26us  | witness=15.97 KiB codeword=16.00 KiB [FIXED]
  steps= 16: prove=   496us  verify=     0us  decide=    26us  | witness=15.97 KiB codeword=16.00 KiB [FIXED]

--- log2(witness) = 12 (num_vars=8192, num_cons=4096) ---
  steps=  4: prove=  2573us  verify=     1us  decide=   168us  | witness=63.97 KiB codeword=64.00 KiB [FIXED]
  steps= 16: prove=  2481us  verify=     1us  decide=   212us  | witness=63.97 KiB codeword=64.00 KiB [FIXED]
```

Key observations:
- `[FIXED]` confirms witness size never grows regardless of step count
- Prove time scales with witness size, NOT number of IVC steps
- Verify time is sub-microsecond (field ops only, no WHIR proof)

### Legacy Accumulation Benchmark

The old benchmark (requires `cli` feature) compares three modes:

```bash
cargo run --release --features cli --bin accumulation_bench
```

See `--help` for options. This benchmark uses the old union-polynomial approach where witness size grows with depth.

### Spartan Benchmark

```bash
cargo bench --bench spartan
```

### WHIR PCS Benchmark

```bash
cargo run --release --features cli --bin main
```

## Current Status and Future Work

### Implemented

- [x] WHIR PCS (Reed-Solomon proximity testing)
- [x] Spartan R1CS prover (sumcheck-based)
- [x] WARP accumulation with fixed-size witness
  - [x] ProtoGalaxy binary fold primitive
  - [x] Twin-constraint sumcheck (codeword proximity + R1CS satisfaction)
  - [x] Fold prover and verifier
  - [x] Terminal algebraic decider
  - [x] Quasar adapter (Spartan -> WARP bridge)
- [x] Quasar multi-instance squash frontend

### Deferred (Next Steps)

- [ ] **Reed-Solomon encoding**: Currently using identity encoding (codeword = witness). Integrate with WHIR's RS encoding for actual PCS security.
- [ ] **WHIR succinct decider**: Generate a WHIR proof at the terminal step so the verifier doesn't need the witness. The algebraic decider infrastructure is in place.
- [ ] **OOD/shift query codeword batching**: Phase 3 of the WARP fold (out-of-domain sampling + Merkle auth paths). Currently deferred to the terminal decider via WHIR.
- [ ] **Fiat-Shamir integration**: Replace the `transcript_round` callback with proper Poseidon2 duplex sponge.

### Future Extensions

- [ ] **Non-uniform IVC (zkVM)**: KiloNova-style holographic folding for multiple opcodes
- [ ] **PCS upgrade**: TensorSwitch+WARP for linear-time prover and sublinear extension field cost
- [ ] **Recursive verifier circuit**: Symphony-style CP-SNARK wrapper
- [ ] **Sublinear accumulation verifier**: Quasar's O(sqrt(N)) technique
