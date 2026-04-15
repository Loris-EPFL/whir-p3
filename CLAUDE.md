# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

whir-p3 is a Rust implementation of the WHIR polynomial commitment scheme using the Plonky3 cryptographic library. It includes:
- **Spartan** proof system (R1CS to linear claims via two-phase sumcheck)
- **WARP** accumulation (RS-encoded fold with twin-constraint sumcheck, Merkle commitment, shift queries, OOD sampling)
- **Batch reduction** (constraint_batch sumcheck + random linear combination to reduce multiple instances to one)
- **IVC** (Incrementally Verifiable Computation with recursive in-circuit fold verification via Poseidon2)
- **Terminal WHIR** proof (single WHIR proof at the end of the accumulation chain)

The library is `#![no_std]` compatible.

## Common Commands

### Build
```bash
cargo build                    # debug build
cargo build --release          # release build
```

### Tests
```bash
cargo test                     # run all tests (389 tests, ~4 min)
cargo test whir::test          # WHIR end-to-end tests only
cargo test spartan             # Spartan tests only
cargo test sumcheck            # sumcheck tests only
cargo test accumulation::warp  # WARP fold tests (twin-constraint, eval fold, encoding)
cargo test accumulation::pipeline  # Full pipeline tests (Spartan -> batch reduce -> fold -> WHIR)
cargo test ivc::warp_ivc       # IVC tests (init, step, batch, recursive, terminal WHIR)
cargo test ivc::warp_fold_verifier_circuit  # Recursive verifier circuit tests
```

### Benchmarks

#### Fair 4-way comparison (recommended)
```bash
# Compares: independent WHIR vs direct fold vs batch+fold
# Args: <log_sizes> <num_steps> <repeats> <batch>
cargo run --release --bin compare_bench -- "12,14" "4,8,16" 3 8

# batch=1: no batch reduction benefit (baseline)
cargo run --release --bin compare_bench -- "10,12,14" "2,4,8,16" 3 1

# batch=8: shows batch reduction benefit (1.5-2.3x over direct fold)
cargo run --release --bin compare_bench -- "10,12,14" "2,4,8,16" 3 8

# Large sizes with high batch
cargo run --release --bin compare_bench -- "14,15,16" "4,8,16,32" 5 8
```

Arguments:
- `log_sizes`: comma-separated log2 of constraint count (e.g., "14" = 2^14 constraints)
- `num_steps`: comma-separated IVC step counts
- `repeats`: number of repetitions for median timing
- `batch`: instances per step (batch=1 means 1 instance per fold, batch=8 means 8 instances reduced to 1 then folded)

All paths start from Spartan-linearized witnesses. Spartan time is reported separately. Comparison columns show speedup ratios (>1 = faster than baseline).

#### Legacy benchmarks
```bash
cargo run --release --bin warp_bench -- "14" "4,8,16" 3 8     # 4-way with recursive IVC
cargo run --release --bin pipeline_bench -- "10,12" "4,8" 3 1  # eval-fold pipeline
cargo run --release --features cli --bin accumulation_bench -- --sizes 12,14 --claims 2,4,8 --repeats 10
```

#### Circuit size measurement
```bash
# Shows recursive circuit breakdown (step vs verifier vs Poseidon2)
cargo test --lib --features bench-timing ivc::warp_ivc::tests::measure_recursive_circuit_size -- --nocapture
```

### Formatting & Linting
```bash
cargo fmt
cargo clippy                   # strict: pedantic + nursery lints enabled
```

## Architecture

### Pipeline: Spartan -> Batch Reduction -> WARP Fold -> WHIR

```
N R1CS instances
  -> Spartan prove each (degree-3 R1CS -> linear claims)
  -> [If batch > 1] Batch reduction: constraint_batch_prove + random_lc (combine batch -> 1)
  -> WARP fold with running accumulator:
       RS encode -> Merkle commit -> twin-constraint sumcheck -> shift queries -> OOD -> eval batch
  -> Repeat for IVC steps (no WHIR per step)
  -> Terminal: single WHIR proof on final accumulated witness
```

### Core Modules (`src/`)

- **`whir/`** -- WHIR polynomial commitment scheme. Split into `committer/` (writer/reader for Merkle-based commitments), `prover/`, `verifier/`, `constraints/`, `parameters.rs` (includes `WhirConfig`, `SumcheckStrategy`), and `proof.rs`.
- **`sumcheck/`** -- Sumcheck protocol implementation with two strategies: `Svo` and `Classic`. Contains `sumcheck_prover.rs`, `lagrange.rs`, `product_polynomial.rs`, `svo.rs`.
- **`spartan/`** -- Spartan proof system built on WHIR. Includes R1CS representation (`r1cs.rs`), the SPARK compiler (`spark.rs`), and the sumcheck-based prover (`r1cs_prover.rs`). Table-based prover for O(n) per sumcheck round.
- **`accumulation/`** -- Accumulation infrastructure:
  - **`warp/`** -- WARP fold: `fold.rs` (twin-constraint sumcheck + RS encode + Merkle + shift/OOD + eval batch), `twin_constraint.rs`, `encoding.rs`, `accumulator.rs`, `decider.rs`, `eval_fold.rs` (eval-only fold variant).
  - **`constraint_batch.rs`** -- Constraint batching sumcheck (reduces l linear claims to point evaluations).
  - **`random_lc.rs`** -- Random linear combination of same-size polynomials (witness stays fixed size).
  - **`pipeline.rs`** -- End-to-end pipeline tests.
  - **`quasar/`** -- Quasar frontend (`fresh.rs`, `frontend.rs`) for squashing instances via WHIR-backed accumulation.
  - **`scheme.rs`** -- LinearizedAccumulationProver/Verifier (v2 accumulation with WHIR per step).
  - `linearized.rs`, `accumulator.rs`, `compact_instance.rs`, `union_poly.rs`, `proof.rs`, `decider.rs` -- supporting types.
- **`ivc/`** -- Incrementally Verifiable Computation:
  - **`warp_ivc.rs`** -- WARP-based IVC: `warp_ivc_init`, `warp_ivc_step`, `warp_ivc_step_recursive`, `warp_ivc_step_batch`. No WHIR per step.
  - **`warp_fold_verifier_circuit.rs`** -- In-circuit WARP fold verifier (Poseidon2 Fiat-Shamir + sumcheck verification). 5293 constraints for l=2.
  - **`eval_fold_verifier_circuit.rs`** -- Alternative eval-only fold verifier circuit.
  - **`ivc.rs`** -- v2 IVC using LinearizedAccumulationProver (WHIR per step).
  - **`step.rs`** -- StepCircuit trait + TrivialStepCircuit.
  - **`verifier_circuit.rs`** -- v2 constraint-batch verifier circuit.
- **`circuit/`** -- R1CS circuit builder for recursive proofs:
  - `builder.rs` -- CircuitBuilder with witness/public input allocation and R1CS constraint generation.
  - `poseidon2.rs` -- Poseidon2 permutation as R1CS constraints.
  - `sponge.rs` -- Duplex sponge challenger as R1CS constraints.
  - `ext_field.rs` -- KoalaBear^4 extension field arithmetic as R1CS constraints.
  - `bits.rs` -- Bit decomposition gadgets.
- **`poly/`** -- Polynomial representations: `evals.rs` (evaluation-domain representation), `multilinear.rs` (`MultilinearPoint`).
- **`fiat_shamir/`** -- Fiat-Shamir transcript via `DomainSeparator` pattern.
- **`parameters/`** -- `ProtocolParameters` (security level, folding factor, PoW bits, rate) and `FoldingFactor` variants (`Constant`, `ConstantFromSecondRound`).

### Key Type Parameters

The codebase is heavily generic. A typical WHIR instantiation requires:
- `F` -- base field (e.g., `KoalaBear`, `KoalaBear`)
- `EF` -- extension field (e.g., `BinomialExtensionField<F, 4>`)
- Hash/Compress types for Merkle trees (Poseidon2-based or Keccak-based)
- Challenger type for Fiat-Shamir

### Features
- `parallel` (default) -- enables Rayon parallelism
- `cli` -- enables CLI binaries with clap, tracing, bincode
- `bench-timing` -- enables per-phase timing and circuit size output in tests

### Rust Configuration
- Edition 2024, MSRV 1.93
- Strict clippy: `pedantic` + `nursery` enabled; `dead_code` allowed
- rustfmt: `group_imports = "StdExternalCrate"`, `imports_granularity = "Crate"`
