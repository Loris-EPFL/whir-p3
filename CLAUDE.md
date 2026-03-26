# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

whir-p3 is a Rust implementation of the WHIR polynomial commitment scheme using the Plonky3 cryptographic library. It includes a Spartan proof system and a two-layer accumulation structure (Quasar + WARP). The library is `#![no_std]` compatible.

## Common Commands

### Build
```bash
cargo build                    # debug build
cargo build --release          # release build
```

### Tests
```bash
cargo test                     # run all tests
cargo test whir::test          # WHIR end-to-end tests only
cargo test spartan             # Spartan tests only
cargo test sumcheck            # sumcheck tests only
```

### Benchmarks
```bash
cargo bench --bench whir                    # WHIR PCS benchmark
cargo bench --bench spartan                 # Spartan prover/verifier
cargo bench --bench accumulation            # accumulation (no_fold vs raw_fold vs quasar_warp)
cargo bench --bench sumcheck                # sumcheck benchmark
cargo bench --bench spartan -- "1024"       # filter by constraint size
cargo bench --bench accumulation -- "2^10/k=4"  # filter by parameters
```

### CLI Binaries (require `--features cli`)
```bash
cargo run --release --features cli --bin main
cargo run --release --features cli --bin accumulation_bench -- --sizes 12,14 --claims 2,4,8 --repeats 20
cargo run --bin accumulation_report         # generate markdown + SVG reports
```

### Formatting & Linting
```bash
cargo fmt
cargo clippy                   # strict: pedantic + nursery lints enabled
```

## Architecture

### Core Modules (`src/`)

- **`whir/`** — WHIR polynomial commitment scheme. Split into `committer/` (writer/reader for Merkle-based commitments), `prover/`, `verifier/`, `constraints/`, `parameters.rs` (includes `WhirConfig`, `SumcheckStrategy`), and `proof.rs`.
- **`sumcheck/`** — Sumcheck protocol implementation with two strategies: `Svo` and `Classic`. Contains `sumcheck_prover.rs`, `lagrange.rs`, `product_polynomial.rs`, `svo.rs`.
- **`spartan/`** — Spartan proof system built on WHIR. Includes R1CS representation (`r1cs.rs`), the SPARK compiler (`spark.rs`), and the sumcheck-based prover (`r1cs_prover.rs`).
- **`accumulation/`** — Two-layer accumulation:
  - **`quasar/`** — Quasar frontend that squashes multiple fresh linearized instances into one committed object (`fresh.rs`, `frontend.rs`).
  - **`scheme.rs`** — WARP-style folded WHIR backend that folds committed accumulators and proves them.
  - `linearized.rs`, `accumulator.rs`, `union_poly.rs`, `proof.rs` — supporting types.
- **`poly/`** — Polynomial representations: `evals.rs` (evaluation-domain representation), `multilinear.rs` (`MultilinearPoint`).
- **`fiat_shamir/`** — Fiat-Shamir transcript via `DomainSeparator` pattern.
- **`parameters/`** — `ProtocolParameters` (security level, folding factor, PoW bits, rate) and `FoldingFactor` variants (`Constant`, `ConstantFromSecondRound`).

### Key Type Parameters

The codebase is heavily generic. A typical WHIR instantiation requires:
- `F` — base field (e.g., `BabyBear`, `KoalaBear`)
- `EF` — extension field (e.g., `BinomialExtensionField<F, 4>`)
- Hash/Compress types for Merkle trees (Poseidon2-based or Keccak-based)
- Challenger type for Fiat-Shamir

### Features
- `parallel` (default) — enables Rayon parallelism
- `cli` — enables CLI binaries with clap, tracing, bincode

### Rust Configuration
- Edition 2024, MSRV 1.93
- Strict clippy: `pedantic` + `nursery` enabled; `dead_code` allowed
- rustfmt: `group_imports = "StdExternalCrate"`, `imports_granularity = "Crate"`
