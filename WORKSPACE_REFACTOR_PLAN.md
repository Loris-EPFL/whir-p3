# Workspace Refactor: whir-p3 → Cargo Workspace

## Context

`whir-p3` is currently one crate (~24k LOC) with 12 binaries and 7 benches. The module tree (`parameters`, `fiat_shamir`, `poly`, `circuit`, `sumcheck`, `spartan`, `whir`, `accumulation`, `ivc`, `cp_snark`) is already layered cleanly — foundation → mid → hub — but shares one `Cargo.toml`, one feature flag set, and one target for `cargo check`. Symptoms: slow incremental rebuilds on any library change, `symphony`/`cli`/`bench-timing` features bleeding across unrelated modules, oversized files (`warp_ivc.rs` ~4k LOC, `poly/evals.rs` ~2.5k, `r1cs_prover.rs` ~1.6k) hiding independent submodules, scattered `pub` API with no consolidated entry points.

Goal: split into a medium-granularity Cargo workspace (7 library crates + 1 bins crate), add per-crate `prelude` modules, and break the oversized files into submodules — without changing behavior. This preserves `#![no_std]` compatibility, keeps the Plonky3 `rev` pin single-sourced, and makes the `symphony` feature local to one crate.

## Workspace Layout (7 library crates + 1 bins crate)

All under `crates/`. Every library crate stays `#![no_std]` + alloc, edition 2024, MSRV 1.93.

| Crate | Source modules absorbed | Internal deps |
|---|---|---|
| **`whir-core`** | `parameters/`, `fiat_shamir/`, `constant.rs`, `utils.rs`, `poly/`, `circuit/` | — |
| **`whir-sumcheck`** | `sumcheck/` | `whir-core` |
| **`whir-spartan`** | `spartan/` | `whir-core`, `whir-sumcheck` |
| **`whir-commit`** | `whir/` (PCS: committer, prover, verifier, constraints, parameters, proof) | `whir-core`, `whir-sumcheck` |
| **`whir-accumulation`** | `accumulation/` (warp/, quasar/, constraint_batch, random_lc, pipeline, scheme, linearized, accumulator, compact_instance, decider, proof, terminal_whir, union_poly) | `whir-core`, `whir-sumcheck`, `whir-spartan`, `whir-commit` |
| **`whir-ivc`** | `ivc/` | all four above |
| **`whir-cp-snark`** | `cp_snark/` (symphony-gated) | `whir-core`, `whir-commit`; `symphony` + `sha2` |
| **`whir-p3-bins`** | `src/bin/*` (12 bins) + `benches/*` (7 benches) | all library crates |

Granularity rationale: each library crate corresponds to one self-contained protocol component. Finer splits (e.g., `whir-poly` separate from `whir-circuit`) produce tiny crates with shared trait bounds and zero compile-time benefit — `whir-core` bundles the foundation accordingly. The Spartan↔Sumcheck↔WHIR triangle is the real re-use boundary and gets three crates.

## Root `Cargo.toml`

```toml
[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.package]
edition = "2024"
rust-version = "1.93"

[workspace.dependencies]
# Single pin for every p3-* crate (currently rev "c38eb05")
p3-field = { git = "https://github.com/Plonky3/Plonky3.git", rev = "c38eb05" }
# ... p3-dft, p3-koala-bear, p3-koala-bear, p3-mersenne-31, p3-goldilocks,
#     p3-merkle-tree, p3-symmetric, p3-matrix, p3-commit, p3-util,
#     p3-maybe-rayon, p3-interpolation, p3-challenger, p3-multilinear-util,
#     p3-keccak, p3-poseidon2, p3-mds
serde = { version = "1.0", default-features = false, features = ["derive", "alloc"] }
thiserror = { version = "2.0", default-features = false }
itertools = { version = "0.14.0", default-features = false, features = ["use_alloc"] }
hashbrown = "0.16"
libm = "0.2.15"
rand = { version = "0.10", default-features = false }
tracing = { version = "0.1.37", default-features = false, features = ["attributes"] }
serde_json = "1.0"

[workspace.lints]
# lift the entire current [lints] block from Cargo.toml
```

Bin-only deps (`clap`, `tracing-subscriber`, `tracing-forest`, `bincode`, `criterion`, `proptest`) stay inside `whir-p3-bins`.

## Feature Flags

- `parallel` — declared in every library crate, forwards to `p3-maybe-rayon/parallel` and optional `rayon`. `whir-p3-bins` enables by default.
- `bench-timing` — declared only in crates with `#[cfg(feature = "bench-timing")]` blocks (`whir-sumcheck`, `whir-commit`, `whir-accumulation`, `whir-ivc`). `whir-p3-bins` aggregates.
- `cli` — only in `whir-p3-bins`.
- `symphony` — only in `whir-cp-snark`; `whir-p3-bins` re-exposes it for `cp_snark_bench`.
- `default-run = "main"` moves to `whir-p3-bins/Cargo.toml`.

## Prelude Modules (one per library crate)

Content mirrors the current exported API; no rewrites.

- `whir-core::prelude` — `Field`/`ExtensionField` re-exports, `MultilinearPoint`, `EvaluationsList`, `Statement`, `ProverState`/`VerifierState`, `DomainSeparator`, sponge constructors.
- `whir-sumcheck::prelude` — `SumcheckProver`, `SumcheckPolynomial`, `ProductPolynomial`, `Svo`.
- `whir-spartan::prelude` — `R1CS`, `R1CSProof`, `SparkCommitment`, `SpartanProver`, `SpartanVerifier`.
- `whir-commit::prelude` — `Whir`, `WhirProof`, `WhirConfig`, `Committer`, `Prover`, `Verifier`, `Constraint`.
- `whir-accumulation::prelude` — `Accumulator`, `AccumulationScheme`, `Pipeline`, `WarpProof`, `QuasarProof`, `Decider`.
- `whir-ivc::prelude` — `Ivc`, `IvcStep`, `WarpIvc`, `UnifiedIvc`, `FoldVerifierCircuit`.
- `whir-cp-snark::prelude` — `CpSnark`, `CpSnarkProof`.

## File Splits (no code rewrites — `mod.rs` façade re-exports)

- `src/ivc/warp_ivc.rs` → `crates/whir-ivc/src/warp/{mod.rs, prover.rs, verifier.rs, folding.rs, setup.rs, proof.rs}`.
- `src/poly/evals.rs` → `crates/whir-core/src/poly/evals/{mod.rs, fold.rs, eval.rs, arithmetic.rs, conversion.rs, parallel.rs}`.
- `src/spartan/r1cs_prover.rs` → `crates/whir-spartan/src/r1cs_prover/{mod.rs, setup.rs, rounds.rs, spark.rs, witness.rs}`.
- `src/ivc/warp_fold_verifier_circuit.rs` → `crates/whir-ivc/src/warp_fold_verifier/{mod.rs, circuit.rs, gadgets.rs, sumcheck.rs}`.
- `src/sumcheck/product_polynomial.rs` → `crates/whir-sumcheck/src/product_polynomial/{mod.rs, poly.rs, prover.rs, verifier.rs, tests.rs}`.

## Migration Order (each step is one commit; `cargo check --workspace` gates the next)

1. Create workspace skeleton: root `Cargo.toml`, empty `crates/*`, keep current `src/` as temporary `whir-p3-legacy` member so CI stays green.
2. Extract **`whir-core`** (leaves: parameters, fiat_shamir, poly, circuit, utils, constant). Verify: `cargo check -p whir-core`.
3. Extract **`whir-sumcheck`**. The stray `use crate::whir::constraints::...` inside a `#[cfg(test)]` block in `sumcheck/product_polynomial.rs:973` is resolved in step 5.
4. Extract **`whir-commit`**.
5. Add `dev-dependencies.whir-commit = { path = "../whir-commit" }` to `whir-sumcheck` for the test leak; run `cargo test -p whir-sumcheck`.
6. Extract **`whir-spartan`** → **`whir-accumulation`** → **`whir-ivc`** → **`whir-cp-snark`** (symphony-gated) in that order.
7. Move all `src/bin/*` + `benches/*` into `whir-p3-bins`; delete `whir-p3-legacy`.
8. Apply file splits (section "File Splits") after all crates compile, isolating churn.
9. Add `prelude` modules last, once APIs have settled.

## Risks & Friction

- **Plonky3 rev duplication** → solved by `[workspace.dependencies]` single pin.
- **Sumcheck→whir test leak** (`sumcheck/product_polynomial.rs:973`) → dev-dep cycle is legal in Cargo.
- **Trait-bound proliferation** crossing crate boundaries → introduce trait aliases in `whir-core::prelude` (e.g. `pub trait WhirField: Field + TwoAdicField + Serialize + ...`).
- **Serde `alloc` feature** must be consistent across all crates or `no_std` breaks → enforce via `serde.workspace = true`.
- **`bench-timing`** cfg blocks need the feature declared in every crate that uses them, else they become dead code after unification.
- **`default-run = "main"`** moves to `whir-p3-bins`.

## Critical Files

- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/Cargo.toml` — replaced by workspace root.
- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/src/lib.rs` — split per-crate.
- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/src/accumulation/mod.rs` — becomes `crates/whir-accumulation/src/lib.rs`.
- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/src/ivc/warp_ivc.rs` — split (section above).
- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/src/sumcheck/product_polynomial.rs` — split + test-leak fix.
- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/src/poly/evals.rs` — split.
- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/src/spartan/r1cs_prover.rs` — split.
- `/Users/paul/Documents/EPFL/MA-2/MSP/whir-p3/src/ivc/warp_fold_verifier_circuit.rs` — split.

## Verification (end-to-end)

1. **Baseline first**: on current `main`, record `cargo test --workspace 2>&1 | tee baseline-tests.txt` and the test count (claimed ~389).
2. After each migration step: `cargo check --workspace` must pass.
3. After full migration:
   - `cargo build --workspace --all-features`
   - `cargo build --workspace --no-default-features` (checks `no_std` integrity)
   - `cargo test --workspace` — pass count matches baseline.
   - `cargo run -p whir-p3-bins --bin main --features cli -- <fixed args>` byte-identical vs. baseline on a seeded run.
   - `cargo bench --workspace --no-run`.
   - `cargo build -p whir-cp-snark --features symphony` (requires sibling `../Symphony` checkout).
   - `cargo doc --workspace --no-deps` (prelude re-exports don't collide).
   - `cargo clippy --workspace --all-features -- -D warnings`.
