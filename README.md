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

### Benchmarking No-Fold vs Raw Fold vs Quasar+WARP

The current prototype supports three benchmark modes over synthetic R1CS instances:

- `no_fold`: prove and verify all fresh claims independently with Spartan+WHIR
- `raw_fold`: send fresh claims directly into the current WARP-style folded WHIR backend
- `quasar_warp`: first squash fresh claims with the new Quasar frontend, then feed the squashed object into the existing WARP-style folded WHIR backend

For the fixed Criterion benchmark:

```bash
cargo bench --bench accumulation
```

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

### Configurable Large Accumulation Benchmarks

For larger matrix sizes and configurable claim counts, use the standalone benchmark runner instead of the Criterion bench.

This runner supports CLI flags and has sensible defaults if you do not pass any arguments.

Basic run:

```bash
cargo run --release --features cli --bin accumulation_bench
```

This defaults to:
- `--sizes 8,10`
- `--claims 2,4`
- `--repeats 10`
- `--shift-queries 2`
- `--folding-factor 2`
- `--folding-schedule <unset>`
- `--starting-log-inv-rate 1`
- `--rs-domain-initial-reduction-factor 1`
- `--security-level 100`

`--folding-schedule` supports the folding modes already available in this repo:
- `--folding-schedule 4` means constant folding factor 4 in all rounds
- `--folding-schedule 6,4` means first round uses 6, later rounds use 4

If `--folding-schedule` is provided, it overrides `--folding-factor`.

Example with larger matrices:

```bash
cargo run --release --features cli --bin accumulation_bench -- \
  --sizes 12,14 \
  --claims 2,4,8 \
  --repeats 20 \
  --folding-factor 2 \
  --starting-log-inv-rate 1 \
  --rs-domain-initial-reduction-factor 1 \
  --shift-queries 2
```

Example with an even longer run for a single sweep:

```bash
cargo run --release --features cli --bin accumulation_bench -- \
  --sizes 14 \
  --claims 2,4,8 \
  --repeats 50 \
  --folding-factor 2 \
  --starting-log-inv-rate 1 \
  --rs-domain-initial-reduction-factor 1 \
  --shift-queries 2
```

The runner writes a CSV file by default to:

```text
output/benchmarks/accumulation/custom_metrics.csv
```

The CSV now contains timing columns for all three modes:

- `no_fold_prove_ms`
- `no_fold_verify_ms`
- `raw_fold_prove_ms`
- `raw_fold_verify_ms`
- `quasar_warp_prove_ms`
- `quasar_warp_verify_ms`

You can override that path with:

```bash
--out output/benchmarks/accumulation/my_run.csv
```

Recommended commands for longer accumulation measurements:

```bash
cargo run --release --features cli --bin accumulation_bench -- --sizes 12 --claims 2,4,8 --repeats 20
cargo run --release --features cli --bin accumulation_bench -- --sizes 14 --claims 2,4 --repeats 20
cargo run --release --features cli --bin accumulation_bench -- --sizes 14 --claims 2,4,8 --repeats 50
```

Example exploring stronger WHIR folding for the folded path while keeping the same benchmark harness:

```bash
cargo run --release --features cli --bin accumulation_bench -- \
  --sizes 14 \
  --claims 2,4,8 \
  --repeats 20 \
  --folding-factor 4 \
  --starting-log-inv-rate 1 \
  --rs-domain-initial-reduction-factor 1
```

Example exploring a non-constant WHIR folding schedule:

```bash
cargo run --release --features cli --bin accumulation_bench -- \
  --sizes 14 \
  --claims 2,4,8 \
  --repeats 20 \
  --folding-schedule 6,4 \
  --starting-log-inv-rate 1 \
  --rs-domain-initial-reduction-factor 1
```

### Architecture Summary

The current codebase now has a two-layer accumulation structure:

1. `Quasar` frontend in `src/accumulation/quasar/`
   - squashes many fresh linearized instances into one squashed committed object
2. existing `WARP-style` folded WHIR backend in `src/accumulation/scheme.rs`
   - folds committed accumulator-style objects and proves them with WHIR

The new Quasar frontend is intentionally implemented as a separate layer so it can reuse the backend unchanged.

### LinearStatement vs PESAT: Design Note

The academic papers (WARP, Quasar) describe accumulation over general **PESAT** (Polynomial Equation SATisfiability) relations of the form:

```
P*(β, w) = η
```

where `P*` is an arbitrary polynomial constraint map. However, this implementation uses **`LinearStatement`** which represents simpler inner-product claims:

```
⟨weights, polynomial_evaluations⟩ = target
```

**Why this is sufficient for R1CS/Spartan:**

The Spartan proving system reduces R1CS satisfiability to a set of *linearized claims* after the sumcheck protocol. These linearized claims are precisely inner-product relations:

1. **Witness evaluation claim**: `⟨eq(ry, ·), z⟩ = z_eval` where `z` is the extended witness
2. **Matrix-vector claims**: `⟨Ã(rx, ·), z⟩ = a_eval`, `⟨B̃(rx, ·), z⟩ = b_eval`, `⟨C̃(rx, ·), z⟩ = c_eval`

These four claims are batched into a single `LinearStatement` using a random challenge. The key insight is:

- **General PESAT** → after linearization → **Inner-product claims** → `LinearStatement`

Therefore, `LinearStatement` is the correct abstraction for accumulating Spartan proofs. The WARP/Quasar soundness arguments apply because:

1. Inner-product claims are a special case of PESAT (degree-1 polynomial constraints)
2. The batching and folding operations preserve the linear structure
3. The terminal decider verifies the final inner-product claim via WHIR

This design choice simplifies the implementation while maintaining full compatibility with R1CS-based proof systems. For constraint systems that produce non-linear claims after the sumcheck phase, the `LinearStatement` abstraction would need to be generalized to full PESAT.

### Paper Alignment Analysis

This section documents how the implementation aligns with (and deviates from) the original papers: **WARP**, **Quasar**, and **Symphony**.

#### WARP Paper Alignment

The WARP paper (Bünz et al.) describes an accumulation scheme using:

| WARP Paper Concept | Implementation | Status |
|---|---|---|
| **Twin constrained codes** `C[(α, μ), (Pb, β, η)]` | `LinearStatement` (inner-product claims only) | ✅ Simplified - sufficient for R1CS |
| **Codeword batching** (§2.4) | `union_polynomial_from_accumulators` + exponential batching | ✅ Implemented (uses `r⁰, r¹, r², ...` weights) |
| **Twin constraint pseudo-batching** (§2.6) | Implicit via `LinearStatement` batching | ⚠️ Simplified - no explicit affine interpolation |
| **Out-of-domain sampling** | `ood_point`, `ood_answer` in `AccumulationTranscript` | ✅ Implemented |
| **Shift queries** (in-domain sampling) | `shift_query_indices`, `shift_query_answers` | ✅ Implemented |
| **Straightline extraction via erasure** | Relies on WHIR's extraction | ✅ Inherited from WHIR |

**Key Deviation**: The WARP paper uses **affine interpolation** `(1-γ)·f₀ + γ·f₁` for twin constraint pseudo-batching (Construction 3, §2.6). Our implementation uses **exponential batching** `Σᵢ rⁱ·fᵢ` which is equivalent in soundness but differs in the algebraic structure. This is a valid simplification for the 2-to-1 case.

#### Quasar Paper Alignment

The Quasar paper (Zheng et al.) describes a multi-instance accumulation scheme:

| Quasar Paper Concept | Implementation | Status |
|---|---|---|
| **Union polynomial** `w̃∪(Y,X) = Σₖ eq̃ₖ₋₁(Y)·w̃⁽ᵏ⁾(X)` | `build_union_polynomial` (concatenation layout) | ✅ Implemented |
| **Multi-cast reduction** (ℓ→1) | `QuasarFrontendProver::squash_to_accumulator` | ✅ Implemented |
| **eq-polynomial weighting** `eq̃ₖ₋₁(τ)` | `eq_weights` function | ✅ Implemented |
| **Partial evaluation check** `w̃∪(τ, rx) = w̃(rx)` | Implicit via target verification | ⚠️ Simplified |
| **Sublinear verifier** (O(log ℓ) CRCs) | Current impl is O(ℓ) linear claims | ⚠️ Not optimized |
| **Sumcheck over Y hypercube** | Direct target computation | ⚠️ Simplified |

**Key Simplification**: The Quasar paper's full protocol runs a sumcheck over the instance-index hypercube Y to reduce to a single evaluation claim. Our `QuasarFrontendProver` simplifies this by:
1. Computing eq-weights directly from `τ`
2. Squashing witnesses via linear combination
3. Verifying the target relationship algebraically

This achieves the same soundness but doesn't provide the sublinear verifier complexity that Quasar optimizes for. For our use case (feeding into WARP backend), this is acceptable.

#### Symphony Paper Alignment

The Symphony paper (Chen) describes a CP-SNARK wrapper for avoiding Fiat-Shamir circuits:

| Symphony Paper Concept | Implementation | Status |
|---|---|---|
| **High-arity folding** (compress ℓnp statements) | Quasar frontend | ✅ Analogous |
| **Commit-and-prove compiler** (§6) | Not yet implemented | 🔴 Phase 4 TODO |
| **Fiat-Shamir in circuit avoidance** | Current design uses standard FS | 🔴 Phase 4 TODO |
| **CP-SNARK relation Rcp** (Eq. 55) | Would wrap accumulation transcript | 🔴 Phase 4 TODO |
| **Two-layer folding** (§8) | Quasar→WARP is 2-layer | ✅ Conceptually aligned |

**Phase 4 Work Required**: To complete Symphony alignment, we need:
1. A CP-SNARK that proves the folding verifier's transcript is correctly computed
2. Commitment to prover messages `(mᵢ)` during accumulation
3. Final SNARK proof for the output relation `Ro`

The current `TerminalDecider` uses WHIR to prove the final accumulator, but doesn't wrap the Fiat-Shamir transcript in a CP-SNARK. This is the main gap for full Symphony compliance.

#### Implementation vs Paper Summary

| Component | Papers | Implementation | Gap |
|---|---|---|---|
| **Accumulator structure** | Twin constraints (α,μ) + PESAT (β,η) | `LinearStatement` only | Acceptable for R1CS |
| **Batching method** | Affine interpolation | Exponential batching | Equivalent soundness |
| **Quasar reduction** | Full sumcheck over Y | Direct eq-weighting | Acceptable |
| **Symphony wrapper** | CP-SNARK + SNARK | WHIR proof only | **Phase 4 TODO** |
| **Extraction** | Straightline erasure-based | WHIR's extraction | Inherited |

The implementation is **sound and functional** for the current use case (R1CS/Spartan accumulation), with the main remaining work being the Symphony CP-SNARK wrapper for Phase 4.
