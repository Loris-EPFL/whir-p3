# Accumulation Scheme: Random LC + Constraint Batching Sumcheck

This document describes the changes made to the WARP-style accumulation backend in `src/accumulation/scheme.rs`, replacing **union polynomial concatenation** with **random linear combination (LC) of codewords** and a **constraint batching sumcheck**.

---

## 1. Motivation

### Previous approach (union polynomial)

Given $\ell$ accumulators with witness polynomials $f_1, \dots, f_\ell \in \mathbb{F}^{2^m}$, the old scheme constructed a **union polynomial** $U \in \mathbb{F}^{\ell \cdot 2^m}$ by concatenation:

$$
U(i, \mathbf{x}) = f_i(\mathbf{x}), \quad i \in \{0,\dots,\ell-1\}, \; \mathbf{x} \in \{0,1\}^m
$$

The combined weight table embedded each $\lambda_i$ at offset $i \cdot 2^m$ in a larger table of size $\ell \cdot 2^m$, and the batched claim was:

$$
\sum_{i=0}^{\ell-1} \gamma^i \sum_{\mathbf{b} \in \{0,1\}^m} \lambda_i(\mathbf{b}) \cdot f_i(\mathbf{b}) = \sum_{i=0}^{\ell-1} \gamma^i \sigma_i
$$

**Problem**: The witness grows by a factor of $\ell$ at each accumulation step. After $d$ steps of batch size $\ell$, the witness has size $\ell^d \cdot 2^m$ — exponential in the recursion depth.

### New approach (random linear combination)

The combined polynomial is:

$$
f = \sum_{i=0}^{\ell-1} \eta^i \cdot f_i \in \mathbb{F}^{2^m}
$$

The witness stays at size $2^m$ regardless of accumulation depth, enabling **unbounded-depth** recursive accumulation (as described in Arc/WARP).

**Challenge**: With random LC, you cannot directly express the batched claim $\sum_i \gamma^i \langle \lambda_i, f_i \rangle$ as a single linear functional on $f$, because $\langle \lambda_i, f \rangle = \sum_j \eta^j \langle \lambda_i, f_j \rangle$ has cross-terms when $i \neq j$. This is why a **constraint batching sumcheck** is needed to first reduce the individual claims to point evaluations.

---

## 2. Protocol Overview

The new accumulation protocol has five phases:

```
Input: ℓ accumulators (fᵢ, λᵢ, σᵢ, rtᵢ)
                │
    ┌───────────▼───────────┐
    │  Phase 1: Observe     │  Absorb public instances into Fiat-Shamir
    │  inputs, sample γ     │  γ ← challenger.sample()
    └───────────┬───────────┘
                │
    ┌───────────▼───────────┐
    │  Phase 2: Constraint  │  Sumcheck reduces ℓ claims to
    │  batching sumcheck    │  point evaluations fᵢ(r)
    └───────────┬───────────┘
                │
    ┌───────────▼───────────┐
    │  Phase 3: Codeword    │  f = Σ ηⁱ fᵢ  (same size)
    │  batching (random LC) │  y = Σ ηⁱ fᵢ(r)
    └───────────┬───────────┘
                │
    ┌───────────▼───────────┐
    │  Phase 4: OOD +       │  Sample z₀, evaluate f(z₀)
    │  shift queries        │  Sample indices, evaluate f
    └───────────┬───────────┘
                │
    ┌───────────▼───────────┐
    │  Phase 5: WHIR proof  │  Prove all claims on f
    │  on combined oracle   │  Output new accumulator
    └───────────┴───────────┘

Output: 1 accumulator (f, eq(r,·), y, rt)
```

---

## 3. Phase 2: Constraint Batching Sumcheck

**File**: `src/accumulation/constraint_batch.rs`

### Claim

Each input accumulator $i$ carries a linear claim:

$$
\langle \lambda_i, f_i \rangle := \sum_{\mathbf{b} \in \{0,1\}^m} \lambda_i(\mathbf{b}) \cdot f_i(\mathbf{b}) = \sigma_i
$$

The batched claim to be proved via sumcheck is:

$$
S = \sum_{i=0}^{\ell-1} \gamma^i \cdot \langle \lambda_i, f_i \rangle = \sum_{i=0}^{\ell-1} \gamma^i \cdot \sigma_i
$$

### Sumcheck rounds

The sum $S$ is over $\mathbf{b} \in \{0,1\}^m$. In round $j$ ($j = 1, \dots, m$), we fix variables $b_1, \dots, b_{j-1}$ to previously sampled challenges $r_1, \dots, r_{j-1}$ and compute the univariate polynomial:

$$
s_j(X) = \sum_{\mathbf{b}' \in \{0,1\}^{m-j}} h(r_1, \dots, r_{j-1}, X, \mathbf{b}')
$$

where:

$$
h(\mathbf{b}) = \sum_{i=0}^{\ell-1} \gamma^i \cdot \lambda_i(\mathbf{b}) \cdot f_i(\mathbf{b})
$$

Since $h$ is a sum of products of two multilinear polynomials ($\lambda_i$ and $f_i$), $s_j(X)$ is a **degree-2** univariate polynomial in $X$.

### Round polynomial representation

For each round, the prover computes and sends $[s_j(0), s_j(2)]$. The value $s_j(1)$ is derived by the verifier as:

$$
s_j(1) = \text{claimed\_sum} - s_j(0)
$$

This exploits the sumcheck invariant $s_j(0) + s_j(1) = \text{claimed\_sum}$.

### Computing $s_j(0)$ and $s_j(2)$

For each polynomial pair $(f_i, \lambda_i)$, the existing `EvaluationsList::sumcheck_coefficients` method splits the evaluation tables into "lo" and "hi" halves and computes:

$$
c_0^{(i)} = \sum_{k} \lambda_i^{\text{lo}}[k] \cdot f_i^{\text{lo}}[k]
$$
$$
c_2^{(i)} = \sum_{k} (2 \lambda_i^{\text{hi}}[k] - \lambda_i^{\text{lo}}[k]) \cdot (2 f_i^{\text{hi}}[k] - f_i^{\text{lo}}[k])
$$

Then:

$$
s_j(0) = \sum_{i=0}^{\ell-1} \gamma^i \cdot c_0^{(i)}, \quad s_j(2) = \sum_{i=0}^{\ell-1} \gamma^i \cdot c_2^{(i)}
$$

### Challenge and compression

After observing $[s_j(0), s_j(2)]$, the verifier samples $r_j \in \mathbb{EF}$. The claimed sum is updated via Lagrange interpolation at $\{0, 1, 2\}$:

$$
\text{claimed\_sum} \leftarrow s_j(0) \cdot L_0(r_j) + s_j(1) \cdot L_1(r_j) + s_j(2) \cdot L_2(r_j)
$$

where $L_k$ are the Lagrange basis polynomials for $\{0, 1, 2\}$ (implemented by `extrapolate_012`).

All polynomial and weight tables are then compressed (folded) with challenge $r_j$:

$$
f_i^{\text{new}}[k] = f_i^{\text{lo}}[k] + r_j \cdot (f_i^{\text{hi}}[k] - f_i^{\text{lo}}[k])
$$

### Final check

After $m$ rounds, each table has been compressed to a single value. The prover sends:

$$
y_i = f_i(\mathbf{r}) \quad \text{for each } i = 0, \dots, \ell-1
$$

where $\mathbf{r} = (r_1, \dots, r_m)$ is the reduction point.

The verifier checks:

$$
\sum_{i=0}^{\ell-1} \gamma^i \cdot \lambda_i(\mathbf{r}) \cdot y_i = \text{final\_claimed\_sum}
$$

where $\lambda_i(\mathbf{r})$ is computed by multilinear interpolation from the public weight tables via `evaluate_hypercube_ext`.

---

## 4. Phase 3: Codeword Batching (Random LC)

**File**: `src/accumulation/random_lc.rs`

After the constraint batching sumcheck, the prover combines the $\ell$ witness polynomials:

$$
f = \sum_{i=0}^{\ell-1} \eta^i \cdot f_i \quad \in \mathbb{F}^{2^m}
$$

where $\eta \in \mathbb{F}$ is the **codeword batching challenge** (sampled from the Fiat-Shamir challenger as a base field element to keep $f$ in $\mathbb{F}$).

The combined evaluation at the reduction point is:

$$
y = \sum_{i=0}^{\ell-1} \eta^i \cdot f_i(\mathbf{r}) = f(\mathbf{r})
$$

This evaluation claim $f(\mathbf{r}) = y$ becomes the output accumulator's constraint.

### Why two separate challenges

The protocol uses $\gamma$ for **constraint batching** and $\eta$ for **codeword batching**. These must be independent:

- $\gamma$ weights the $\ell$ sumcheck claims and is used before the codeword combination
- $\eta$ weights the $\ell$ oracles and determines the combined polynomial $f$

Using the same challenge for both would create an algebraic dependency that could compromise soundness.

---

## 5. Output Accumulator

The output accumulator stores:

| Field | Value | Description |
|-------|-------|-------------|
| `commitment_root` | `merkle_root(f)` | WHIR Merkle commitment to the combined polynomial |
| `linear_claim.weights[0]` | $\text{eq}(\mathbf{r}, \cdot) \in \mathbb{EF}^{2^m}$ | Equality polynomial at the reduction point |
| `linear_claim.evaluations[0]` | $y = \sum_i \eta^i f_i(\mathbf{r})$ | Expected evaluation |
| `witness.poly` | $f = \sum_i \eta^i f_i \in \mathbb{F}^{2^m}$ | The combined polynomial (prover only) |

The evaluation claim $f(\mathbf{r}) = y$ is expressed as a `LinearStatement` with weight $\text{eq}(\mathbf{r}, \cdot)$ and target $y$, using:

$$
f(\mathbf{r}) = \sum_{\mathbf{b} \in \{0,1\}^m} \text{eq}(\mathbf{r}, \mathbf{b}) \cdot f(\mathbf{b}) = y
$$

This is constructed via `EvaluationsList::new_from_point(r, 1)`.

### Decider compatibility

The decider (`decide_linearized_accumulator`) verifies:

$$
\sum_{\mathbf{b}} \lambda(\mathbf{b}) \cdot f(\mathbf{b}) \stackrel{?}{=} \sigma
$$

For the output accumulator with $\lambda = \text{eq}(\mathbf{r}, \cdot)$ and $\sigma = y$, this reduces to checking $f(\mathbf{r}) = y$, which is correct by construction.

---

## 6. Fiat-Shamir Transcript

The complete Fiat-Shamir transcript for the accumulation protocol:

```
Observe: commitment_root[0], ..., commitment_root[ℓ-1]
Observe: target[0], ..., target[ℓ-1]
                                                    ──► Sample: γ (constraint batching)

For round j = 1, ..., m:
  Observe: [s_j(0), s_j(2)]
                                                    ──► Sample: r_j (sumcheck challenge)

Observe: f₀(r), f₁(r), ..., f_{ℓ-1}(r)
                                                    ──► Sample: η (codeword batching)

[WHIR commitment phase begins here]
                                                    ──► Sample: ood_point coordinates
                                                    ──► Sample: shift_query_indices

[WHIR proof continues with its own transcript]
```

### Transcript data stored in proof

The `AccumulationTranscript` stores:

| Field | Type | Source |
|-------|------|--------|
| `constraint_batching_challenge` | `F` | Derived (verified by verifier) |
| `constraint_batch_proof.round_polys` | `Vec<[EF; 2]>` | Prover message |
| `constraint_batch_proof.individual_evals` | `Vec<EF>` | Prover message |
| `codeword_batching_challenge` | `F` | Derived (verified by verifier) |
| `ood_point` | `MultilinearPoint<EF>` | Derived (verified by verifier) |
| `ood_answer` | `EF` | Prover message |
| `shift_query_indices` | `Vec<usize>` | Derived (verified by verifier) |
| `shift_query_answers` | `Vec<EF>` | Prover message |

---

## 7. Comparison: Old vs New

| Aspect | Union Polynomial (old) | Random LC (new) |
|--------|----------------------|-----------------|
| Combined poly size | $\ell \cdot 2^m$ | $2^m$ |
| Witness growth per step | $\times \ell$ | $\times 1$ (constant) |
| After $d$ steps | $\ell^d \cdot 2^m$ | $2^m$ |
| Max recursion depth | Bounded (exponential growth) | **Unbounded** |
| Constraint batching | Direct LC of weight tables | **Sumcheck** (new Phase 2) |
| WhirConfig `num_variables` | $m + \log_2 \ell$ | $m$ (same as input) |
| Soundness basis | Embedding correctness | Mutual correlated agreement |
| Cross-term handling | None (union avoids them) | Sumcheck eliminates them |

---

## 8. Files Modified

| File | Change |
|------|--------|
| `src/accumulation/random_lc.rs` | **New.** Random linear combination utility. |
| `src/accumulation/constraint_batch.rs` | **New.** Constraint batching sumcheck (prover + verifier). |
| `src/accumulation/proof.rs` | **Modified.** `AccumulationTranscript` now has two-phase structure. |
| `src/accumulation/scheme.rs` | **Rewritten.** Prover and verifier use random LC + sumcheck. |
| `src/accumulation/mod.rs` | **Modified.** Added `random_lc` and `constraint_batch` modules. |
| `src/accumulation/quasar/frontend.rs` | **Modified.** Integration test uses `num_variables` (not `+1`). |
