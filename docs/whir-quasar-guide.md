# Connecting WHIR and Quasar: Building WHIR-Based Accumulation

## 1. Overview

This document explains how to use **WHIR** (a Reed–Solomon IOPP / multilinear PCS with super-fast verification) as the polynomial commitment scheme inside **Quasar** (a multi-instance accumulation scheme with sublinear verifier complexity). The combination yields a hash-based, plausibly post-quantum accumulation scheme with:

- **Sublinear CRC operations** in the recursive circuit (O(1) per step instead of O(ℓ))
- **Fast verification** inherited from WHIR (~hundreds of μs for evaluation proofs)
- **Transparent setup** (no trusted ceremony)
- **Plausible post-quantum security** (hash-based assumptions only)

---

## 2. Background: What Each Piece Does

### 2.1 WHIR

WHIR (Arnon–Chiesa–Fenzi–Yogev, 2024) is an **IOP of proximity for constrained Reed–Solomon codes** that doubles as a multilinear PCS.

**Key properties:**
- Commits to a multilinear polynomial `f ∈ F^{<2}[X₁,…,Xₘ]` by Reed–Solomon encoding it over a foldable domain `L` and Merkle-committing the codeword.
- Supports **weighted sum queries**: given a weight polynomial `w(z, X)`, proves `Σ_{b ∈ {0,1}^m} w(f(b), b) = σ`. This captures multilinear evaluation as a special case via `w(z, X) = z · eq(X, r)`.
- Verification time: ~300–600 μs at 100-bit security for degree 2²².
- Proof size: 36–123 KiB depending on rate ρ and security level.
- Prover: quasi-linear (dominated by FFTs for RS encoding).
- Hash-based, transparent, plausibly post-quantum.

### 2.2 Quasar

Quasar (Zheng–Gao–Guo–Xiao, 2025) is a **multi-instance accumulation scheme** for polynomial commitment schemes, constructing a multi-instance IVC.

**Key properties:**
- Accumulates ℓ predicate instances + 1 accumulator into a new accumulator.
- Verifier performs **O(1) CRC operations** per step (vs O(ℓ) in ProtoGalaxy/KiloNova).
- Total CRC across all N steps: O(√N) instead of O(N).
- Built from two components: **NIR_multicast** (multi-cast reduction) and **NIR_fold** (2-to-1 reduction).
- Generic over the PCS: works with curve-based or code-based commitments.

---

## 3. Why WHIR Fits Quasar

Quasar's code-based instantiation ("Quasar (code)") requires a PCS satisfying:

| Requirement | WHIR Capability |
|---|---|
| Multilinear polynomial commitments | ✅ Native multilinear PCS |
| Extractability (knowledge soundness) | ✅ Via Merkle commitments + Fiat–Shamir in ROM |
| Oracle batching with succinctness | ✅ Via WHIR's constrained RS proximity testing |
| Hash-based / post-quantum | ✅ Only symmetric-key assumptions |
| Evaluation proofs for `p̃(r) = v` | ✅ Via weighted sum with `w(z,X) = z · eq(X,r)` |

The critical interface is the **oracle batching protocol** (Definition 5 in Quasar). WHIR can instantiate this because:

1. WHIR reduces proximity claims on multiple codewords to a single proximity claim on a combined codeword.
2. The batching proof is **sublinear** in the polynomial/codeword size — satisfying the succinctness requirement that makes Quasar's verifier sublinear.

---

## 4. Architecture: How the Pieces Connect

```
┌─────────────────────────────────────────────────┐
│                   Quasar IVC                     │
│                                                  │
│  ┌──────────────┐    ┌──────────────┐            │
│  │  NIR_multicast│───▶│   NIR_fold   │            │
│  │  (multi-cast  │    │  (2-to-1     │            │
│  │   reduction)  │    │   reduction) │            │
│  └──────┬───────┘    └──────┬───────┘            │
│         │                    │                    │
│         ▼                    ▼                    │
│  ┌─────────────────────────────────────┐         │
│  │     Oracle Batching (NIR_batch)     │         │
│  │     ─────────────────────────       │         │
│  │     Instantiated with WHIR          │         │
│  │                                     │         │
│  │  • Codeword batching via RS folding │         │
│  │  • Out-of-domain sampling           │         │
│  │  • Merkle commitment to codewords   │         │
│  └─────────────────────────────────────┘         │
│                                                  │
│  Predicate: HyperPlonk (multilinear plonkish)    │
│  Commitment: WHIR (RS codes + Merkle trees)      │
└─────────────────────────────────────────────────┘
```

### 4.1 Data Flow at Each IVC Step

1. **Generate ℓ predicate instances** from computation chunks, each producing a witness `w⁽ᵏ⁾`.
2. **NIR_multicast**: Commit to the union polynomial `w̃_∪(Y,X)` encoding all ℓ witnesses via WHIR (RS-encode and Merkle-commit). Run sum-check to reduce ℓ constraint checks to one evaluation claim.
3. **NIR_fold**: Merge the new committed instance with the running accumulator. Run a 1-round sum-check, then invoke **NIR_batch** (oracle batching) to combine oracles.
4. **NIR_batch (WHIR)**: This is the key interface point — use WHIR's codeword batching to combine two RS codewords into one, preserving proximity and evaluation claims.
5. **Output**: A new accumulator `acc'` and proof `pf`.

---

## 5. Instantiating NIR_batch with WHIR

This is the core technical connection. Quasar's oracle batching protocol (Definition 5) requires:

**Input:** Randomness `r ∈ F`, two polynomial oracles `[[f̃₀]], [[f̃₁]]` with a batched evaluation claim `Σ eq̃ᵢ(r) · f̃ᵢ(x) = v`.

**Output:** A single oracle `[[f̃]]` with evaluation claims `f̃(xⱼ) = vⱼ`.

**Required property:** The proof `π_batch` must be **sublinear** in |f̃|.

### WHIR-based instantiation:

1. **Encode** each polynomial `f̃ᵢ ∈ F^{<2}[X]` as an RS codeword `uᵢ = C(fᵢ)` over domain `L`.
2. **Commit** each codeword via Merkle tree (this is already done from the accumulator state).
3. **Batch the codewords**: Compute `u = γ₁·u₁ + γ₂·u₂` and commit to it.
4. **Out-of-domain sampling**: The verifier sends random challenges `α₁,…,αₛ ∈ F^{log n} \ {0,1}^{log n}`. The prover responds with evaluations `ũ(αⱼ)` of the multilinear extension.
5. **In-domain spot checks**: The verifier queries `u₁, u₂, u` at random positions `b₁,…,bₜ ∈ L` and checks consistency: `γ₁·u₁(bⱼ) + γ₂·u₂(bⱼ) = u(bⱼ)`.
6. **Output**: New evaluation claims on `ũ` and the oracle `[[ũ]]`.

**Succinctness**: The proof consists of `s` field elements (out-of-domain evaluations) + `t` Merkle authentication paths. Both `s` and `t` are `O(λ / log(1/ρ))`, independent of the polynomial size — satisfying the sublinearity requirement.

### Handling the systematic code assumption

Quasar (Section 6.2) assumes the code is **systematic** (first `k` entries of `C(x)` equal `x`). Standard RS codes over smooth domains are systematic. When using WHIR:

- If WHIR uses a standard RS encoding over a foldable domain `L`, the multilinear extension of the codeword `ũᵢ(Y, X)` decomposes as `eq̃₀(Y)·f̃ᵢ(X) + [redundancy terms]`.
- An evaluation claim `f̃ᵢ(x) = vᵢ` lifts to `ũᵢ(0, x) = vᵢ`, which WHIR can verify as a weighted sum query.

---

## 6. Verifier Cost Analysis

For `ℓ` accumulated instances with witness length `n` and code rate `ρ`:

| Component | Cost |
|---|---|
| Sum-check (multi-cast) | O(log ℓ) field ops + O(log ℓ) RO queries |
| Sum-check (fold) | O(d) field ops |
| Instance accumulation `x̃(τ)` | O(ℓ · m) field ops |
| **Oracle batching (WHIR)** | **O(λ/log(1/ρ) · (log n + log ℓ)) RO queries** |
| CRC operations | **O(1)** — independent of ℓ |

Compare with prior code-based schemes:

| Scheme | Verifier RO queries | CRC / Group ops |
|---|---|---|
| Arc (RS codes) | O(ℓ · λ/log(1/ρ) · log n) | — |
| WARP (linear codes) | O(ℓ · λ/log(1/ρ) · log n) | — |
| **Quasar + WHIR** | **O(λ/log(1/ρ) · (log n + log ℓ))** | **O(1)** |

The key improvement: the `ℓ` factor moves inside a logarithm.

---

## 7. Comparison with Related Approaches

### Quasar + WHIR vs. WARP

- **WARP** achieves linear prover time with general linear codes and a novel straightline extractor based on erasure correction. It works with *any* linear code.
- **Quasar + WHIR** specifically leverages RS structure (foldable domains, weighted sums) for faster verification, but the prover is quasi-linear due to RS encoding FFTs.
- If linear prover time is the priority, WARP (or Quasar instantiated with a linear-time-encodable code like Brakedown/Spielman codes) is preferable.
- If verifier speed is the priority, WHIR's ~300 μs verification makes it attractive.

### Quasar + WHIR vs. BOIL

- **BOIL** uses a split accumulation approach with STIR-inspired oracle batching, deferring proximity testing to the end.
- **Quasar + WHIR** takes a different structural approach: sublinear multi-cast reduction via union polynomials, with WHIR handling the oracle batching.
- BOIL supports Plonkish arithmetization natively; Quasar also targets Plonkish (HyperPlonk).

---

## 8. Implementation Considerations

### 8.1 Choosing Parameters

- **Rate ρ**: Lower rates (e.g., 1/8 or 1/16) reduce WHIR proof size and verifier hash complexity at the cost of larger codewords (more prover work). For accumulation, lower ρ is generally better since the oracle batching proof shrinks.
- **Folding parameter k**: Controls rounds vs. per-round work in WHIR. Typical choice: k = 4 or k = log(m)/2.
- **Security parameter λ**: Determines number of out-of-domain samples `s ≈ λ / log|F|` and spot checks `t ≈ λ / (-log(1-δ))`.
- **Accumulation width ℓ**: Trade off between fewer IVC steps (larger ℓ) and recursive circuit size. Quasar's O(1) CRC means you can push ℓ higher than with ProtoGalaxy.

### 8.2 Recursive Circuit Impact

The recursive circuit at each step contains:
- **Computation trace**: The predicate φ for ℓ chunks.
- **Accumulation verifier trace**: O(ℓ) field operations + O(1) CRC operations + hash operations for Fiat–Shamir.
- **Accumulator compression**: Hash the accumulator for the next step.

With WHIR, the "CRC" operations become Merkle path verifications (hash operations), which are natively efficient in the recursive circuit when using algebraic hashes (Poseidon, Rescue, etc.).

### 8.3 Hash Function Choice

WHIR commits via Merkle trees. For recursion-friendliness:
- Use **Poseidon** or **Monolith** for the Merkle hash (circuit-friendly).
- The cost of verifying Merkle paths inside the recursive circuit dominates the recursion overhead.
- WHIR's low query complexity (small `t`) directly reduces the number of Merkle paths the recursive circuit must verify.

---

## 9. Open Questions and Caveats

1. **Linear-time prover**: WHIR uses RS codes, which require FFTs for encoding → quasi-linear prover. To get a truly linear-time prover with Quasar, use a linear-time-encodable code (e.g., expander codes as in WARP) instead of WHIR. This sacrifices WHIR's verification speed.

2. **Multiple accumulators (PCD)**: Quasar explicitly leaves sublinear-verifier PCD (multiple accumulators, not just multiple instances) as an open problem (footnote 4 in the paper). WHIR doesn't resolve this.

3. **Soundness in list-decoding regime**: WHIR supports proximity bounds up to `1 - √ρ` (or `1 - ρ` under RS decoding conjectures). Ensure the Quasar proximity parameters are compatible with WHIR's soundness analysis.

4. **Extraction model**: Quasar uses round-by-round (RBR) knowledge soundness. WHIR's RBR soundness analysis (via STIR/BaseFold lineage) must be verified to compose correctly. WARP introduced a variant of straightline RBR-KS specifically for this — check whether WHIR's extraction strategy (which historically relies on rewinding in some formulations) is compatible with Quasar's straightline requirements.

5. **Concrete benchmarks**: No published implementation of Quasar + WHIR exists yet. The theoretical analysis is promising, but concrete performance depends heavily on hash choice, field size, and circuit framework.

---

## 10. Summary: Recipe for WHIR Accumulation via Quasar

1. **Choose your NARK**: HyperPlonk (multilinear plonkish constraints) with WHIR as the PCS.
2. **Build NIR_multicast**: Follow Quasar Section 5.1 — interleave the SPS protocol with the multi-cast reduction, committing union polynomials via WHIR.
3. **Build NIR_fold**: Follow Quasar Section 5.2 / Construction 1 — use a 1-round sum-check and invoke NIR_batch.
4. **Instantiate NIR_batch with WHIR**: Implement the codeword batching protocol (Quasar Figure 14 / Section 6.2) using WHIR's RS proximity testing with out-of-domain sampling and spot checks.
5. **Compose into IVC**: Follow Quasar Section 6 — the recursive circuit verifies the accumulation step (O(ℓ) field ops + O(1) Merkle path checks + Fiat–Shamir hashes).
6. **Verify at the end**: Run the WHIR evaluation proof (decider) on the final accumulator.

---

## References

- **Quasar**: Zheng, Gao, Guo, Xiao. "Quasar: Sublinear Accumulation Schemes for Multiple Instances." 2025.
- **WHIR**: Arnon, Chiesa, Fenzi, Yogev. "WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification." EUROCRYPT 2025. [eprint 2024/1586](https://eprint.iacr.org/2024/1586)
- **WARP**: Bünz, Chiesa, Fenzi, Wang. "Linear-Time Accumulation Schemes." 2025. [eprint 2025/753](https://eprint.iacr.org/2025/753)
- **BOIL**: Kattis, Nadeau, Bhavsar. "BOIL: Proof-Carrying Data from Accumulation of Correlated Holographic IOPs." 2024. [eprint 2024/1993](https://eprint.iacr.org/2024/1993)
- **ProtoGalaxy**: Eagen, Gabizon. "ProtoGalaxy: Efficient ProtoStar-style Folding of Multiple Instances." 2023.
- **Whirlaway**: Lambda Class. "Whirlaway: Multilinear STARKs using WHIR as PCS." 2024.
