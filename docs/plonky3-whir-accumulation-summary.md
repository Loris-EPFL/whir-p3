# WHIR Accumulation: Hurdles, Elements & Equations
## Building on whir-p3 (Plonky3) + Spartan → Quasar/WARP Accumulation

---

## 1. Your Current Stack

```
┌─────────────────────────────────────────────────────────┐
│                  Current: whir-p3 + Spartan              │
│                                                          │
│  Arithmetization:  CCS (via Spartan / SuperSpartan)      │
│  PCS:              WHIR (whir-p3, Plonky3 field crates)  │
│  Fields:           KoalaBear / KoalaBear / Mersenne31     │
│  Hashing:          Poseidon2 (circuit-friendly)          │
│  Proof structure:  Sumcheck + WHIR proximity testing     │
│  Inspiration:      Whirlaway (SuperSpartan + WHIR)       │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Target: WHIR Accumulation Scheme             │
│                                                          │
│  Framework:  Quasar (sublinear multi-instance acc.)      │
│  Extraction: WARP (straightline RBR-KS for RS codes)     │
│  PCS:        WHIR (reuse your whir-p3 implementation)    │
│  IVC:        Recursive Spartan/CCS verifier circuit      │
└─────────────────────────────────────────────────────────┘
```

### What you have (whir-p3 + Spartan)
- **whir-p3**: Plonky3-compatible WHIR implementation (fork of tcoratger/whir-p3). Provides Merkle-committed RS codewords, sumcheck-based folding, OOD sampling, shift queries — the full WHIR IOPP.
- **Spartan on top**: SuperSpartan-style argument for CCS constraints. The trace is committed as a multilinear polynomial via WHIR. Sumcheck reduces constraint checks to evaluation claims, which WHIR opens.
- **Plonky3 primitives**: Field arithmetic (KoalaBear, KoalaBear, M31), Poseidon2, Merkle trees, DFT/FFT.

### What you need to build
- **Accumulation layer**: Turn your single-shot Spartan+WHIR proof into an IVC scheme where each step accumulates instances rather than fully proving them.
- **Recursive circuit**: A Spartan/CCS circuit that verifies the accumulation step.
- **Decider**: A final WHIR evaluation proof on the accumulated instance.

---

## 2. Core Mathematical Objects

### 2.1 Reed–Solomon Code (as used in whir-p3)

$$
\mathsf{RS}[\mathbb{F}, L, m] = \left\{ f : L \to \mathbb{F} \;\middle|\; \exists\, \hat{p} \in \mathbb{F}^{<2}[X_1, \dots, X_m] \text{ s.t. } \forall x \in L,\; \hat{p}(x, x^2, \dots, x^{2^{m-1}}) = f(x) \right\}
$$

- $L$: foldable evaluation domain (multiplicative coset, $|L| = 2^{m}/\rho$)
- In whir-p3 this is over Plonky3 fields (e.g., KoalaBear $p = 2^{31} - 2^{24} + 1$)
- Every codeword ↔ multilinear polynomial in $m$ variables

### 2.2 Constrained Reed–Solomon Code (CRS) — WHIR's native object

$$
\mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma] := \left\{ f \in \mathsf{RS}[\mathbb{F}, L, m] \;\middle|\; \sum_{\mathbf{b} \in \{0,1\}^m} \hat{w}(\hat{f}(\mathbf{b}), \mathbf{b}) = \sigma \right\}
$$

This is what makes WHIR special for accumulation: the constraint is built into the code itself, not bolted on.

### 2.3 Key Polynomials

**Equality polynomial:**
$$
\mathsf{eq}(\mathbf{X}, \mathbf{Y}) = \prod_{i=1}^{m} \left( X_i Y_i + (1 - X_i)(1 - Y_i) \right)
$$

**Single evaluation claim** $\hat{f}(\mathbf{z}) = v$:
$$
\hat{w}(Z, \mathbf{X}) = Z \cdot \mathsf{eq}(\mathbf{z}, \mathbf{X}), \quad \sigma = v
$$

**Batched evaluation claims** (random $\xi$):
$$
\hat{w}(Z, \mathbf{X}) = Z \cdot \sum_{i=0}^{t} \xi^{i+1} \cdot \mathsf{eq}(\mathbf{z}_i, \mathbf{X}), \quad \sigma = \sum_{i=0}^{t} \xi^{i+1} \cdot y_i
$$

### 2.4 CCS / Spartan Connection

Your Spartan layer produces constraint claims of the form $Az \circ Bz - Cz = 0$ (R1CS) or the generalized CCS form. These reduce via sumcheck to evaluation claims on the witness multilinear polynomial — which become weight constraints in the CRS formulation.

Specifically, the Spartan sumcheck reduces:
$$
\sum_{\mathbf{x} \in \{0,1\}^s} \tilde{L}_i(\mathbf{x}) \cdot \prod_{j} \tilde{M}_j(\mathbf{x}, \cdot) = 0
$$
to evaluation claims $\tilde{w}(\mathbf{r}) = v$, which are exactly what WHIR's CRS handles natively.

---

## 3. Architecture: From whir-p3 + Spartan to Accumulation

```
┌──────────────────────────────────────────────────────────────┐
│                    Quasar-style IVC                           │
│                                                              │
│  Step i: Computation chunk → CCS witness w⁽ⁱ⁾                │
│                                                              │
│  ┌────────────────────┐                                      │
│  │  NIR_multicast      │  Commit union polynomial via WHIR   │
│  │  (ℓ instances → 1)  │  Sumcheck reduces ℓ constraint      │
│  │                     │  checks to 1 evaluation claim       │
│  └────────┬───────────┘                                      │
│           ▼                                                  │
│  ┌────────────────────┐                                      │
│  │  NIR_fold           │  Merge new instance with running    │
│  │  (2 → 1 reduction) │  accumulator via 1-round sumcheck   │
│  └────────┬───────────┘                                      │
│           ▼                                                  │
│  ┌────────────────────────────────────────┐                  │
│  │  NIR_batch (oracle batching via WHIR)  │ ← YOUR KEY IMPL │
│  │                                        │                  │
│  │  1. Batch codewords: u = γ₁u₁ + γ₂u₂  │                  │
│  │  2. OOD sampling: z₀ ∈ F, y₀ = ĝ(z₀)  │                  │
│  │  3. Spot checks at random b_j ∈ L     │                  │
│  │  4. Output: new oracle [[ũ]]          │                  │
│  │                                        │                  │
│  │  ★ Uses your whir-p3 RS encoding,      │                  │
│  │    Merkle trees, and folding directly  │                  │
│  └────────────────────────────────────────┘                  │
│                                                              │
│  Recursive circuit (CCS/Spartan):                            │
│  • Verifies accumulation step                                │
│  • O(ℓ) field ops + O(1) Merkle checks + Fiat–Shamir        │
│  • Hash: Poseidon2 (already in your Plonky3 stack)           │
└──────────────────────────────────────────────────────────────┘
```

### 3.1 Data Flow at Each IVC Step

1. **Generate ℓ CCS instances** from computation chunks, each producing witness $w^{(k)}$
2. **NIR_multicast**: Commit union polynomial $\tilde{w}_\cup(Y, X)$ encoding all ℓ witnesses via WHIR (RS-encode + Merkle-commit). Sumcheck reduces ℓ constraint checks to one evaluation claim.
3. **NIR_fold**: Merge new committed instance with running accumulator. 1-round sumcheck → invoke NIR_batch.
4. **NIR_batch (WHIR)**: Codeword batching to combine two RS codewords into one. This is where your whir-p3 code gets extended.
5. **Output**: New accumulator $\text{acc}'$ and proof $\text{pf}$.

### 3.2 Accumulator Structure

```rust
// What you'll need to represent in your Rust code:
struct Accumulator<F: Field> {
    // Explicit instance (short, public)
    merkle_root: Hash,              // rt: commitment to oracle
    eval_point: Vec<F>,             // α: evaluation point
    eval_value: F,                  // μ: claimed value
    ccs_point: Vec<F>,              // β: CCS constraint point
    ccs_value: F,                   // η: CCS constraint value

    // Witness (long, private)
    merkle_tree: MerkleTreeData,    // td: full tree
    oracle: Vec<F>,                 // f: the RS codeword
    witness: Vec<F>,                // w: decoded multilinear polynomial
}
```

---

## 4. WHIR Single Iteration (What whir-p3 already does)

This is the engine your accumulation scheme will call. A single WHIR iteration reduces:
$$
\text{proximity to } \mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma] \longrightarrow \text{proximity to } \mathsf{CRS}[\mathbb{F}, L^2, m-k, \hat{w}', \sigma']
$$

### 4.1 Protocol Steps (map to your whir-p3 code)

| Step | WHIR Protocol | whir-p3 Component |
|------|--------------|-------------------|
| Rounds 1–k | Sumcheck: prove $\sum_\mathbf{b} \hat{w}(\hat{f}(\mathbf{b}), \mathbf{b}) = \sigma$ | `sumcheck` module |
| Round k+1 | Send folded codeword $g : L^2 \to \mathbb{F}$ | RS encoding + Merkle commit |
| Round k+2 | OOD sample: $z_0 \gets \mathbb{F}$, prover sends $y_0 = \hat{g}(\mathbf{z}_0)$ | `ood_sample` / Fiat-Shamir |
| Shift queries | $t$ queries, fold computation | `fold` operation on cosets |

### 4.2 Recursive Claim Equations

New weight polynomial:
$$
\hat{w}'(Z, \mathbf{X}) := \hat{w}(Z, \alpha_1, \dots, \alpha_k, \mathbf{X}) + Z \cdot \sum_{i=0}^{t} \xi^{i+1} \cdot \mathsf{eq}(\mathbf{X}, \mathbf{z}_i)
$$

New target:
$$
\sigma' := \hat{h}_k(\alpha_k) + \sum_{i=0}^{t} \xi^{i+1} \cdot y_i
$$

### 4.3 Folding Operation

For $k = 1$ on coset $\{z, -z\}$:
$$
\mathsf{Fold}(f, \alpha_1)(z) = (1 - \alpha_1) \cdot f(z) + \alpha_1 \cdot f(-z)
$$

General $k$: read coset of size $2^k$, take specific linear combination. This is already in whir-p3.

### 4.4 Distance Preservation

If $f$ is $\delta$-far from CRS, then except with probability $\approx (1 - \delta)^t$, the output $g$ is $(1 - \rho')$-far from the reduced code. New rate: $\rho' = 2^{1-k} \cdot \rho$.

---

## 5. NIR_batch: The Key New Component to Build

This is what you need to implement on top of whir-p3. It's the oracle batching protocol that makes accumulation work.

### 5.1 Interface

```rust
// Pseudocode for what you're building
fn nir_batch(
    r: F,                           // batching randomness
    oracle_0: &WhirCommitment,      // [[f̃₀]] — from new instance
    oracle_1: &WhirCommitment,      // [[f̃₁]] — from running accumulator
    eval_claim: (Vec<F>, F),        // (x, v) s.t. Σ eq̃ᵢ(r)·f̃ᵢ(x) = v
) -> (WhirCommitment, Vec<(Vec<F>, F)>, BatchProof) {
    // Returns: new oracle [[f̃]], new eval claims, proof
}
```

### 5.2 Protocol Steps

1. **Encode** each $\tilde{f}_i$ as RS codeword $u_i = C(f_i)$ over $L$ ← **reuse whir-p3 RS encoding**
2. **Commit** via Merkle tree ← **reuse whir-p3 Merkle commitment**
3. **Batch**: $u = \gamma_1 \cdot u_1 + \gamma_2 \cdot u_2$, commit to $u$
4. **OOD sampling**: Verifier sends $\alpha_1, \dots, \alpha_s \in \mathbb{F}^{\log n} \setminus \{0,1\}^{\log n}$; prover responds with $\tilde{u}(\alpha_j)$ ← **reuse whir-p3 OOD machinery**
5. **Spot checks**: Query $u_1, u_2, u$ at random $b_j \in L$, verify $\gamma_1 \cdot u_1(b_j) + \gamma_2 \cdot u_2(b_j) = u(b_j)$ ← **reuse whir-p3 query infrastructure**
6. **Output**: New evaluation claims on $\tilde{u}$ and oracle $[[\tilde{u}]]$

### 5.3 Succinctness (why this makes Quasar work)

Proof = $s$ field elements (OOD evaluations) + $t$ Merkle authentication paths.

Both $s, t = O(\lambda / \log(1/\rho))$, **independent of polynomial size** → sublinear verifier.

### 5.4 Systematic Code Lifting

For standard RS over foldable $L$ (which whir-p3 uses):
$$
\tilde{u}_i(Y, X) = \tilde{\mathsf{eq}}_0(Y) \cdot \tilde{f}_i(X) + [\text{redundancy terms}]
$$

Evaluation claim $\tilde{f}_i(x) = v_i$ lifts to $\tilde{u}_i(0, x) = v_i$, verified via WHIR weighted sum query.

---

## 6. Mutual Correlated Agreement

### 6.1 Why It Matters

This is the mathematical guarantee that makes unbounded-depth accumulation sound. When you batch multiple oracles via random linear combination, mutual correlated agreement ensures the agreement set is preserved.

### 6.2 RS Code Bounds

| Regime | Proximity Radius $\delta_{\text{PG}}$ | Error $\varepsilon_{\text{PG}}$ | Status |
|--------|---------------------------------------|--------------------------------|--------|
| Unique decoding | $\delta(C)/2$ | $n / |\mathbb{F}|$ | **Proven** |
| List decoding | $1 - \sqrt{\delta(C)} - \eta$ | depends on $\eta$ | Conjectured |

### 6.3 Implication for Your Field Choice

With KoalaBear ($p \approx 2^{31}$), the error term $n / |\mathbb{F}|$ is manageable for moderate $n$, but you'll likely need extension fields for target security $\lambda = 128$. This is standard in Plonky3-based systems.

---

## 7. Soundness & Extraction

### 7.1 Total Soundness Error

$$
\kappa_{\text{ACC}} \leq (t_{\text{FS}} + k) \cdot \varepsilon_{\text{rbr}} + \kappa_{\text{MT}}(\sigma_{\text{MT}}, t_{\text{MT}}, \dots) + \kappa_{\text{FS}}(t_{\text{FS}})
$$

| Term | Source | Your stack |
|------|--------|-----------|
| $\varepsilon_{\text{rbr}}$ | IOR round-by-round error | From WHIR iteration soundness |
| $\kappa_{\text{MT}}$ | Merkle extraction error | Poseidon2 Merkle trees |
| $\kappa_{\text{FS}}$ | Fiat–Shamir extraction error | Sponge-based transcript |

### 7.2 Field Size Requirement

$$
|\mathbb{F}| \geq 2^\lambda \cdot \mathrm{poly}(\ell, \log M, \log n, |\Lambda(C, \delta)|)
$$

For KoalaBear base field with extension to $\mathbb{F}_{p^4}$: $|\mathbb{F}| \approx 2^{124}$, sufficient for $\lambda = 100$ bits.

### 7.3 Straightline Extraction (WARP Strategy)

1. Receive valid witness $w'$ for output accumulator (codeword $u$ close to oracle $f$)
2. Identify agreement set $S \subseteq [n]$ where $f$ and $u$ agree, $|S| \geq (1-\delta) \cdot n$
3. For each input oracle $f_i$, restrict to $S$ and perform **erasure correction** to recover $u_i$
4. RS erasure correction: $O(n \cdot \text{polylog}(n))$ — efficient for RS codes

### 7.4 RBR Knowledge Soundness

WARP's relaxed variant: uses a **knowledge state function** taking a candidate witness as additional input, with per-round extractors. This composes with Fiat–Shamir to give straightline state-restoration knowledge soundness.

---

## 8. Verifier Cost Comparison

| Component | Cost |
|-----------|------|
| Sumcheck (multi-cast) | $O(\log \ell)$ field ops + $O(\log \ell)$ RO queries |
| Sumcheck (fold) | $O(d)$ field ops |
| Instance accumulation $\tilde{x}(\tau)$ | $O(\ell \cdot m)$ field ops |
| **Oracle batching (WHIR)** | $O\!\left(\frac{\lambda}{\log(1/\rho)} \cdot (\log n + \log \ell)\right)$ RO queries |
| CRC operations | **O(1)** — independent of $\ell$ |

### Cross-Scheme Comparison

| Scheme | Verifier RO Queries | CRC Ops |
|--------|-------------------|---------|
| Arc (RS) | $O(\ell \cdot \frac{\lambda}{\log(1/\rho)} \cdot \log n)$ | — |
| WARP (linear codes) | $O(\ell \cdot \frac{\lambda}{\log(1/\rho)} \cdot \log n)$ | — |
| **Quasar + WHIR (your target)** | $O\!\left(\frac{\lambda}{\log(1/\rho)} \cdot (\log n + \log \ell)\right)$ | **O(1)** |

The $\ell$ factor moves inside a logarithm — this is Quasar's key contribution.

---

## 9. Hurdles Specific to Your Implementation

### 9.1 ⚠️ CRITICAL: Extraction Model Compatibility

**Problem:** WHIR's historical soundness analysis uses rewinding-based extraction. Quasar requires RBR knowledge soundness. WARP introduced straightline RBR-KS specifically for code-based accumulation.

**What this means for you:** You may need to:
1. Verify that whir-p3's WHIR iteration satisfies WARP's relaxed RBR-KS definition
2. Potentially modify the extraction argument (not the code, but the security proof)
3. Ensure the Fiat–Shamir transcript in whir-p3 is compatible with straightline extraction

**Practical impact:** This is primarily a theoretical concern. The code doesn't change, but you need the security proof to go through.

### 9.2 ⚠️ CRITICAL: Recursive Circuit for Spartan/CCS

**Problem:** You need a CCS circuit that verifies the accumulation step. This circuit must itself be provable by your Spartan+WHIR system.

**What the circuit contains:**
- $O(\ell)$ field operations (sumcheck verification)
- $O(1)$ Merkle path verifications (Poseidon2 hashes)
- Fiat–Shamir transcript re-derivation
- Accumulator compression (hash new accumulator for next step)

**Implementation challenge:** Plonky3 doesn't have a native "recursive verifier" for Spartan+WHIR. You'll need to arithmetize the accumulation verifier as CCS constraints. The Poseidon2 hash verification is the dominant cost — but Poseidon2 is designed to be efficient in CCS/AIR, and your stack already includes Poseidon2 AIR from Plonky3.

**Concrete approach:**
```rust
// You need to build this as a CCS circuit:
fn accumulation_verifier_circuit(
    // Public inputs
    old_acc_hash: Hash,
    new_acc_hash: Hash,
    // Advice (private inputs)
    sumcheck_messages: Vec<Vec<F>>,
    merkle_paths: Vec<MerklePath>,
    fiat_shamir_challenges: Vec<F>,
) -> bool {
    // 1. Re-derive Fiat-Shamir challenges from transcript
    // 2. Verify sumcheck equations
    // 3. Verify Merkle openings at shift query positions
    // 4. Verify OOD consistency
    // 5. Check accumulator hash
}
```

### 9.3 ⚠️ HIGH: Small Field Considerations

**Problem:** KoalaBear ($p \approx 2^{31}$) has $|\mathbb{F}| \approx 2^{31}$, which is too small for direct $\lambda = 128$ security.

**Solutions (standard in Plonky3 ecosystem):**
- Use extension field $\mathbb{F}_{p^4}$ for challenges and OOD samples ($|\mathbb{F}_{p^4}| \approx 2^{124}$)
- Keep base field operations in KoalaBear for prover efficiency
- Ensure the WHIR OOD sampling and Fiat-Shamir challenges use the extension field

**Your whir-p3 likely already handles this** since it's built on Plonky3's field tower, but verify that the accumulation-specific randomness (batching coefficients $\gamma_i$, sumcheck challenges) also uses extension field elements.

### 9.4 ⚠️ HIGH: Spartan → CCS → CRS Reduction

**Problem:** You need to formalize how Spartan's CCS constraints reduce to CRS proximity claims that WHIR can handle. This is the "PESAT-to-CRS IOR" in the WARP/Arc terminology.

**What Whirlaway does:** The SuperSpartan argument reduces CCS constraints via sumcheck to evaluation claims on the witness polynomial. These evaluation claims become weight constraints in WHIR's CRS.

**What you need additionally for accumulation:** Instead of fully verifying these claims at each step, you accumulate them. The evaluation claim $\tilde{w}(\mathbf{r}) = v$ from Spartan becomes part of the accumulator's explicit instance $(\alpha, \mu)$.

### 9.5 ⚠️ MEDIUM: Quasi-Linear Prover (Not Linear)

**Design tradeoff:** WHIR uses RS codes → FFTs → $O(n \log n)$ prover. WARP achieves $O(n)$ with expander codes.

**For your use case:** This is likely acceptable. The whir-p3 prover is already quasi-linear, and you're getting WHIR's ~300 μs verification in return. If linear-time proving becomes critical later, you'd swap WHIR for expander codes (Brakedown-style) but lose the verification speed.

### 9.6 ⚠️ MEDIUM: PCD Not Supported

Quasar leaves sublinear-verifier PCD (multiple accumulators for distributed proving) as an open problem. If you need PCD (e.g., for parallel proving across multiple machines), this combination doesn't provide it.

### 9.7 ⚠️ LOW: No Existing Implementation

No published implementation of Quasar+WHIR accumulation exists. You're building something new. The closest references are:
- **Whirlaway**: SuperSpartan + WHIR (single-shot, no accumulation)
- **Microsoft Spartan2**: Spartan with WHIR PCS support (single-shot)
- **Arc**: RS-based accumulation (but not using WHIR or Quasar)

---

## 10. Parameter Selection for whir-p3

### 10.1 Rate $\rho$

| Choice | Proof Size | Verifier Hashes | Prover Cost |
|--------|-----------|-----------------|-------------|
| $\rho = 1/4$ | Larger | More | Less |
| $\rho = 1/8$ | Medium | Medium | Medium |
| $\rho = 1/16$ | Smaller | Fewer | More |

For accumulation, prefer **lower $\rho$** — the oracle batching proof shrinks, which directly reduces recursive circuit size.

### 10.2 Folding Parameter $k$

- Typical: $k = 4$ or $k = \log(m)/2$
- For single-step accumulation: $k$ affects sumcheck rounds and $2^k$ symbols per query
- Higher $k$ → fewer rounds but more work per query

### 10.3 Repetition Parameter $t$

$$
t \geq \frac{\lambda}{-\log(1 - \delta)}
$$

Larger $t$ = more Merkle paths in recursive circuit. With Poseidon2, each Merkle path verification costs ~1 Poseidon2 permutation per tree level, which your Plonky3 stack handles efficiently.

### 10.4 Proximity Bound $\delta$

| Regime | Bound | OOD Required? | Status |
|--------|-------|---------------|--------|
| Unique decoding | $\delta < 1 - \sqrt{\rho}$ | No | **Proven** |
| List decoding | $\delta < 1 - \rho$ | Yes | Conjectured |

Recommendation: start with unique decoding (proven) for safety, optimize to list decoding later.

### 10.5 Accumulation Width $\ell$

Quasar's O(1) CRC allows larger $\ell$ than ProtoGalaxy. But larger $\ell$ means larger union polynomial and recursive circuit. Start with $\ell = 2$–$4$ and benchmark.

---

## 11. Implementation Roadmap

### Phase 1: Extend whir-p3 with Oracle Batching

```
whir-p3/src/
├── ... (existing WHIR implementation)
├── accumulation/
│   ├── mod.rs
│   ├── nir_batch.rs          ← Core: codeword batching protocol
│   ├── nir_multicast.rs      ← Multi-instance → 1 eval claim
│   ├── nir_fold.rs           ← 2-to-1 accumulator folding
│   └── accumulator.rs        ← Accumulator data structures
```

**nir_batch.rs** reuses:
- RS encoding from whir-p3
- Merkle commitment from whir-p3
- OOD sampling from whir-p3
- Spot-check queries from whir-p3

New logic: codeword linear combination $u = \gamma_1 u_1 + \gamma_2 u_2$ and consistency checks.

### Phase 2: Build the Recursive Circuit

Arithmetize the accumulation verifier as CCS constraints. Key sub-circuits:
1. **Poseidon2 hash verification** (for Merkle paths) — use Plonky3's existing Poseidon2 AIR
2. **Sumcheck verification** (field operations) — straightforward in CCS
3. **Fiat-Shamir re-derivation** (sponge operations) — Poseidon2-based sponge

### Phase 3: Compose into IVC

Wire together:
1. Computation step → ℓ CCS instances
2. NIR_multicast → 1 evaluation claim
3. NIR_fold → updated accumulator
4. Recursive circuit proves the step
5. Iterate

### Phase 4: Decider

At the very end, run the full WHIR evaluation proof on the final accumulator to produce a verifiable proof.

---

## 12. Key Equations Summary

### Accumulation Core

**Codeword batching:**
$$u = \gamma_1 \cdot u_1 + \gamma_2 \cdot u_2$$

**Spot check consistency:**
$$\gamma_1 \cdot u_1(b_j) + \gamma_2 \cdot u_2(b_j) = u(b_j) \quad \forall j \in [t]$$

**WHIR recursive claim (new weight):**
$$\hat{w}'(Z, \mathbf{X}) := \hat{w}(Z, \alpha_1, \dots, \alpha_k, \mathbf{X}) + Z \cdot \sum_{i=0}^{t} \xi^{i+1} \cdot \mathsf{eq}(\mathbf{X}, \mathbf{z}_i)$$

**WHIR recursive claim (new target):**
$$\sigma' := \hat{h}_k(\alpha_k) + \sum_{i=0}^{t} \xi^{i+1} \cdot y_i$$

### Spartan/CCS Reduction

**CCS constraint (what your Spartan layer proves):**
$$\sum_{i=0}^{q-1} c_i \cdot \prod_{j \in S_i} \langle \tilde{M}_j, \tilde{z} \rangle = 0$$

**Spartan sumcheck reduces to evaluation claim:**
$$\tilde{w}(\mathbf{r}) = v$$

**This becomes accumulator's explicit instance:**
$$(\alpha, \mu) = (\mathbf{r}, v)$$

### Security

**Soundness budget:**
$$\kappa_{\text{ACC}} \leq (t_{\text{FS}} + k) \cdot \varepsilon_{\text{rbr}} + \kappa_{\text{MT}} + \kappa_{\text{FS}}$$

**Field size requirement:**
$$|\mathbb{F}| \geq 2^\lambda \cdot \mathrm{poly}(\ell, \log M, \log n)$$

**Per-iteration soundness:**
$$(1 - \delta)^t \leq 2^{-\lambda}$$

---

## 13. References

- **WHIR:** Arnon, Chiesa, Fenzi, Yogev. ePrint 2024/1586. EUROCRYPT 2025.
- **Quasar:** Zheng, Gao, Guo, Xiao. 2025.
- **WARP:** Bünz, Chiesa, Fenzi, Wang. ePrint 2025/753.
- **Arc:** Bünz, Mishra, Nguyen, Wang. ePrint 2024/1731. CRYPTO 2025.
- **Spartan/SuperSpartan:** Setty, Thaler, Wahby. CRYPTO 2020 / ePrint 2023/552.
- **Spartan2 (Microsoft):** github.com/Microsoft/Spartan2
- **whir-p3:** github.com/tcoratger/whir-p3
- **Whirlaway:** github.com/TomWambsgans/Whirlaway
- **Plonky3:** github.com/Plonky3/Plonky3
- **BOIL:** Kattis, Nadeau, Bhavsar. ePrint 2024/1993.
- **BaseFold:** Zeilberger, Chen, Fisch. CRYPTO 2024.
- **STIR:** Arnon, Chiesa, Fenzi, Yogev. CRYPTO 2024.
