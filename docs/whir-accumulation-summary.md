# WHIR Accumulation via Quasar + WARP: Hurdles, Elements & Equations

## 1. Goal

Build a **hash-based, plausibly post-quantum accumulation scheme** that combines:

- **WHIR** — RS proximity testing with super-fast verification (the PCS / proximity engine)
- **Quasar** — multi-instance accumulation with sublinear verifier (the accumulation framework)
- **WARP** — linear-time accumulation techniques and straightline extraction strategy (the extraction / soundness backbone)

Target properties: O(1) CRC ops per step, transparent setup, ~300–600 μs verification, sublinear verifier complexity.

---

## 2. Core Mathematical Objects

### 2.1 Reed–Solomon Code

$$
\mathsf{RS}[\mathbb{F}, L, m] = \left\{ f : L \to \mathbb{F} \;\middle|\; \exists\, \hat{p} \in \mathbb{F}^{<2}[X_1, \dots, X_m] \text{ s.t. } \forall x \in L,\; \hat{p}(x, x^2, \dots, x^{2^{m-1}}) = f(x) \right\}
$$

- $L \subseteq \mathbb{F}$: smooth foldable evaluation domain ($|L|$ is a power of 2)
- $m$: number of variables, degree bound $d = 2^m$, rate $\rho = 2^m / |L|$
- Every codeword corresponds to a **multilinear polynomial** $\hat{f}$ in $m$ variables

### 2.2 Constrained Reed–Solomon Code (CRS)

$$
\mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma] := \left\{ f \in \mathsf{RS}[\mathbb{F}, L, m] \;\middle|\; \sum_{\mathbf{b} \in \{0,1\}^m} \hat{w}(\hat{f}(\mathbf{b}), \mathbf{b}) = \sigma \right\}
$$

- $\hat{w} \in \mathbb{F}[Z, X_1, \dots, X_m]$: weight polynomial encoding constraints
- $\sigma \in \mathbb{F}$: target sum

### 2.3 Equality Polynomial

$$
\mathsf{eq}(\mathbf{X}, \mathbf{Y}) = \prod_{i=1}^{m} \left( X_i Y_i + (1 - X_i)(1 - Y_i) \right)
$$

Used to encode point evaluations as weighted sums.

### 2.4 Evaluation Claim Encoding

A single evaluation claim $\hat{f}(\mathbf{z}) = v$ becomes:

$$
\hat{w}(Z, X_1, \dots, X_m) = Z \cdot \mathsf{eq}(\mathbf{z}, X_1, \dots, X_m), \quad \sigma = v
$$

Batched evaluation claims (via random $\xi$):

$$
\hat{w}(Z, \mathbf{X}) = Z \cdot \sum_{i=0}^{t} \xi^{i+1} \cdot \mathsf{eq}(\mathbf{z}_i, \mathbf{X}), \quad \sigma = \sum_{i=0}^{t} \xi^{i+1} \cdot y_i
$$

---

## 3. Building Blocks & Their Roles

### 3.1 Architecture Overview

```
Quasar IVC
├── NIR_multicast (multi-cast reduction: ℓ instances → 1 evaluation claim)
│   └── Sumcheck on union polynomial w̃_∪(Y, X)
│   └── WHIR commitment to union polynomial
├── NIR_fold (2-to-1 reduction: new instance + running accumulator → new accumulator)
│   └── 1-round sumcheck
│   └── NIR_batch (oracle batching)
│       └── WHIR codeword batching (RS folding + OOD + spot checks)
└── Recursive circuit (verifies accumulation step)
    └── O(ℓ) field ops + O(1) Merkle checks + Fiat–Shamir hashes
```

### 3.2 Two Required IORs (from WARP/Arc recipe)

| IOR | Function | WHIR Role |
|-----|----------|-----------|
| **PESAT-to-CRS** | Reduce $(x, w) \in R_\circledcirc(\mathbb{F})$ to a CRS proximity claim | Encode witness, derive weight polynomial |
| **CRS-batching** | Reduce $\ell$ CRS proximity claims → 1 CRS proximity claim | Core accumulation step via WHIR iteration |

### 3.3 Accumulator Structure

```
acc.x = (rt, α, μ, β, η)       // Merkle root + eval point/value + PESAT point/value
acc.w = (td, f, w)              // Merkle tree data + oracle + decoded witness
```

Accumulation relation $R_C$ tracks:
- **Explicit instance** $\bigl((\alpha, \mu), (\beta, \eta)\bigr)$: evaluation claim $\hat{u}(\alpha) = \mu$ and PESAT constraint $\hat{P}_b(\beta, C^{-1}(u)) = \eta$
- **Implicit instance** $f : [n] \to \mathbb{F}$: oracle (Merkle-committed)
- **Witness** $u \in C$: actual codeword close to $f$

---

## 4. WHIR Single-Iteration Protocol

Reduces proximity to $\mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma]$ down to proximity to $\mathsf{CRS}[\mathbb{F}, L^2, m - k, \hat{w}', \sigma']$.

### 4.1 Steps

**Rounds 1–k (Sumcheck):** Prove $\sum_{\mathbf{b} \in \{0,1\}^m} \hat{w}(\hat{f}(\mathbf{b}), \mathbf{b}) = \sigma$. Prover sends quadratic polynomials $\hat{h}_1, \dots, \hat{h}_k$; verifier replies with $\alpha_1, \dots, \alpha_k \in \mathbb{F}$.

**Round k+1 (Claimed codeword):** Prover sends $g : L^2 \to \mathbb{F}$, honestly the codeword of $\hat{f}(\alpha_1, \dots, \alpha_k, \cdot)$.

**Round k+2 (OOD sample):** Verifier samples $z_0 \gets \mathbb{F}$, sets $\mathbf{z}_0 := (z_0, z_0^2, \dots, z_0^{2^{m-1}})$. Prover replies with $y_0 := \hat{g}(\mathbf{z}_0)$.

**Shift queries:** For $i \in [t]$, verifier samples $z_i \gets L^{2^k}$, computes $y_i := \mathsf{Fold}(f, (\alpha_1, \dots, \alpha_k))(z_i)$ by querying $f$ at $2^k$ positions. Sets $\mathbf{z}_i := (z_i, \dots, z_i^{2^{m-1}})$. Verifier samples $\xi \gets \mathbb{F}$.

### 4.2 Recursive Claim (Output)

$$
\hat{w}'(Z, \mathbf{X}) := \hat{w}(Z, \alpha_1, \dots, \alpha_k, \mathbf{X}) + Z \cdot \sum_{i=0}^{t} \xi^{i+1} \cdot \mathsf{eq}(\mathbf{X}, \mathbf{z}_i)
$$

$$
\sigma' := \hat{h}_k(\alpha_k) + \sum_{i=0}^{t} \xi^{i+1} \cdot y_i
$$

### 4.3 Folding Operation

For $k = 1$ on coset $\{z, -z\}$:

$$
\mathsf{Fold}(f, \alpha_1)(z) = (1 - \alpha_1) \cdot f(z) + \alpha_1 \cdot f(-z)
$$

General $k$: read coset of size $2^k$, take specific linear combination.

### 4.4 Distance Preservation

If $f$ is $\delta$-far from $\mathsf{CRS}$, then except with probability $\approx (1 - \delta)^t$, the output $g$ is $(1 - \rho')$-far from the reduced code. New rate: $\rho' = 2^{1-k} \cdot \rho$.

---

## 5. Quasar NIR_batch Instantiation with WHIR

### 5.1 Input/Output

- **Input:** Randomness $r \in \mathbb{F}$, two polynomial oracles $[[f̃_0]], [[f̃_1]]$ with batched evaluation claim $\sum \tilde{\mathsf{eq}}_i(r) \cdot \tilde{f}_i(x) = v$
- **Output:** Single oracle $[[\tilde{f}]]$ with evaluation claims $\tilde{f}(x_j) = v_j$
- **Requirement:** Proof $\pi_{\text{batch}}$ must be **sublinear** in $|\tilde{f}|$

### 5.2 WHIR-Based Protocol

1. **Encode** each $\tilde{f}_i$ as RS codeword $u_i = C(f_i)$ over domain $L$
2. **Commit** each codeword via Merkle tree (already done from accumulator state)
3. **Batch codewords:** $u = \gamma_1 \cdot u_1 + \gamma_2 \cdot u_2$, commit to $u$
4. **OOD sampling:** Verifier sends $\alpha_1, \dots, \alpha_s \in \mathbb{F}^{\log n} \setminus \{0,1\}^{\log n}$; prover responds with $\tilde{u}(\alpha_j)$
5. **Spot checks:** Verifier queries $u_1, u_2, u$ at random $b_1, \dots, b_t \in L$, checks: $\gamma_1 \cdot u_1(b_j) + \gamma_2 \cdot u_2(b_j) = u(b_j)$
6. **Output:** New evaluation claims on $\tilde{u}$ and oracle $[[\tilde{u}]]$

**Succinctness:** Proof = $s$ field elements + $t$ Merkle paths. Both $s, t = O(\lambda / \log(1/\rho))$, independent of polynomial size.

### 5.3 Systematic Code Lifting

For standard RS over foldable $L$, the multilinear extension decomposes as:

$$
\tilde{u}_i(Y, X) = \tilde{\mathsf{eq}}_0(Y) \cdot \tilde{f}_i(X) + [\text{redundancy terms}]
$$

An evaluation claim $\tilde{f}_i(x) = v_i$ lifts to $\tilde{u}_i(0, x) = v_i$, verified via WHIR weighted sum query.

---

## 6. Mutual Correlated Agreement

### 6.1 Definition

A proximity generator $\mathsf{PG}(\ell, \alpha)$ for code $C$ has mutual correlated agreement with proximity radius $\delta_{\mathrm{PG}}$ and error $\varepsilon_{\mathrm{PG}}$ if: for all $f_1, \dots, f_\ell$, with high probability over $\alpha$, the agreement set of $\sum \gamma_i f_i$ with $C$ coincides with the correlated agreement set of $(f_1, \dots, f_\ell)$ with $C^\ell$.

### 6.2 RS Bounds

| Regime | Proximity Radius | Error |
|--------|-----------------|-------|
| Unique decoding (proven) | $\delta_{\mathrm{PG}} = \delta(C)/2$ | $\varepsilon_{\mathrm{PG}} = n / |\mathbb{F}|$ |
| List decoding (conjectured) | $\delta_{\mathrm{PG}} = 1 - \sqrt{\delta(C)} - \eta$ | depends on $\eta$ |

### 6.3 Role in Accumulation

Ensures that random linear combination of multiple oracles preserves the agreement set — making **unbounded-depth accumulation** possible while maintaining distance. Also critical for the **straightline extraction** strategy (WARP).

---

## 7. Soundness & Extraction

### 7.1 Soundness Error Budget

$$
\kappa_{\mathrm{ACC}} \leq (t_{\mathrm{FS}} + k) \cdot \varepsilon_{\mathrm{rbr}} + \kappa_{\mathrm{MT}}(\sigma_{\mathrm{MT}}, t_{\mathrm{MT}}, \dots) + \kappa_{\mathrm{FS}}(t_{\mathrm{FS}})
$$

| Term | Source |
|------|--------|
| $\varepsilon_{\mathrm{rbr}}$ | IOR round-by-round error |
| $\kappa_{\mathrm{MT}}$ | Merkle tree extraction error |
| $\kappa_{\mathrm{FS}}$ | Fiat–Shamir extraction error |

### 7.2 Field Size Requirement

$$
|\mathbb{F}| \geq 2^\lambda \cdot \mathrm{poly}(\ell, \log M, \log n, |\Lambda(C, \delta)|)
$$

where $|\Lambda(C, \delta)|$ = list size at distance $\delta$ (unique decoding: 1; list decoding: depends on parameters).

### 7.3 Straightline Extraction Strategy (from WARP)

1. Receive valid witness $w'$ for output accumulator (codeword $u$ close to oracle $f$)
2. Identify agreement set $S \subseteq [n]$ where $f$ and $u$ agree, $|S| \geq (1-\delta) \cdot n$
3. For each input oracle $f_i$, restrict to $S$ and perform **erasure correction** to recover $u_i$
4. Succeeds because $|S| \geq (1-\delta) \cdot n > (1 - \delta(C)) \cdot n$
5. RS erasure correction: $O(n \cdot \mathrm{polylog}(n))$

### 7.4 Round-by-Round Knowledge Soundness (RBR-KS)

WARP introduces a relaxed variant using a **knowledge state function** (takes candidate witness as additional input) and per-round extractors. Required for straightline state-restoration knowledge soundness after Fiat–Shamir compilation.

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

| Scheme | Verifier RO Queries | CRC / Group Ops |
|--------|-------------------|-----------------|
| Arc (RS codes) | $O(\ell \cdot \frac{\lambda}{\log(1/\rho)} \cdot \log n)$ | — |
| WARP (linear codes) | $O(\ell \cdot \frac{\lambda}{\log(1/\rho)} \cdot \log n)$ | — |
| **Quasar + WHIR** | $O\!\left(\frac{\lambda}{\log(1/\rho)} \cdot (\log n + \log \ell)\right)$ | **O(1)** |

Key improvement: the $\ell$ factor moves inside a logarithm.

---

## 9. Hurdles & Open Problems

### 9.1 Extraction Model Compatibility ⚠️ CRITICAL

- Quasar uses round-by-round (RBR) knowledge soundness
- WARP introduced **straightline RBR-KS** specifically for code-based accumulation
- WHIR's extraction historically relies on **rewinding** in some formulations
- **Hurdle:** Verify that WHIR's extraction strategy is compatible with Quasar's straightline requirements — may need to adapt WHIR's soundness proof to the WARP-style knowledge state function framework

### 9.2 Linear-Time Prover ⚠️ DESIGN TRADEOFF

- WHIR uses RS codes → FFTs → **quasi-linear** prover $O(n \log n)$
- WARP achieves **linear-time** prover via expander codes (Brakedown/Spielman)
- **Hurdle:** Cannot get both WHIR's fast verification and WARP's linear proving simultaneously
- **Decision:** Choose WHIR if verifier speed is priority; choose expander codes if prover speed is priority

### 9.3 Soundness in List-Decoding Regime ⚠️ THEORETICAL

- WHIR supports proximity bounds up to $1 - \sqrt{\rho}$ (proven) or $1 - \rho$ (conjectured)
- **Hurdle:** Ensure Quasar's proximity parameters are compatible with WHIR's soundness analysis
- OOD sampling pins down a unique codeword when multiple may be close — must verify this interacts correctly with Quasar's multi-instance structure

### 9.4 PCD / Multiple Accumulators ⚠️ OPEN PROBLEM

- Quasar explicitly leaves sublinear-verifier **PCD** (multiple accumulators, not just multiple instances) as an open problem
- WHIR does not resolve this
- **Hurdle:** If your application requires PCD (e.g., distributed proving), this combination does not provide it

### 9.5 Recursive Circuit Overhead ⚠️ ENGINEERING

- Recursive circuit must verify: $O(\ell)$ field ops + $O(1)$ Merkle path checks + Fiat–Shamir hashes
- Merkle path verification dominates recursion overhead
- **Hurdle:** Hash function choice is critical — must be both secure and circuit-friendly
- Recommendation: Poseidon or Monolith for Merkle hash
- WHIR's low query complexity (small $t$) directly reduces Merkle paths the circuit must verify

### 9.6 No Existing Implementation ⚠️ PRACTICAL

- No published implementation of Quasar + WHIR exists
- Concrete performance depends on hash choice, field size, circuit framework
- **Hurdle:** Theoretical analysis is promising but unvalidated in practice

### 9.7 Systematic Code Assumption ⚠️ TECHNICAL

- Quasar (Section 6.2) assumes the code is **systematic** (first $k$ entries of $C(x)$ equal $x$)
- Standard RS over smooth/foldable domains is systematic, but must verify this holds for the specific WHIR parameterization being used
- Evaluation claim lifting ($\tilde{f}_i(x) = v_i \Rightarrow \tilde{u}_i(0, x) = v_i$) depends on this

---

## 10. Parameter Selection Guide

### 10.1 Rate $\rho$

- Lower $\rho$ (e.g., 1/8 or 1/16) → smaller WHIR proofs, fewer verifier hashes, but larger codewords
- RS codes are MDS: optimal rate-distance tradeoff $\delta(C) = 1 - \rho$
- For accumulation, prefer **lower $\rho$** since oracle batching proof shrinks

### 10.2 Folding Parameter $k$

- Larger $k$: fewer iterations, but $2^k$ symbols read per query, rate drops faster ($\rho' = 2^{1-k}\rho$)
- Typical: $k = 4$ or $k = \log(m)/2$
- For accumulation (single-step reduction): affects sumcheck rounds and query cost

### 10.3 Repetition Parameter $t$

- Soundness per iteration: $(1 - \delta)^t$
- Need $t \geq \lambda / (-\log(1 - \delta))$ for $\lambda$-bit security
- Larger $t$ → more Merkle paths in recursive circuit → bigger recursion overhead

### 10.4 Proximity Bound $\delta$

| Regime | Bound | OOD Required? | Status |
|--------|-------|---------------|--------|
| Unique decoding | $\delta < 1 - \sqrt{\rho}$ | No | Proven |
| List decoding | $\delta < 1 - \rho$ | Yes | Conjectured |

Use largest provable/conjectured $\delta$ for best verifier efficiency.

### 10.5 Accumulation Width $\ell$

- Larger $\ell$: fewer IVC steps, but larger union polynomial and recursive circuit
- Quasar's O(1) CRC allows pushing $\ell$ higher than ProtoGalaxy
- Tradeoff: recursive circuit size vs. total number of IVC steps

---

## 11. Implementation Recipe

1. **Choose NARK:** HyperPlonk (multilinear plonkish) with WHIR as PCS
2. **Build NIR_multicast** (Quasar §5.1): interleave SPS protocol with multi-cast reduction, commit union polynomials via WHIR
3. **Build NIR_fold** (Quasar §5.2 / Construction 1): 1-round sumcheck → invoke NIR_batch
4. **Instantiate NIR_batch with WHIR** (Quasar Figure 14 / §6.2): codeword batching via RS proximity testing + OOD + spot checks
5. **Adapt extraction** (WARP strategy): implement straightline RBR-KS with knowledge state function; verify compatibility with WHIR's soundness proof
6. **Compose into IVC** (Quasar §6): recursive circuit verifies accumulation step
7. **Choose hash:** Poseidon/Monolith for circuit-friendly Merkle trees
8. **Final verification (decider):** Run WHIR evaluation proof on final accumulator

---

## 12. References

- **WHIR:** Arnon, Chiesa, Fenzi, Yogev. ePrint 2024/1586. EUROCRYPT 2025.
- **Quasar:** Zheng, Gao, Guo, Xiao. 2025.
- **WARP:** Bünz, Chiesa, Fenzi, Wang. ePrint 2025/753.
- **Arc:** Bünz, Mishra, Nguyen, Wang. ePrint 2024/1731. CRYPTO 2025.
- **BOIL:** Kattis, Nadeau, Bhavsar. ePrint 2024/1993.
- **STIR:** Arnon, Chiesa, Fenzi, Yogev. CRYPTO 2024.
- **BaseFold:** Zeilberger, Chen, Fisch. CRYPTO 2024.
- **ProtoGalaxy:** Eagen, Gabizon. 2023.
- **Proximity Gaps for RS:** Ben-Sasson, Carmon, Ishai, Kopparty, Saraf. FOCS 2020.
