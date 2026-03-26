# WHIR: Essential Elements for Building an Accumulation Scheme

## 1. Overview and Positioning

WHIR (Weights Help Improving Rate) is an IOP of proximity (IOPP) for **constrained Reed–Solomon codes** (CRS). It was introduced by Arnon, Chiesa, Fenzi, and Yogev (EUROCRYPT 2025, ePrint 2024/1586). WHIR combines the sumcheck-based folding of BaseFold with the rate-reduction technique of STIR, achieving the fastest known verification time among all hash-based proximity tests.

For accumulation, WHIR is relevant as the **proximity testing engine**. The general recipe (established by Arc [BMNW25b] and WARP [BCFW25]) compiles suitable Interactive Oracle Reductions (IORs) into accumulation schemes via the BCS/Fiat–Shamir transformation in the random oracle model. WHIR's constrained-code formulation is particularly well-suited to this because it natively handles evaluation constraints — exactly what accumulation relations require.

---

## 2. Constrained Reed–Solomon Codes

### 2.1 Standard Reed–Solomon Code

Let $\mathbb{F}$ be a finite field, $L \subseteq \mathbb{F}$ a smooth evaluation domain (multiplicative coset of $\mathbb{F}^*$ with $|L|$ a power of two), and $m \in \mathbb{N}$ the number of variables (so the degree bound is $d = 2^m$ and the rate is $\rho = 2^m / |L|$).

$$
\mathsf{RS}[\mathbb{F}, L, m] = \{ f : L \to \mathbb{F} \mid \exists\, \hat{p} \in \mathbb{F}^{<2}[X_1, \dots, X_m] \text{ s.t. } \forall x \in L,\; \hat{p}(x, x^2, \dots, x^{2^{m-1}}) = f(x) \}
$$

Key insight: every codeword corresponds to a **multilinear polynomial** $\hat{f}$ in $m$ variables, where the univariate-to-multilinear correspondence is given by $\hat{f}(\mathbf{b}) = f(x)$ for $\mathbf{b} = (x, x^2, \dots, x^{2^{m-1}})$. This multilinear view is critical for the sumcheck integration.

### 2.2 Constrained Reed–Solomon Code (CRS)

A CRS code augments the RS code with a constraint expressed via a **weight polynomial** $\hat{w} \in \mathbb{F}[Z, X_1, \dots, X_m]$ and a **target** $\sigma \in \mathbb{F}$:

$$
\mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma] := \left\{ f \in \mathsf{RS}[\mathbb{F}, L, m] \;\middle|\; \sum_{\mathbf{b} \in \{0,1\}^m} \hat{w}(\hat{f}(\mathbf{b}), \mathbf{b}) = \sigma \right\}
$$

### 2.3 Expressing Evaluation Claims

An evaluation claim $\hat{f}(\mathbf{z}) = v$ is captured by setting:

$$
\hat{w}(Z, X_1, \dots, X_m) = Z \cdot \mathsf{eq}(\mathbf{z}, X_1, \dots, X_m), \quad \sigma = v
$$

where $\mathsf{eq}(\mathbf{X}, \mathbf{Y}) = \prod_{i=1}^m (X_i Y_i + (1 - X_i)(1 - Y_i))$.

Multiple evaluation claims can be batched into a single weight polynomial via random linear combinations:

$$
\hat{w}(Z, \mathbf{X}) = Z \cdot \sum_{i=0}^{t} \xi^{i+1} \cdot \mathsf{eq}(\mathbf{z}_i, \mathbf{X}), \quad \sigma = \sum_{i=0}^{t} \xi^{i+1} \cdot y_i
$$

This batching is central to accumulation: it allows folding multiple proximity-with-evaluation claims into a single CRS proximity claim.

---

## 3. The WHIR Protocol (Single Iteration)

A single WHIR iteration reduces proximity to $\mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma]$ to proximity to $\mathsf{CRS}[\mathbb{F}, L^2, m - k, \hat{w}', \sigma']$, where $k$ is a folding parameter.

### 3.1 Protocol Steps

Let $\delta \in (0, 1 - \rho)$ be the proximity parameter and $t$ the repetition parameter.

**Round 1 — Sumcheck rounds ($k$ rounds):**
The prover and verifier run $k$ rounds of sumcheck for:
$$
\sum_{\mathbf{b} \in \{0,1\}^m} \hat{w}(\hat{f}(\mathbf{b}), \mathbf{b}) = \sigma
$$
Prover sends quadratic polynomials $\hat{h}_1, \dots, \hat{h}_k$; verifier replies with random $\alpha_1, \dots, \alpha_k \in \mathbb{F}$.

**Round $k+1$ — Claimed codeword:**
The prover sends $g : L^2 \to \mathbb{F}$. Honestly, $g$ is the codeword of $\hat{f}(\alpha_1, \dots, \alpha_k, \cdot)$, a multilinear polynomial in $m - k$ variables.

**Round $k+2$ — Out-of-domain (OOD) sample and answer:**
- Verifier samples $z_0 \gets \mathbb{F}$, sets $\mathbf{z}_0 := (z_0, z_0^2, \dots, z_0^{2^{m-1}})$.
- Prover replies with $y_0 := \hat{g}(\mathbf{z}_0)$.

**Shift queries (verifier queries):**
For $i \in [t]$, verifier samples $z_i \gets L^{2^k}$ and computes $y_i := \mathsf{Fold}(f, (\alpha_1, \dots, \alpha_k))(z_i)$ by querying $f$ at $2^k$ positions. Sets $\mathbf{z}_i := (z_i, \dots, z_i^{2^{m-1}})$.

Verifier samples combination randomness $\xi \gets \mathbb{F}$.

**Recursive claim:**
$$
\hat{w}'(Z, \mathbf{X}) := \hat{w}(Z, \alpha_1, \dots, \alpha_k, \mathbf{X}) + Z \cdot \sum_{i=0}^{t} \xi^{i+1} \cdot \mathsf{eq}(\mathbf{X}, \mathbf{z}_i)
$$
$$
\sigma' := \hat{h}_k(\alpha_k) + \sum_{i=0}^{t} \xi^{i+1} \cdot y_i
$$

### 3.2 Complexity per Iteration

| Metric | Cost |
|--------|------|
| Prover oracle | $\approx n/2$ field elements (the function $g$) |
| Verifier queries | $t$ queries, each reading $2^k$ field elements |
| Verifier field ops | $O(k)$ for sumcheck checks + $O(t \cdot 2^k)$ for fold computation |
| Verifier hashes | Authentication paths for $t$ query positions |
| Soundness error | $\approx (1 - \delta)^t$ per iteration |

### 3.3 Folding Operation

The folding $\mathsf{Fold}(f, (\alpha_1, \dots, \alpha_k))$ at point $z$ is computed by reading $2^k$ values of $f$ and taking a specific linear combination. This is the same folding as in FRI/STIR: for $k = 1$, given a coset $\{z, -z\}$, the fold is $(1-\alpha_1) \cdot f(z) + \alpha_1 \cdot f(-z)$ (after appropriate normalization). For general $k$, it extends to reading a coset of size $2^k$.

### 3.4 Soundness and Distance Preservation

If $f$ is $\delta$-far from $\mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma]$, then except with probability $\approx (1 - \delta)^t$, the output $g$ is $(1 - \rho')$-far from the reduced code. The new rate is $\rho' = 2^{1-k} \cdot \rho$.

In the list-decoding regime (conjectured): proximity parameter up to $\delta < 1 - \rho$.
In the unique-decoding regime (proven): proximity parameter up to $\delta < 1 - \sqrt{\rho}$.

---

## 4. Mutual Correlated Agreement

### 4.1 Definition (Informal)

A proximity generator $\mathsf{PG}(\ell, \alpha)$ for code $C$ has **mutual correlated agreement** with proximity radius $\delta_{\mathrm{PG}}$ and error $\varepsilon_{\mathrm{PG}}$ if: for all $f_1, \dots, f_\ell : [n] \to \mathbb{F}$ and $\delta \in (0, \delta_{\mathrm{PG}})$, with high probability over $\alpha$, the agreement set of the random linear combination $\sum \gamma_i f_i$ with $C$ coincides with the correlated agreement set of $(f_1, \dots, f_\ell)$ with the interleaved code $C^\ell$.

### 4.2 Known Results for Reed–Solomon Codes

- **Unique decoding regime:** RS codes have mutual correlated agreement with $\delta_{\mathrm{PG}} = \delta(C)/2$ and $\varepsilon_{\mathrm{PG}} = n / |\mathbb{F}|$ [BCIKS20; ACFY25].
- **List decoding regime (conjectured):** RS codes have (mutual) correlated agreement with $\delta_{\mathrm{PG}} = 1 - \sqrt{\delta(C)} - \eta$ with error depending on $\eta$ [BCIKS20; ACFY25 conjecture].

### 4.3 Relevance to Accumulation

Mutual correlated agreement is the key ingredient for **twin constraint pseudo-batching** (reducing multiple proximity claims to one). It ensures that when you take a random linear combination of multiple oracles, the agreement set is preserved — which is what makes unbounded-depth accumulation possible while maintaining distance.

It is also critical for the **straightline extraction** strategy: the extractor identifies where the accumulated oracle $f$ agrees with a known codeword $u$, then restricts each input oracle $f_i$ to that agreement set and performs erasure correction to recover the individual codewords.

---

## 5. Out-of-Domain Sampling

### 5.1 Purpose

Out-of-domain (OOD) sampling forces the prover to "commit" to a single codeword in the list $\Lambda(C, f, \delta)$ — essential when working in the list-decoding regime where multiple codewords may be close to $f$.

### 5.2 For Reed–Solomon Codes

Given $f : L \to \mathbb{F}$ close to RS code $C$:
- Verifier sends random $\tau \in \mathbb{F}$ (outside $L$).
- Prover responds with $\sigma = \hat{f}(\tau)$.
- This pins down a unique codeword because distinct polynomials of degree $< d$ can agree at $\tau$ with probability $\leq d / |\mathbb{F}|$.

### 5.3 For CRS and Accumulation

In WHIR's iteration, the OOD sample $z_0$ and answer $y_0$ create an evaluation constraint $\hat{g}(\mathbf{z}_0) = y_0$ that is folded into the recursive weight polynomial. This is what enables distance preservation across iterations.

For accumulation, OOD samples serve a dual purpose: they enforce list-decoding soundness and they generate the evaluation claims that the constrained code relation tracks.

---

## 6. From WHIR to Accumulation: The IOR Framework

### 6.1 The Two Required IORs

Following the Arc/WARP recipe, an accumulation scheme for PESAT (polynomial equation satisfiability) requires two IORs:

1. **PESAT-to-CRS IOR:** Reduces checking $(x, w) \in R_\circledcirc(\mathbb{F})$ to a proximity claim $f \in \mathsf{CRS}[\mathbb{F}, L, m, \hat{w}, \sigma]$, where $f = C(w)$.

2. **CRS-batching IOR:** Reduces $\ell$ proximity claims to CRS into a single proximity claim to CRS. This is the core accumulation step.

### 6.2 Accumulation Relation

The accumulation relation $R_C$ tracks:
- An **explicit instance** $((\alpha, \mu), (\beta, \eta))$: the evaluation claim $\hat{u}(\alpha) = \mu$ and the PESAT constraint $\hat{P}_b(\beta, C^{-1}(u)) = \eta$.
- An **implicit instance** $f : [n] \to \mathbb{F}$: the oracle (Merkle-committed).
- A **witness** $u \in C$: the actual codeword.

Membership means: $u$ is close to $f$, $u$ satisfies the evaluation constraint, and $u$ satisfies the bundled PESAT constraint.

### 6.3 What WHIR Provides

WHIR's iteration naturally performs the CRS-batching step:
- **Input:** $\ell$ oracles $f_1, \dots, f_\ell$ with proximity claims to respective CRS codes (each with their own evaluation and PESAT constraints).
- **Processing:** Twin constraint pseudo-batching (via sumcheck) combines the $\ell$ constraints. Codeword batching (via random linear combination + OOD + shift queries) combines the $\ell$ oracles into one.
- **Output:** A single oracle $f$ with a single proximity claim to a CRS code.

### 6.4 Key Differences from Using WHIR as a Plain IOPP

When adapting WHIR for accumulation (vs. using it as a standalone proof system):

| Aspect | WHIR as IOPP | WHIR for Accumulation |
|--------|-------------|----------------------|
| **Goal** | Decide proximity (accept/reject) | Reduce proximity claims (many → one) |
| **Iteration** | Recursively reduce until trivial | Single-step reduction per accumulation |
| **Output** | Accept/reject bit | New accumulator (instance + oracle) |
| **Distance** | Must be preserved across all iterations | Must be preserved per step (unbounded depth) |
| **Extraction** | Not required (just soundness) | Straightline extraction required (for PCD) |

---

## 7. Compilation: From IOR to Accumulation Scheme

### 7.1 Merkle Commitments

Oracles $f : [n] \to \mathbb{F}$ are committed via Merkle trees. The accumulator stores the Merkle root (short, in the explicit instance) and the full oracle + authentication data (in the witness part).

### 7.2 Fiat–Shamir Transformation

All verifier randomness is derived via a duplex-sponge Fiat–Shamir transformation, absorbing all prover messages and public inputs. This makes the accumulation scheme non-interactive.

### 7.3 Accumulation Scheme Structure

$\mathsf{ACC} = (\mathsf{I_{ACC}}, \mathsf{P_{ACC}}, \mathsf{V_{ACC}}, \mathsf{D_{ACC}})$:

- **$\mathsf{I_{ACC}}(i)$:** Outputs proving/verification keys from the PESAT index.
- **$\mathsf{P_{ACC}}$:** Given $\ell_1$ instance-witness pairs and $\ell_2$ input accumulators:
  1. Encode witnesses → Merkle commit.
  2. Run PESAT-to-CRS reduction (derives bundling randomness via Fiat–Shamir).
  3. Run CRS-batching IOR (sumcheck + codeword batching + OOD + shift queries).
  4. Output new accumulator and proof.
- **$\mathsf{V_{ACC}}$:** Re-derives all Fiat–Shamir randomness, checks sumcheck equations, verifies Merkle openings at shift query positions, checks OOD consistency.
- **$\mathsf{D_{ACC}}$:** Given a final accumulator, checks that the oracle is a valid codeword satisfying the twin constraints.

### 7.4 Accumulator Structure

```
acc.x = (rt, α, μ, β, η)       // Merkle root + evaluation point/value + PESAT point/value
acc.w = (td, f, w)              // Merkle tree data + oracle + decoded witness
```

---

## 8. Security Considerations

### 8.1 Round-by-Round Knowledge Soundness

The IORs must satisfy round-by-round (RBR) knowledge soundness, which implies straightline state-restoration knowledge soundness after Fiat–Shamir compilation. WARP introduces a relaxed variant of RBR knowledge soundness that uses a **knowledge state function** (takes a candidate witness as additional input) and per-round extractors.

### 8.2 Straightline Extraction Strategy

For RS codes with efficient decoding:
1. The extractor receives a valid witness $w'$ for the output accumulator (a codeword $u$ close to the output oracle $f$).
2. It identifies the agreement set $S \subseteq [n]$ where $f$ and $u$ agree ($|S| \geq (1-\delta) \cdot n$).
3. For each input oracle $f_i$, it restricts to $S$ and performs **erasure correction** to recover $u_i$.
4. Erasure correction succeeds because $|S| \geq (1-\delta) \cdot n > (1 - \delta(C)) \cdot n$.

For RS codes this is efficient: erasure correction runs in $O(n \cdot \mathrm{polylog}(n))$.

### 8.3 Field Size Requirements

To achieve security parameter $\lambda$, the field must satisfy:
$$
|\mathbb{F}| \geq 2^\lambda \cdot \mathrm{poly}(\ell, \log M, \log n, |\Lambda(C, \delta)|)
$$

where $|\Lambda(C, \delta)|$ is the list size at distance $\delta$. For RS codes in the unique-decoding regime, $|\Lambda| = 1$; in the list-decoding regime, $|\Lambda|$ depends on the code parameters.

### 8.4 Soundness Error Budget

The total accumulation scheme error decomposes as:
$$
\kappa_{\mathrm{ACC}} \leq (t_{\mathrm{FS}} + k) \cdot \varepsilon_{\mathrm{rbr}} + \kappa_{\mathrm{MT}}(\sigma_{\mathrm{MT}}, t_{\mathrm{MT}}, \dots) + \kappa_{\mathrm{FS}}(t_{\mathrm{FS}})
$$

where $\varepsilon_{\mathrm{rbr}}$ is the IOR's RBR error, $\kappa_{\mathrm{MT}}$ is Merkle extraction error, and $\kappa_{\mathrm{FS}}$ is Fiat–Shamir extraction error.

---

## 9. Parameter Tradeoffs for a WHIR Accumulation Scheme

### 9.1 Folding Parameter $k$

- Larger $k$: fewer iterations to reach trivial code, but $2^k$ symbols read per query and rate decreases faster ($\rho' = 2^{1-k} \rho$).
- For accumulation (single-step reduction): $k$ affects the number of sumcheck rounds and query cost per shift query.

### 9.2 Repetition Parameter $t$

- Controls soundness: error per iteration is $(1 - \delta)^t$.
- Need $t \geq \lambda / (-\log(1 - \delta))$ for $\lambda$ bits of security.
- Larger $t$ means more verifier queries → larger accumulation verifier circuit (relevant for recursion overhead in PCD).

### 9.3 Proximity Bound $\delta$

- Larger $\delta$ (closer to list-decoding capacity): fewer queries needed, but requires larger fields and conjectured list-decoding bounds.
- Smaller $\delta$ (unique-decoding regime): proven security, can avoid OOD samples, but more queries needed.
- Recommendation from WARP: use the largest provable/conjectured $\delta$ for best verifier efficiency.

### 9.4 Rate $\rho$

- Smaller rate: better distance ($\delta(C) = 1 - \rho$ for MDS codes), fewer queries, smaller proofs — but larger codewords and more prover work.
- RS codes are MDS, so they have optimal rate-distance tradeoff (unlike general linear-time codes).

---

## 10. Advantages of WHIR for Accumulation (vs. Alternatives)

1. **Native constraint handling:** CRS codes directly express evaluation + PESAT constraints without auxiliary oracles or quotients.
2. **Single oracle per step:** WHIR's iteration sends one oracle (unlike Arc which sends two), reducing Merkle commitment costs.
3. **List-decoding support:** Fewer verifier queries (conjectured; unique-decoding is proven).
4. **Multilinear integration:** The multilinear view of RS codewords is compatible with sumcheck-based constraint batching.
5. **Quasilinear prover:** RS encoding is $O(n \log n)$ via FFT; WHIR's prover is dominated by this cost. (Note: not linear-time like WARP with expander codes, but concretely fast.)
6. **Concrete efficiency:** WHIR's verification is microsecond-scale, directly translating to a small accumulation verifier circuit.

---

## 11. Key References

- **WHIR:** Arnon, Chiesa, Fenzi, Yogev. "WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification." EUROCRYPT 2025. ePrint 2024/1586.
- **STIR:** Arnon, Chiesa, Fenzi, Yogev. "STIR: Reed–Solomon Proximity Testing with Fewer Queries." CRYPTO 2024.
- **Arc:** Bünz, Mishra, Nguyen, Wang. "Arc: Accumulation for Reed–Solomon Codes." CRYPTO 2025. ePrint 2024/1731.
- **WARP:** Bünz, Chiesa, Fenzi, Wang. "Linear-Time Accumulation Schemes." 2025.
- **Accumulation without Homomorphism:** Bünz, Mishra, Nguyen, Wang. ITCS 2025. ePrint 2024/474.
- **Proximity Gaps for RS:** Ben-Sasson, Carmon, Ishai, Kopparty, Saraf. FOCS 2020.
- **BCS Transformation:** Ben-Sasson, Chiesa, Spooner. "Interactive Oracle Proofs." TCC 2016.
- **BaseFold:** Zeilberger, Chen, Fisch. CRYPTO 2024.
