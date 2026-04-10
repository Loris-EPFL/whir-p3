# VEIL: Lightweight Zero-Knowledge for Hash-Based Multilinear Proof Systems

**Rahul Dalal, Tamir Hemo, Eugene Rabinovich, and Ron D. Rothblum**
Succinct
March 23, 2026

Emails: {rahul, tamir, eugene, ron}@succinct.xyz

## Abstract

As efficient proof systems mature rapidly, more practical use cases that require zero-knowledge (ZK) guarantees are arising. Adding ZK typically requires either composing the non-zk base system with an expensive zk one that proves correctness of the cryptographic hashes performed by the base verifier, or alternatively making tightly coupled modifications to every component of the base protocol.

We introduce VEIL, a lightweight and non-intrusive compiler for hash-based multilinear proof systems. VEIL achieves ZK without these drawbacks. Our approach decouples the protocol's algebraic interactions from the cryptographic hashing and applies a ZK wrapper solely to the algebraic components. This results in a simple protocol that achieves a minimal prover overhead of `(1 + o(1))`, while maintaining the architectural integrity of the base proof system.

Our proof-of-concept implementation demonstrates that, over a 31-bit base prime field, for a trace of `2^29` field elements, compared to the non-zk proof system, VEIL has a prover overhead of about 3%, verifier overhead of 22% and proof-size overhead of 12%.

---

## 1. Introduction

Recent years have seen a rapid advancement in the design of efficient proof-systems. The initial key catalyst for the development of proof-systems was the invention of zero-knowledge proofs [GMR89] — these are proof-systems that reveal nothing beyond the correctness of the computation. While the field originated from this seminal work, in recent years much of the focus (in the applied world) has been on developing proof-systems that offer succinct verification [BFLS91, Kil92, Mic00] of complex computational statements, but are not necessarily zero-knowledge. As these practical proof-systems mature, and additional use cases arise, there is often a critical need for them to actually offer zero-knowledge (zk) guarantees, so as to protect sensitive witness data.

The "common wisdom" is that converting a succinct proof-system to be zk is not difficult. Indeed, there are a plethora of methods to do so. For example, the classical approach, originating with Ben-Or et al. [BGG+88], is to compose a base proof-system with an inner zero-knowledge proof system. At a high-level, the prover commits to the non-zk proof and then proves, using an inner zero-knowledge proof-system, that the original verifier would have accepted. This methodology, which arose in the theory literature already in the 80's, is heavily utilized in practical systems such as Orion [XZS22] as well as many modern zkVMs, which often employ a final wrapping phase using a ZK proof system such as Plonk [GWC19] or Groth16 [Gro16].

While conceptually simple and highly modular, this approach can be quite expensive in practice: it forces the inner ZK proof system to prove statements involving complex cryptographic hashing (such as verifying Merkle tree paths). Evaluating these cryptographic hash functions inside an arithmetic circuit introduces massive computational overhead (especially if the field used differs from that of the outer proof-system), thereby bottlenecking the entire system. Additionally, this approach introduces highly undesirable latency since the inner proof can only start once the base proof is completed.

An alternative approach is to "ZK-ify" each individual component of the proof-system from the ground up — thereby modifying various components such as the proximity tests, sumcheck protocols and other connecting components to natively be zero-knowledge. This approach, considered in a line of work [CFS17, BCF+17, BCR+19, XZZ+19, BCL22, HK24, RW24, Dia25] originally introduced at least a constant prover overhead over the non-zk variant of the protocols, but has been recently highly optimized to achieve minimal (additive) overheads [CFW26]. Still, the main caveat is that this approach is highly intrusive to the code base: it requires surgical changes to every part of the protocol, deeply coupling the ZK logic with the base proof-system. As multilinear proof systems rapidly evolve, maintaining, updating and auditing these tightly coupled, bespoke ZK components becomes an unsustainable engineering burden.

**Remark 1.1.** Throughout this work we focus on hash-based proof-systems. We remark that additional techniques can be leveraged when relying on homomorphic cryptographic primitives (e.g., relying on the hardness of discrete log or lattice assumptions). See, e.g., the recent work [KS25].

### 1.1 Our Contribution

We propose a new simple and practical method for compiling a large class of non-zk proof-systems to be zk. The key benefits of our method are that:

1. It is computationally lightweight (both for the prover and verifier); and
2. It is architecturally "non-intrusive", meaning that zk is added as a "wrapper" over an existing non-zk proof-system, making it far more maintainable.

Thus, we present VEIL, a lightweight compiler for the "ZK-ification" of suitable hash-based multilinear proof-systems. VEIL strikes a balance between the two lines of work mentioned above, achieving modularity close to that of the composition approach [BGG+88] but without the high overhead of full recursive proving. We emphasize that we do not aim to achieve optimal asymptotics as in [CFW26] and take a more practical perspective — specifically, we target a multiplicative prover overhead of `(1 + o(1))` rather than insisting on additive poly-logarithmic overhead, as in [CFW26].

Specifically, we focus on multilinear hash-based proof-systems. We observe that such systems generally follow a common structural pattern:

1. The prover first commits to the multilinear extension of the computation trace.
2. The prover and verifier then engage in an interactive phase that relies purely on field arithmetic. In this phase, all communication between prover and verifier is "in the clear" (i.e., is not mediated by oracles).
3. The protocol ultimately reduces to a multilinear evaluation claim on the trace, which is proven by the verifier relative to the original commitment.

Following the terminology of Kalai and Raz [KR08], we refer to such a protocol as a multilinear interactive PCP.

Moreover, we leverage the fact that hash-based multilinear polynomial commitment schemes used in practice typically have the following structure: the data is embedded within a tall matrix `M`. The prover encodes each column of this matrix using a Reed-Solomon code and sends an oracle in which each symbol corresponds to a full row of the encoded matrix. For the evaluation proof, the verifier chooses a random linear combination of the columns and then the prover and verifier engage in a proximity proof relative to (a constrained variant of) the code. Examples for practical proximity tests for such constrained Reed-Solomon codes include Basefold [ZCF24], WHIR [ACFY25] and Ligerito [NA25].

Popular multilinear hash-based proof-systems, ranging from the Kalai-Raz [KR08] IPCP to the recent SP1 Hypercube proof-system [SP1], can be captured via this abstraction.

### 1.2 Our Approach

We propose a lightweight and simple method (which we call VEIL) to compile multilinear proof-systems to be zk. Our approach is inspired by and generalizes an approach proposed recently by Frigo and shelat [FS24], which is itself inspired by [AHIV17, WTS+18]. In particular, we rely on common techniques that are widely used in zero-knowledge protocols, but, to the best of our knowledge, we utilize them in a manner that is particularly lightweight and easy to maintain.

The main components of VEIL are:

- **Trace Queries:** To protect the raw computation trace, we pad each column with `q` random field elements before encoding, where `q` is the query complexity of the proximity test. Intuitively, using the fact that the Reed-Solomon code is a "zk-code" [DGR20, ISVW13], this protects the row openings. We "hide" the cost of this padding by maintaining the same codeword length `n` for the Reed-Solomon codewords and only slightly increasing their message sizes. This reduces the distance from `delta` to `delta - q/n` (concrete parameters to bear in mind are `delta = 1/2`, `q = 2^7` and `n = 2^21`, making this cost negligible).

- **The Proximity Test:** To ensure the final proximity test does not leak information, we append a single additional uniformly random column to the matrix to blind the verifier's random linear combination. Note that this means that the underlying proximity test is being run on a random vector and so we do not need for the proximity test itself to be zero-knowledge. The additional cost here is adding a column to the matrix. Assuming initially the matrix had `t` columns, the multiplicative prover overhead is roughly `1 + 1/t`. In practice a typical setting of `t` would be `t = 2^7`, and so the overhead is less than 1%.

- **The Interactive Transcript:** With the oracle queries protected by the padding above, we are left only with the interactive phase of the protocol. Crucially, because this phase strictly involves algebraic constraints and does not involve cryptographic hashing, we can utilize the classical Ben-Or et al. approach. Thus, we wrap this specific, lightweight portion of the computation using an "off-the-shelf" zero-knowledge proof system.

  In more detail, suppose that in this part of the protocol the prover needs to send a total of `c` field elements. Then, in our compiled protocol the prover first commits to a random vector `r in F^c`. For every `i in [c]`, instead of sending the `i`-th symbol `tau_i` of the transcript, the prover sends `tau'_i = tau_i + r_i`. At the end of this phase the prover sends an additional zero-knowledge proof that the commitment to `r` could be opened so that `tau' - r` satisfies the base verifier's decision predicate.

By decoupling the algebraic interaction from the heavy cryptographic commitments, the inner zero-knowledge proof-system that we use will be run on a small and purely algebraic statement (i.e., one not involving any hashing). We further observe that in typical hash-based schemes the communication is very much dominated by the proximity test. Thus, we do not even need for the zero-knowledge proof of the interactive part to be succinct (e.g., the communication can be linear in the base verifier's decision predicate).

The approach results in a non-intrusive compiler that avoids proving cryptographic hashes in circuits entirely, yielding minimal computational overhead and preserving ease of maintenance of the underlying codebase.

**Remark 1.2.** Shielding the proximity test by appending the trace with an extra random column may seem like overkill, but simplifies the protocol considerably. Indeed, since the amount of data revealed in the proximity test is much smaller than a full column, adding such a large amount of entropy seems excessive. Striving for optimal efficiency, one might instead try to modify the proximity test to be zk — indeed, this is the approach taken by [CFW26]. We avoid doing so since this is quite complex and less robust to changes, whereas the additional random column that we add introduces only a very small concrete overhead.

**The Inner ZK Proof-System.** As noted above, for the "off-the-shelf" zk proof-system we could use any existing zk system. One appealing choice is to use the zk variant of Ligero [AHIV17], which even offers a partially succinct proof.

In our implementation we actually construct a new proof-system. The proof-system has a more efficient prover than Ligero (in the regime we focus on in which most of the computation is linear) but on the other hand is not succinct.

The bird's eye view is a similar approach to the Ligero zero-knowledge variant except that we do not embed the data in a matrix but rather keep it as a vector. Doing so lets us avoid using expensive multiplication codes for checking linear claims in the proof (concretely we still use the Reed-Solomon code, but save the cost of the inverse FFT required for the evaluation→evaluation representation used in Ligero).

**Remark 1.3.** Throughout this work, for the sake of simplicity, we rely exclusively on proximity gaps in the unique decoding regime (rather than list decoding bounds). For the outer (non-zk) proof-system, adapting the construction to the list decoding regime is straightforward. The inner proof-system requires more care and while we believe it can also be adapted to this regime, we leave this to future work.

### 1.3 Organization

We begin in Section 2 with preliminaries. Then, in Section 3 we present sub-protocols that will be used within our inner zk proof-system. The zk compiler is then presented in Section 4. Finally, we report on our benchmarks in Section 5.

---

## 2. Preliminaries

We use `F` to denote a finite field and use `F^x` to denote its multiplicative subgroup `F^x = F \ {0}`.

For `a, b in F^n`, the relative distance `d_rel(a, b)` is the fraction of coordinates `i in [n]` at which `a_i != b_i`. For a (non-empty) subset `S subset F^n`, we define `d_rel(a, S) := min_{s in S} d_rel(a, s)`.

Given vectors `c_1, ..., c_t in F^n`, we denote by `[c_1, ..., c_t]` the `n x t` matrix whose columns are the `c_i`. We extend relative distance to matrices row-wise: for `[x_1, ..., x_t], [x'_1, ..., x'_t] in F^(n x t)`, we set

```
d_rel([x_1, ..., x_t], [x'_1, ..., x'_t])
```

to be the fraction of row indices at which the corresponding rows differ in any coordinate. Similarly, for a non-empty subset `S subset F^(n x t)`, we define `d_rel([x_1, ..., x_t], S)` to be the minimum of this row-wise distance over all elements of `S`.

### 2.1 Error-Correcting Codes

An error-correcting code over an alphabet `Sigma` is an injective mapping `C : Sigma^n -> Sigma^m`, for `n, m in N`. The rate of the code is `n/m` and its relative distance is defined as `min_{x != x'} d_rel(C(x), C(x'))`. The code is linear if `Sigma` is a finite field `F` and `C` is a linear function over the field.

#### 2.1.1 Zero-Knowledge Codes

**Definition 2.1 (ZK Code [DGR20, ISVW13]).** An error correcting code `C : F^n x F^k -> F^m` is a `k`-zero-knowledge code if for any set `I subset [m]` of size `k`, for any fixed `w in F^n`, the projection of `C(w, r)` onto the coordinates of `I` is uniformly distributed whenever `r in F^k` is uniformly distributed.

**Remark 2.2.** It can be quickly seen that a linear code `C : F^n x F^k -> F^m` is `k`-zk if the composition

```
F^k --iota_2--> F^n x F^k --C--> F^m --p--> F^k
```

is full-rank whenever `iota_2` is the inclusion into the second factor and `p` is the projection onto some subset of `k` coordinates.

#### 2.1.2 Multiplicative Codes

**Definition 2.3.** Let `a, b in F^m`. Then the Hadamard product `a * b` is the pointwise product defined by `(a * b)_i := a_i · b_i`.

**Definition 2.4.** A linear error correcting code `C : F^n -> F^m` is multiplicative if:

- `1 := (1, ..., 1) in C`.
- There is an associated linear product code `C^* : F^(n*) -> F^m` such that for all `v_1, v_2 in C`, we have `v_1 * v_2 in C^*`.

**Remark 2.5.** In the literature, multiplicative codes are usually systematic, which is impossible here because we require codes to be zk. This creates ambiguity in exactly how the message spaces for `C, C^*` are represented—our codes really need to be thought of as maps instead of subspaces. The extra condition `1 in C` allows us to resolve the relative ambiguity between the representations for `C` and `C^*` as explained below.

Given such a multiplicative code `C`, we get a linear map `S := S_C : F^n -> F^(n*)` mapping `a in F^n` to the element `u` such that `C^*(u) = C(a) * 1`. Furthermore, this satisfies that `C = C^* ∘ S`. If `D : F^(n*) -> F^n` is a section of `S`, then this defines a vector product `P` on `F^n` given by `P(a, b) = D(u)` where `C^*(u) = C(a) * C(b)`.

**Lemma 2.6.** There exists an invertible `r : F^n -> F^n` such that for the code `C' := C ∘ r^(-1)`, there exists a section `D` of `S_{C'}` such that for all `a, b in F^n`, if `u` is the element such that `C^*(u) = C(a) * C(b)`, then `D(u) = a * b`.

*Proof.* This is equivalent to finding `D` such that the `P` induced as above is the Hadamard product. There exists a subset `I` of the coordinates of `F^m` such that if `p_I` is the corresponding coordinate projection on `F^m`, then the function `w := p_I ∘ C` is an isomorphism. Consider `D_0 := w^(-1) ∘ p_I ∘ C^*`.

Denote by `e_i` for `i in [n]` the standard coordinate vectors of `F^n`. Then `D_0` induces the Hadamard product in the basis `w^(-1)(e_i)` for `i in I`. Therefore, if `r` is the linear map defined on bases by `w^(-1)(e_i) -> e_i`, we have that `D := r ∘ D_0` suffices for the given `r`. ∎

**Definition 2.7.** We say a code `C` is in good form if `r` being the identity suffices in Lemma 2.6.

A slightly notation-abusing mnemonic is that `D` satisfies

```
(D ∘ (C^*)^(-1))(C(a) * C(b)) = a * b   for all a, b in F^n.
```

**Definition 2.8.** Let `C : F^n -> F^m` be a multiplicative code in good form with product code `C^* : F^(n*) -> F^m`. Call a function `D` produced from Lemma 2.6 a reduction function for `C`.

**Examples of Multiplicative Codes.** Next, we present two variants of the Reed-Solomon code and show that they are zk-codes.

**Example 2.9.** Let `Xi subset F` be a multiplicative subgroup of size `2^m`. Let `C : F^n -> F^(2^m)` be the coefficient-to-evaluation Reed-Solomon code given by `C((a_i))` being the evaluations of the degree-`(n-1)` polynomial with coefficients `a_i` on `Xi`.

Then `C` is an `n`-zk-code (e.g., by Remark 2.2 and the full rank of Vandermonde matrices). Through the FFT algorithm, it may be encoded in time `O(m · 2^m)`.

**Example 2.10.** Let `Xi subset F` be a multiplicative subgroup of size `2^m`, `Xi_0 subset Xi` a subgroup of size `2n`, and `zeta_{2^(m+1)} in F` a `2^(m+1)`-th root of unity. Let `C : F^(2n) -> F^(2^m)` be the interpolation Reed-Solomon code such that `C((a_i))` is computed by interpreting the `a_i` as the evaluations of a degree-`(2n-1)` polynomial on `Xi_0` and then evaluating the polynomial on `zeta_{2^(m+1)} · Xi`.

Then `C` is a multiplicative `2n`-zk-code in good form. Through the FFT algorithm it can be encoded in time `O(m · 2^m)`, though with larger constant factors than coefficient-to-evaluation Reed-Solomon. One choice of product code interpolates evaluations on `Xi_1` to `zeta_{2^(m+1)} · Xi`, where `Xi_1` is the order-`2^(n+1)` subgroup of `Xi`. One choice of reduction `D` is just function restriction which takes time `O(m)`.

### 2.2 Interactive Oracle Proofs

We next define the notion of interactive oracle proof, due to [BCS16, RRR21].

An `ell`-round (public-coin) interactive oracle protocol consists of two entities, a prover `P` and a verifier `V` who interact with each other over `ell` rounds on a common input `x`. The prover additionally receives an input `w` called the witness. In each round the prover may send either long oracle messages from which the verifier reads a few of the symbols, or short messages that are read entirely.

The key parameters that we will care about are:

1. **Query Complexity:** the number of bits that the verifier reads from the prover's oracle messages.
2. **Round complexity:** the number of rounds `ell`.
3. **Communication complexity:** the total length of `P`'s direct messages.
4. **Verifier and Prover complexities:** the computational complexity of the verifier and prover.

**Definition 2.11 (Interactive oracle proof (IOP)).** An `ell`-round interactive oracle proof (IOP) with soundness error `epsilon` for a relation `R` is an `ell`-round (public-coin) interactive oracle protocol `(P, V)` such that

- **Completeness:** If `(x, w) in R` then when `V` interacts with `P`, it accepts with probability 1.
- **Soundness:** If `x` is such that for every `w` it holds `(x, w) not in R`, then for every prover strategy `P*`, when `V` interacts with `P*`, it accepts with probability at most `epsilon`.

**Definition 2.12 (Zero-Knowledge IOP).** An IOP for relation `R` is zero-knowledge (zk) if there exists a probabilistic polynomial-time simulator `Sim` such that for every randomness `r in {0,1}^*` for `V` and `(x, w) in R`, it holds that `Sim(r, x)` is distributed identically to the tuple of all messages received from `P` and oracle query responses received by `V` when interacting with `P` on input `(x, w)` using randomness `r`.

### 2.3 Multilinear Interactive Oracle Proofs

Our compilation scheme works for any protocol in a class we define of Multilinear Interactive Oracle Proofs, or MIOPs.

#### 2.3.1 Multilinear Polynomials

A polynomial `f_hat : F^n -> F` is multilinear if it has individual degree at most 1 in each variable. We represent a multilinear polynomial by its vector of evaluations `f_hat = (f_i)_i in F^(2^n)` on `{0,1}^n`, where the `i`-th coordinate corresponds to the element of `{0,1}^n` representing `i` in binary — this uniquely determines `f_hat` by the process of multilinear extension:

Define the equality polynomial `eq : F^n x F^n -> F` by

```
eq(x, z) := prod_{i=1}^n (x_i z_i + (1 - x_i)(1 - z_i))
```

This restricts to the indicator function of the diagonal in `({0,1}^n)^2`; i.e., for `x, y in {0,1}^n` we have `eq(x, y) = 1` if `x = y` and 0 otherwise.

The multilinear extension of `f_hat : {0,1}^n -> F` can then be given by

```
F_hat(z) = sum_{x in {0,1}^n} f(x) · eq(x, z)
```

In particular, `(eq(x, z_0))_{x in {0,1}^n}` gives the coefficients of the linear combination that evaluates any multilinear polynomial at `z_0 in F^n` from its values on `{0,1}^n`.

#### 2.3.2 MIOPs

**Definition 2.13.** A Multilinear Interactive Oracle Proof (MIOP) is an IOP that satisfies the following:

- All messages sent by `P` are either elements of some finite field `F` or oracles for evaluations of multilinear polynomials on `F^n` for some `n`.
- All messages sent by the verifier are random coin tosses (where the number of messages and their format are fixed beforehand).
- The verifier accepts or rejects by, at the end of the interaction, only checking polynomial conditions with inputs that are either prover messages in `F` or evaluations of one of the multilinear oracles at some publicly-known point.

We say that the protocol `(P, V)` is an MIOP for a relation `R` with soundness error `2^(-lambda)`, if the following two conditions hold:

- **Completeness:** if `(x, w) in R` then `V` accepts with probability 1 when interacting with `P`.
- **Soundness:** if for every `w` it holds `(x, w) not in R`, then for any prover strategy `P*`, the verifier `V` accepts when interacting with `P*` with probability at most `2^(-lambda)`.

### 2.4 Proximity Gaps

We now recall a key property needed for proving soundness of protocols. Given a code `C : F^n -> F^m`, we write `C^t` for the interleaved code: the set of matrices `[c_1, ..., c_t] in F^(m x t)` whose columns each lie in the image of `C`. The distance measure `d_rel` is essentially treating `C^t` as a (non-linear) code of length `m` with alphabet `F^t`.

**Definition 2.14 (Proximity Generator).** Let `C : F^n -> F^m` be an error-correcting code, `t in N`, and `delta, eps_PG(m, |F|) > 0`. A distribution `PG` over `F^t` is a `(delta, eps_PG)`-proximity-generator for `C` if for all `delta' <= delta` and all `A in F^(m x t)`,

```
d_rel(A, C^t) >= delta'  ==>  Pr_{rho <- PG}[d_rel(A · rho, C) < delta'] <= eps_PG(m, |F|).
```

**Remark 2.15.** Note also the important companion fact that if `d_rel(A, C^ell) <= delta'`, then `d_rel(a, C) <= delta'` for any `a` in the column span of `A`.

We associate two additional parameters to a probability distribution `PG ~ F^t`. Its "linear bias" [NN93] and its randomness complexity.

**Definition 2.16 (Linear Bias and Randomness Complexity).** Let `PG` be a distribution over `F^t`.

- The (linear) bias of `PG` is `eps^•_PG := max_{v in F^t \ {0}} Pr_{rho <- PG}[rho · v = 0]`.
- The randomness complexity of `PG`, denoted `c(PG)`, is the number of independent uniform field elements needed to sample from `PG`.

**Remark 2.17.** Note that if `PG` is a proximity generator, `eps^•_PG <= eps_PG(m, |F|)` by applying the proximity gaps definition to rank-1 matrices `v · x^T`.

**Example 2.18.** Some commonly studied PG are:

1. **Linear:** `(rho, 1) in F^2` for `rho` uniform over `F`. This has linear bias `eps^•_PG = 1/|F|`.
2. **Degree-`t`:** `(rho^t, ..., rho^2, rho, 1) in F^(t+1)` for `rho` uniform over `F`. This has linear bias `eps^•_PG = t/|F|`.
3. **`t`-MLE:** If `t` is a power of 2, the PG is `(eq(x, z_0))_{x in {0,1}^(log t)} in F^t` where `z_0` is sampled uniformly over `F^(log t)`. This has linear bias `eps^•_PG = log t / |F|`.

Note that these proximity gaps properties only depend on the image of `C`, not its method of encoding. Furthermore, if `PG` is a proximity generator for `C` then any restriction of `PG` to some subset of coordinates is also a proximity generator with the same parameters (e.g., by specializing to matrices `A` with corresponding all-zero rows).

**Example 2.19 ([BCI+23, DP24b]).** Let `C : F^n -> F^m` be a Reed-Solomon code. Then it has minimum relative distance `Delta = 1 - n/m`. It has `(delta, eps_PG)`-proximity gaps up to `Delta/2` for the following PG, `eps_PG`:

- **Degree-`t`:** `eps_PG(m, |F|) = m · t / |F|`
- **`t`-MLE:** `eps_PG(m, |F|) = m · log t / |F|`

#### 2.4.1 Zero-Knowledge Proximity Generators

To achieve zero-knowledge we will need PG that allow us to add a "mask" with a guaranteed non-zero coefficient.

**Definition 2.20.** A proximity generator `PG ~ F^t` for some code `C` is zero-knowledge (zk) if it is supported on `F^(t-1) x F^x`.

We can modify Example 2.18 to get zk-versions.

**Example 2.21.** Some zk-PG are:

1. Linear
2. Degree-`t`
3. **augmented `t`-MLE:** If `t` is a power of 2, the PG is `((eq(x, z_0))_{x in {0,1}^(log t)}, 1) in F^(t+1)` where `z_0` is sampled uniformly over `F^(log t)`. This has linear bias `eps^•_PG = log(t)/|F|`.

It can then be seen that

**Lemma 2.22.** Let `C : F^n -> F^m` be a Reed-Solomon code. Then it has minimum relative distance `Delta = 1 - n/m`. It has `(delta, eps_PG)`-proximity gaps up to `Delta/2` for the following PG, `eps_PG`:

- **augmented `t`-MLE:** `eps_PG(m, |F|) = m · log(t) / |F|`

---

## 3. Commit-and-Prove Interactive Oracle Schemes

In this section, we describe several related commit-and-prove protocols. These will be key components of our compilation step. We start by introducing a general framework for commit-and-prove interactive oracle schemes, which captures the common structure of our protocols.

**Definition 3.1 (Commit-and-Prove IOP).** Let `W` be a witness space, `X` be an explicit input space, and `R subset W x X` be a relation. A commit-and-prove interactive oracle scheme for `R` consists of three probabilistic polynomial-time algorithms `(Commit, P, V)` with the following semantics:

- `Commit(w)`: Takes as input a witness `w in W` and outputs an oracle string `C`.
- `(P, V)`: Form an interactive oracle protocol where `V` gets as input oracle access to `C` (and potentially other oracles sent during the protocol) and explicit access to `x in X`, while `P` gets as input `w` and `x`.

We require the following properties:

1. **Completeness:** If `(w, x) in R`, then `V` accepts with probability 1 when interacting with `P` and given oracle `C = Commit(w)`.
2. **Binding:** For every commitment oracle `C`, there exists `w in W` such that for every `x` with `(w, x) not in R` and for every prover `P*`, the verifier `V` rejects with all but `2^(-lambda)` probability when interacting with `P*` and given inputs `C, x`. We call `2^(-lambda)` the binding error.

**Definition 3.2.** We say that a commit-and-prove oracle scheme for `R` is zero-knowledge if there exists a probabilistic polynomial-time simulator `Sim` such that for every randomness `r in {0,1}^*` for `V`, commitment oracle `C = Commit(w)`, and explicit input `x` with `(w, x) in R`, it holds that `Sim(r, x)` is distributed identically to the tuple of all messages received from `P` and oracle query responses received by `V` when interacting with `P` on input `C, x` using randomness `r`.

### 3.1 ZK Lin-Eval PCS

The first protocol allows one to commit to a vector in `F^n` so that later linear function evaluations can be proved about the committed vector with zero-knowledge.

**Definition 3.3 (Linear Evaluation Scheme).** A linear evaluation interactive oracle commitment scheme is a commit-and-prove IOP (Definition 3.1) with:

- Witness space `W = F^n`,
- Explicit input space `X = F^n x F` (pairs `(ell, alpha)`),
- Relation `R = {(w, (ell, alpha)) : <w, ell> = alpha}`.

**Lemma 3.4.** Let `C : F^(n+k) -> F^m` be a `k`-zk-code with minimum distance `Delta` with `PG ~ F^2` a zk `(delta, eps_PG)`-proximity-generator for `C` with `delta <= Delta/2`. Then there exists a zk linear evaluation interactive oracle commitment scheme with the following parameters:

- **Query Complexity:** `k` queries to the commitment oracle with an alphabet size of 2 field elements.
- **Binding error:** `eps_PG(m, |F|) + (1 - delta)^k`.
- **Commit Time:** `2 · T_C(n) + O(n)`, where `T_C(n)` is the encoding time of `C`.
- **Prove Time:** `O(n)`.
- **Verify Time:** `T_C(n) + O(n)`.
- **Message Complexity:** `n + k + 1` prover and `c(PG)` verifier field elements.

Furthermore, this protocol takes the form of an interaction phase in which no queries are made to the commitment oracle followed by a query phase in which `k` i.i.d. uniform queries are made.

#### 3.1.1 Proof of Lemma 3.4

The commitment algorithm and evaluation protocol are described, respectively, in Figs. 1 and 2.

**Figure 1: Linear Evaluation Commitment**

Parameters: `k`-zk code `C : F^(n+k) -> F^m`
Input: vector `w in F^n`

1. `P` generates a masking vector `r in F^n` uniformly at random.
2. `P` generates two padding vectors uniformly at random in `F^k` and appends them to `w, r` respectively, producing `w', r' in F^(n+k)`.
3. `P` computes `c = C w'` and `c' = C r'`. It generates and sends the interleaved codeword `C in F^(2 x m)`, where `C_{0,i} = c_i` and `C_{1,i} = c'_i`, for all `i in [m]`, as the commitment oracle.

**Figure 2: Linear Evaluation Protocol**

Parameters: Zk proximity generator `PG ~ F^2` for `C`
Public Input: commitment `C in F^(2 x m)`, linear function `ell : F^n -> F`, claimed evaluation `alpha in F`.
Prover Private Input: `w', r' in F^(n+k)` from the commitment phase.

*Interaction Phase*

1. `P` sends `beta := ell(r)`, where `r` is the `n`-symbol long prefix of `r'`.
2. `V` sends random `(rho_1, rho_2) <- PG`.
3. `P` sends as an explicit message `x' = rho_1 · w' + rho_2 · r'`.
4. `V` checks that `ell(x) = rho_1 · alpha + rho_2 · beta`, where `x` is the `n`-symbol prefix of `x'`.

*Query Phase*

5. `V` samples `i_1, ..., i_k in [m]` i.i.d. uniformly at random.
6. For each `j in [k]`: `V` queries the `i_j`-th column of `C` and checks that `rho_1 · C_{0, i_j} + rho_2 · C_{1, i_j} = (C x')_{i_j}`.

**Completeness.** All checks follow from linearity of `ell` and `C`: the interaction-phase check gives `ell(x) = rho_1 ell(w) + rho_2 ell(r) = rho_1 alpha + rho_2 beta`, and the query-phase check gives `rho_1 C_{0,i} + rho_2 C_{1,i} = rho_1 (C w')_i + rho_2 (C r')_i = (C x')_i`.

**Binding.** Let `C = [C_0, C_1] in F^(2 x m)` be an arbitrary commitment oracle. Let `[N'_0, N'_1] in F^(2 x n)` denote the nearest preimage of `C` under `C^2` (breaking ties arbitrarily) and `[N_0, N_1]` its first `n` coordinates. Consider the bound witness `w* := N_0`.

Fix a cheating prover `P*` and a false claim `(ell, alpha)` with `alpha != <w*, ell>`. Let `beta` be the prover's first message, and let `x'` be the message sent in response to `(rho_1, rho_2)` (which may depend on `(rho_1, rho_2)`).

*Step 5 catches malformed oracles.* Either `d_rel([C_0, C_1], C^2) < delta` or not. In the second case, we apply the proximity gaps property (Definition 2.14): `d_rel(rho_1 C_0 + rho_2 C_1, C) >= delta` except with probability at most `eps_PG(m, |F|)` over `(rho_1, rho_2)`. Since `C x' in C`, this gives `d_rel(C x', rho_1 C_0 + rho_2 C_1) >= delta`, so all `k` queries pass with probability at most `(1 - delta)^k`.

*Step 4 catches false evaluations.* We may therefore assume that `d_rel([C_0, C_1], C^2) < delta`. If the prover sends `x'` with prefix `x = rho_1 N_0 + rho_2 N_1`, then Step 4 requires

```
rho_1 (ell(N_0) - alpha) + rho_2 (ell(N_1) - beta) = 0.
```

Since `ell(N_0) != alpha`, the coefficient vector `(ell(N_0) - alpha, ell(N_1) - beta)` is nonzero, so the equation holds with probability `<= eps^•_PG`.

*Step 5 catches inconsistent openings.* We may therefore further assume that `x != rho_1 N_0 + rho_2 N_1`, which implies `x' != rho_1 N'_0 + rho_2 N'_1`, giving `d_rel(C x', C(rho_1 N'_0 + rho_2 N'_1)) >= Delta` by the minimum distance of `C`. On the other hand, since `d_rel([C_0, C_1], C^2) < delta`, the companion fact gives `d_rel(rho_1 C_0 + rho_2 C_1, rho_1 C N'_0 + rho_2 C N'_1) < delta`. Therefore, by the triangle inequality,

```
d_rel(C x', rho_1 C_0 + rho_2 C_1) >= Delta - delta >= delta.
```

Then each query in Step 5 detects the mismatch with probability at least `delta`, so all `k` queries pass with probability at most `(1 - delta)^k`.

Union bounding within each case and taking a max gives the stated error, using `eps^•_PG <= eps_PG(m, |F|)` (Remark 2.17) to absorb the second case into the first.

**Zero-knowledge.** We construct a simulator `Sim` whose output is distributed identically to the verifier's view in an honest execution. The simulator receives as input the linear function `ell : F^n -> F`, the claimed evaluation `alpha in F`, and the verifier's randomness: `(rho_1, rho_2)` and the multiset of query indices `I` from Step 5. It must produce `beta, x'` and oracle query responses `(C'_{0,i}, C'_{1,i})` for each unique `i in I`. We define `Sim` as follows:

1. Sample `x' in F^(n+k)` uniformly at random. Set `beta := rho_2^(-1) · (ell(x) - rho_1 alpha)`, where `x` is the length-`n` prefix of `x'`.
2. For each unique `i in I`: sample `C'_{0,i} in F` uniformly at random and set `C'_{1,i} := rho_2^(-1)((C x')_i - rho_1 C'_{0,i})`.

By construction, `Sim`'s output satisfies all of `V`'s checks. We now show that for any fixed verifier randomness `((rho_1, rho_2), I)`, the verifier's view in an honest execution has the same distribution.

*Free and determined variables.* For each `i in I`, the query-phase check `rho_1 C_{0,i} + rho_2 C_{1,i} = (C x')_i` uniquely determines `C_{1,i}` from `(x', C_{0,i})` (since `rho_2 != 0` as `PG` is zk). In an honest execution (where `ell(w) = alpha`), the explicit-message check `ell(x) = rho_1 alpha + rho_2 beta` is identically satisfied, so `beta` is determined by `x'` via `beta = rho_2^(-1)(ell(x) - rho_1 alpha)`.

Since both `Sim` and the honest prover compute `(beta, C_{1,i})` using the same formulas, it suffices to show that the free variables `(x', (C_{0,i})_{i in I})` have the same joint distribution. In `Sim`, these are mutually independent and uniform.

*`x'` is uniform.* In the real protocol, `x' = rho_1 w' + rho_2 r'` where the mask `r' in F^(n+k)` is fully uniform and independent of `w'`. Since `rho_2 != 0` (as `PG` is zk), `x'` is uniform over `F^(n+k)`.

*`x'` is independent of `(C_{0,i})_{i in I}`.* The commitment entries are `C_{0,i} = (C w')_i`, which depend on the padding `p_w in F^k`. We claim `p_w` is independent of `x'`: writing `x' = (rho_1 w + rho_2 r, rho_1 p_w + rho_2 p_r)`, the second component is masked by `rho_2 p_r` (uniform, independent of `p_w`, since `rho_2 != 0`) and the first component depends only on `r` (independent of `p_w`). So `x'` is independent of `p_w`, and hence of `(C w')_{i in I}`.

*`(C_{0,i})_{i in I}` is i.i.d. uniform.* Since `C` is a `k`-zk-code and `|I| <= k`, the projection `(C w')_{i in I}` is uniform in `F^|I|` as `p_w` varies. Independence from `x'` (shown above) then gives that `(C_{0,i})_{i in I}` is i.i.d. uniform and independent of `x'`, matching `Sim`.

### 3.2 ZK Hadamard-Eval PCS

The next protocol allows the sender to commit to three vectors `a, b, c` and later prove, with zero-knowledge, a Hadamard product relation `a * b = c` between them in addition to evaluations `ell(a), ell(b), ell(c)` at a common linear function `ell`.

**Definition 3.5 (Hadamard-Check Scheme).** A Hadamard-check oracle commitment scheme is a commit-and-prove IOP (Definition 3.1) with:

- Witness space `W = (F^n)^3` (triples `(a, b, c)`),
- Explicit input space `X = F^n x F^3` (linear functional `ell` and claimed values `(alpha_a, alpha_b, alpha_c)`),
- Relation `R = {((a, b, c), (ell, (alpha_*))) : a * b = c and ell(*) = alpha_* for * in {a, b, c}}`.

**Lemma 3.6.** Let `C : F^(n+k) -> F^m` be a multiplicative `k`-zk-code in good form, with minimum relative distance `Delta` and `PG ~ F^4` a zk `(delta, eps_PG)`-proximity-generator for `C` with `delta <= Delta/2`. Let `C` have product code `C^*` of minimum relative distance `Delta^*` and `PG^* ~ F^2` a zk `(delta^*, eps_{PG^*})`-proximity-generator for `C^*` with `delta^* <= Delta^*/2` and `delta^* <= delta`. Let `D` be the reduction function for `C^*` (see Definition 2.8). Let `T_C, T_{C^*}, T_D` be the encoding times of `C, C^*, D` respectively. Finally, let `LB ~ F^n` have linear bias `eps^•_LB`.

Then, there exists a zk Hadamard-check oracle commitment scheme with the following parameters:

- **Query Complexity:** `k` queries to the commitment oracle with an alphabet size of 5 field elements.
- **Binding error:** `eps_PG(m, |F|) + eps_{PG^*}(m, |F|) + eps^•_LB + (1 - delta^*)^k`.
- **Commit Time:** `4 T_C(n) + T_{C^*}(n) + O(n)`.
- **Prove Time:** `T_{C^*}(n) + T_D(n) + O(n)`.
- **Verify Time:** `T_C(n) + T_{C^*}(n) + T_D(n) + O(n)`.
- **Message Complexity:** `n^* + n + k + 2` prover and `c(LB) + c(PG) + c(PG^*)` verifier field elements, where `n^*` is the message length of `C^*`.

Furthermore, this protocol takes the form of an interaction phase in which no queries are made to the oracles followed by a query phase in which `k` i.i.d. uniform queries are made to the commitment oracle.

#### 3.2.1 Proof of Lemma 3.6

The commitment algorithm and evaluation protocol are described, respectively, in Figs. 3 and 4.

**Figure 3: The Hadamard-Check Commitment**

Parameters: Multiplicative `k`-zk code `C : F^(n+k) -> F^m` in good form with product code `C^*`
Input: vectors `a, b, c in F^n`

1. `P` generates a masking vector `r_+ in F^n` i.i.d. uniformly at random.
2. `P` generates a masking vector `r_x in F^(2n)` uniformly at random.
3. `P` generates a padding vector in `F^(2k)` uniformly at random and appends it to `r_x` to produce `r'_x in F^(2(n+k))`.
4. `P` generates four padding vectors in `F^k` uniformly at random and appends them to `*, r_+` to produce `*', r'_+ in F^(n+k)` for `* in {a, b, c}`.
5. `P` sends the matrix `C in F^({a,b,c,+,x} x m)`, where `C_{*,i} = (C *')_i` for `* in {a,b,c}`, `C_{+,i} = (C r'_+)_i`, and `C_{x,i} = (C^* r'_x)_i`.

**Figure 4: Hadamard-Check Protocol**

Parameters: Reduction function `D` for `C^*` (Definition 2.8), zk proximity generators `PG ~ F^4` for `C` and `PG^* ~ F^2` for `C^*`, linear bias generator `LB ~ F^n`
Public Input: Commitment `C in F^({a,b,c,+,x} x m)`, linear function `ell : F^n -> F`, claimed evaluations `alpha_*` in `F` for `* in {a, b, c}`.
Prover Private Input: For `* in {a, b, c}`: padded vectors/masks `*', r'_* in F^(n+k)` from commitment scheme phase.

1. `V` samples a random vector `u <- LB`. Use `u` to also denote the linear function `v -> u · v`.
2. `P` sends:
   - `beta := ell(r_+)`, where `r_+` is the length-`n` prefix of `r'_+`,
   - `gamma := u(r^red_x)`, where `r^red_x` is the length-`n` prefix of `D(r'_x)` (recall the reduction function `D` from Definition 2.8).
3. `V` sends `(sigma_1, sigma_2) <- PG^*`.
4. `P` sends as an explicit message `Phi` defined to be the input in the product code `C^*` satisfying

   ```
   C^* Phi := sigma_1 ((C a') * (C b') - C c') + sigma_2 · C^* r'_x.
   ```

5. `V` sends `(rho_1, rho_2, rho_3, rho_4) <- PG`.
6. `P` sends as an explicit message `x' := rho_1 a' + rho_2 b' + rho_3 c' + rho_4 r'_+`.
7. `V` checks:
   - `u(f) = sigma_2 · gamma`, where `f` is the `n`-symbol prefix of `f' := D(Phi)`,
   - `ell(x) = rho_1 alpha_a + rho_2 alpha_b + rho_3 alpha_c + rho_4 beta`, where `x` is the length-`n` prefix of `x'`.
8. `V` samples `i_1, ..., i_k in [n+k]` i.i.d. uniformly at random.
9. For each `j in [k]`: `V` queries the `i_j`-th column of `C` and checks:

   ```
   sigma_1 (C_{a, i_j} C_{b, i_j} - C_{c, i_j}) + sigma_2 C_{x, i_j} = (C^* Phi)_{i_j}
   rho_1 C_{a, i_j} + rho_2 C_{b, i_j} + rho_3 C_{c, i_j} + rho_4 C_{+, i_j} = (C x')_{i_j}
   ```

**Completeness.** All checks follow from linearity of `ell` and `C`. The most complicated step is the Hadamard check in Step 7: since `D` is a reduction function satisfying `D ∘ S = id`, linearity gives `D(Phi) = sigma_1 (a' * b' - c') + sigma_2 · D(r'_x)`, whose length-`n` prefix is `sigma_1 (a * b - c) + sigma_2 · r^red_x = sigma_2 · r^red_x`, so `u(f) = sigma_2 gamma`.

**Binding.** Let `C in F^({a,b,c,+,x} x m)` be a commitment oracle and define

```
C^1 := [C_a, C_b, C_c, C_+],     C^2 := [C_a * C_b - C_c, C_x].
```

Choose

```
(N^1)' := (N'_a, N'_b, N'_c, N'_+) in F^(4 x (n+k)),
(N^2)' := (N'_{abc}, N'_x) in F^(2 x 2(n+k))
```

to minimize `d_rel(C (N^1)', C^1)` and `d_rel(C^* (N^2)', C^2)` respectively (breaking ties arbitrarily). Write `*_hat := prefix_n(N'_*)` for `* in {a, b, c}`, `r^hat_+ := prefix_n(N'_+)`, and `r^hat_x := prefix_n(D(N'_x))`. We define the bound witness to be `(a_hat, b_hat, c_hat)`.

Fix a cheating prover `P*` and a false claim `(ell, alpha_a, alpha_b, alpha_c)`. Thus, either (1) `a_hat * b_hat != c_hat` or (2) `ell(s_hat) != alpha_s` for some `s in {a, b, c}`. Define

```
T_x(sigma) := sigma_1 (C_a * C_b - C_c) + sigma_2 C_x,
T_+(rho) := rho_1 C_a + rho_2 C_b + rho_3 C_c + rho_4 C_+,
```

and their decoded analogues

```
T^C_x(sigma) := sigma_1 (C N'_a * C N'_b - C N'_c) + sigma_2 C^* N'_x,
T^C_+(rho) := rho_1 C N'_a + rho_2 C N'_b + rho_3 C N'_c + rho_4 C N'_+.
```

Recall that `Delta` (resp., `Delta^*`) is the distance of `C` (resp., `C^*`) and that `PG ~ F^4` (resp. `PG ~ F^2`) is a zk `(delta, eps_PG)`-proximity-generator for `C` with `delta <= Delta/2` (resp., `(delta^*, eps_{PG^*})`-proximity-generator for `C^*` with `delta^* <= Delta^*/2`).

*Step 9 catches malformed oracles.* Assume that `d_rel(C (N^1)', C^1) >= delta^*`. By the proximity gaps property of `PG` (see Definition 2.14) and `delta^* <= delta` gives that `d_rel(T_+(rho), C) >= delta^*` except with probability `eps_PG(m, |F|)` over `rho`. Since `C x' in C`, this gives `d_rel(C x', T_+(rho)) >= delta^*`, so the second check of Step 9 accepts with probability at most `(1 - delta^*)^k`.

Assume that `d_rel(C^* (N^2)', C^2) >= delta^*`. Since `(N^2)'` minimized the distance, we also get that `d_rel([C N'_a * C N'_b - C N'_c, C^* N'_x], C^2) >= delta^*` which gives by the proximity gaps property of `PG^*` (Definition 2.14) that `d_rel(T_x(sigma), C^*) >= delta^*` except with probability `eps_{PG^*}(m, |F|)`.

Analyzing the far-case similarly to above, unless `d_rel(C (N^1)', C^1), d_rel(C^* (N^2)', C^2) < delta^*`, Step 9 accepts with probability at most `(1 - delta^*)^k + eps_PG(m, |F|) + eps_{PG^*}(m, |F|)`. Therefore we assume that both distances are less than `delta^*`. In this case, Remark 2.15 gives that

```
d_rel(C N'_a * C N'_b - C N'_c, C_a * C_b - C_c), d_rel(C^* N'_{abc}, C_a * C_b - C_c) < delta^*
==> d_rel(C N'_a * C N'_b - C N'_c, C^* N'_{abc}) < Delta^*.
```

By multiplicativity, the last distance is between two `C^*`-codewords and so we have that:

```
C^* N'_{abc} = C N'_a * C N'_b - C N'_c.
```

*Violation (A): `a_hat * b_hat != c_hat`.* Assume we are in the case that `a_hat * b_hat != c_hat`.

*Step 7 (first item) catches the false Hadamard claim.* Suppose the prover sends `Phi` such that `C^* Phi = T^C_x(sigma)`. The reduction-function property (Lemma 2.6) then gives

```
prefix_n(D(Phi)) = sigma_1 (a_hat * b_hat - c_hat) + sigma_2 r^hat_x.
```

Setting `e := a_hat * b_hat - c_hat != 0`, the check `u(f) = sigma_2 gamma` becomes

```
sigma_1 u(e) + sigma_2 (u(r^hat_x) - gamma) = 0.
```

Since `e != 0` and `LB` has linear bias `eps^•_LB`, `Pr_{u <- LB}[u · e = 0] <= eps^•_LB`. Conditioned on `u(e) != 0`: the coefficient vector `(u(e), u(r^hat_x) - gamma)` is nonzero, so the equation holds with probability `<= eps^•_{PG^*}`. Overall the explicit Hadamard check passes with probability at most `eps^•_LB + eps^•_{PG^*}`.

*Step 9 (first line) catches inconsistent `Phi`.* We may therefore further restrict to `C^* Phi != T^C_x(sigma)`, giving `d_rel(C^* Phi, T^C_x(sigma)) >= Delta^*` by the minimum distance of `C^*`. Since in the case we're considering `d_rel(C^* (N^2)', C^2) <= delta^*`, Remark 2.15 gives

```
d_rel(T_x(sigma), T^C_x(sigma)) < delta^*
```

implying by the triangle inequality that

```
d_rel(C^* Phi, T_x(sigma)) >= Delta^* - delta^* >= delta^*.
```

Then each query detects the mismatch with probability `>= delta^*`, so all `k` queries pass with probability at most `(1 - delta^*)^k`.

*Violation (B): `ell(s_hat) != alpha_s` for some `s in {a, b, c}`.*

*Step 7 (second item) catches false linear evaluations.* If the prover sends `x'` such that its prefix `x = rho_1 a_hat + rho_2 b_hat + rho_3 c_hat + rho_4 r^hat_+`, then Step 7 requires

```
rho_1 (ell(a_hat) - alpha_a) + rho_2 (ell(b_hat) - alpha_b) + rho_3 (ell(c_hat) - alpha_c) + rho_4 (ell(r^hat_+) - beta) = 0.
```

If `ell(s_hat) != alpha_s` for some `s in {a, b, c}`, the coefficient vector is nonzero, so the equation holds with probability `<= eps^•_PG`.

*Step 9 (second line) catches inconsistent openings.* We may therefore further restrict to `x != rho_1 a_hat + rho_2 b_hat + rho_3 c_hat + rho_4 r^hat_+`, where `x` denotes the length-`n` prefix of `x'`, which implies `x' != rho_1 N'_a + rho_2 N'_b + rho_3 N'_c + rho_4 N'_+`, giving `d_rel(C x', T^C_+(rho)) >= Delta` by the minimum distance of `C`. Since the companion fact gives `d_rel(T_+(rho), T^C_+(rho)) < delta^* <= delta`, the triangle inequality gives

```
d_rel(C x', T_+(rho)) >= Delta - delta^* >= Delta - delta >= delta.
```

Then each query detects the mismatch with probability `>= delta`, so all `k` queries pass with probability `<= (1 - delta)^k`.

Union bounding within each case and taking a max gives the stated error, using `eps^•_PG <= eps_PG(m, |F|)` and `eps^•_{PG^*} <= eps_{PG^*}(m, |F|)` (Remark 2.17) to absorb the linear-bias terms.

**Zero-knowledge.** We construct a simulator `Sim` whose output is distributed identically to the verifier's view in an honest execution. The simulator receives as input the linear functional `ell`, the claimed evaluations `alpha_*` for `* in {a, b, c}`, and the verifier's randomness: `u, (rho_1, rho_2, rho_3, rho_4), (sigma_1, sigma_2)`, and the multiset of query indices `I` from Step 8. It must produce the prover's explicit messages `beta, gamma, Phi, x'` and oracle query responses `(C'_{*,i})_{* in {a,b,c,+,x}}` for each unique `i in I`. We define `Sim` as follows:

1. Sample `x' in F^(n+k)` uniformly at random and set `beta := rho_4^(-1) · (ell(x) - rho_1 alpha_a - rho_2 alpha_b - rho_3 alpha_c)`, where `x` denotes the length-`n` prefix of `x'`.
2. Sample `Phi in F^(2(n+k))` uniformly at random. Set `gamma := sigma_2^(-1) · u(f)`, where `f` is the length-`n` prefix of `D(Phi)`.
3. For each unique `i in I`: sample `C'_{a,i}, C'_{b,i}, C'_{c,i} in F` i.i.d. uniformly at random, then set

   ```
   C'_{+,i} := rho_4^(-1) ((C x')_i - rho_1 C'_{a,i} - rho_2 C'_{b,i} - rho_3 C'_{c,i}),
   C'_{x,i} := sigma_2^(-1) ((C^* Phi)_i - sigma_1 C'_{a,i} C'_{b,i} + sigma_1 C'_{c,i}).
   ```

By construction, `Sim`'s output satisfies all of `V`'s checks. We now show that for any fixed verifier randomness `(u, rho, sigma, I)`, the verifier's view in an honest execution has the same distribution.

*Free and determined variables.* For each `i in I`, the query-phase check equations uniquely determine `(C_{+,i}, C_{x,i})` from `(x', Phi, C_{a,i}, C_{b,i}, C_{c,i})` (since `rho_4 != 0` and `sigma_2 != 0`, as `PG` and `PG^*` are zk):

```
C_{+,i} = rho_4^(-1) ((C x')_i - rho_1 C_{a,i} - rho_2 C_{b,i} - rho_3 C_{c,i}),
C_{x,i} = sigma_2^(-1) ((C^* Phi)_i - sigma_1 C_{a,i} C_{b,i} + sigma_1 C_{c,i}).
```

Similarly, in an honest execution (where `ell(*) = alpha_*` for `* = a, b, c` and `a * b = c`), the explicit-message checks in Step 7 are identically satisfied, so `beta` is determined by `x'` and `gamma` is determined by `Phi`:

```
beta = rho_4^(-1) (ell(x) - rho_1 alpha_a - rho_2 alpha_b - rho_3 alpha_c),
gamma = sigma_2^(-1) · u(prefix_n(D(Phi))).
```

(For `gamma`: by linearity of `D`, `prefix_n(D(Phi)) = sigma_1 · prefix_n(D(Phi_0)) + sigma_2 · r^red_x` where `Phi_0 := (C^*)^(-1)((C a') * (C b') - C c')`. Since `a * b = c`, the completeness argument gives `prefix_n(D(Phi_0)) = 0`, so `u(f) = sigma_2 · u(r^red_x) = sigma_2 gamma`.)

Since both `Sim` and the honest prover compute `(C_{+,i}, C_{x,i})` and `(beta, gamma)` using the same formulas, it suffices to show that the free variables `(x', Phi, (C_{a,i}, C_{b,i}, C_{c,i})_{i in I})` have the same joint distribution. In `Sim`, these are mutually independent and uniform. We show the real protocol produces the same distribution.

*Independence via masking.* In the real protocol, the free variables depend on the random inputs as follows:

- `x' = (rho_1 a' + rho_2 b' + rho_3 c') + rho_4 · r'_+`, where the mask `r'_+ in F^(n+k)` is fully uniform and independent of all other randomness.
- `Phi = sigma_1 Phi_0 + sigma_2 · r'_x`, where `Phi_0` depends only on `(a', b', c')` and the mask `r'_x in F^(2(n+k))` is fully uniform and independent of all other randomness.
- `(C_{a,i}, C_{b,i}, C_{c,i}) = ((C a')_i, (C b')_i, (C c')_i)`, depending only on the padded witnesses `(a', b', c')`.

We use the following standard fact: if `Z` is uniform in `F^d` and independent of a random variable `W`, then `g(W) + t Z` is uniform in `F^d` and independent of `W`, for any function `g` and any nonzero scalar `t`. Since `r'_+` is independent of `(r'_x, a', b', c')` and `rho_4 != 0` (as `PG` is zk), the variable `x'` is uniform over `F^(n+k)` and independent of `(Phi, (C_{a,i}, C_{b,i}, C_{c,i})_{i in I})`. By the same reasoning applied to `r'_x` (using `sigma_2 != 0` as `PG^*` is zk), `Phi` is uniform over `F^(2(n+k))` and independent of `(C_{a,i}, C_{b,i}, C_{c,i})_{i in I}`. Therefore `x', Phi`, and `(C_{a,i}, C_{b,i}, C_{c,i})_{i in I}` are mutually independent, matching `Sim`.

*Marginal distribution of query responses.* It remains to show `(C_{a,i}, C_{b,i}, C_{c,i})_{i in I}` is i.i.d. uniform in `F^3`. The padding vectors `p_a, p_b, p_c in F^k` (from the commitment, Step 4) are mutually independent and uniform. Since `C` is a `k`-zk-code and `|I| <= k`, for each `* in {a, b, c}` the projection `(C *')_{i in I}` is uniform in `F^|I|`. Independence of the three paddings gives that `((C a')_{i in I}, (C b')_{i in I}, (C c')_{i in I})` is uniform in `F^(3|I|)`, so the triples `(C_{a,i}, C_{b,i}, C_{c,i})` are i.i.d. uniform in `F^3`.

### 3.3 Zero-Knowledge Circuit Evaluation

We now want a commit-and-prove protocol for arbitrary arithmetic circuit satisfiability. It is well known that the satisfiability of a circuit `C` can be reduced to the satisfiability of an R1CS instance checking that `(A w) * (B w) = C w` for some `w in F^(n')` and `A, B, C in F^(m' x n')` that can be efficiently constructed from `C`. We therefore instead construct an R1CS evaluation scheme:

**Definition 3.7 (R1CS Evaluation Scheme).** An R1CS interactive oracle commitment scheme is a commit-and-prove IOP (Definition 3.1) with:

- Witness space `W = F^(n')`,
- Explicit input space: matrix triples `(A, B, C)` in `X = (F^(m' x n'))^3`,
- Relation `R = {(w, (A, B, C)) : (A w) * (B w) = C w}`.

We specify the codes used by the sub-protocols. For the zk-linear-eval sub-protocol on vectors of length `n' + 6`: let `C_+ : F^(n'+6+k) -> F^(m_+)` be a `k`-zk code with encoding time `T_{C_+}(n')`. For the zk-Hadamard-check sub-protocol on vectors of length `m' + 2`: let `C_x : F^(m'+2+k) -> F^(m_x)` be a multiplicative `k`-zk code in good form with encoding time `T_{C_x}(m')`; product code `C^*_x` with encoding time `T_{C^*_x}(m')`; and reduction function `D` with time `T_D(m')`. Let `LB_x ~ F^(m'+2)` have linear bias `eps^•_{LB_x}`. Let `eps_+` and `eps_x` denote the binding errors of the resulting zk-linear-eval (Lemma 3.4) and zk-Hadamard-check (Lemma 3.6) sub-protocols, and let `c_{V,+}` and `c_{V,x}` denote their verifier message complexities.

**Lemma 3.8.** Let `C_+, C_x, C^*_x` be codes as specified above (in particular, `C_x` in good form). Then there exists a zk R1CS evaluation interactive oracle commitment scheme with the following parameters, where `s` is the total sparsity of `A, B` and `C` (i.e., the total number of nonzero entries):

- **Query Complexity:** `k` queries to `C_+` with alphabet size 2 field elements and `k` queries to `C_x` with alphabet size 5 field elements.
- **Binding error:** `3 eps^•_{LB_x} + 2/|F| + max{eps_+, eps_x}`.
- **Commit Time:** `2 T_{C_+}(n') + O(n')`.
- **Prove Time:** `s + 4 T_{C_x}(m') + 2 T_{C^*_x}(m') + T_D(m') + O(m' + n')`.
- **Verify Time:** `s + T_{C_+}(n') + T_{C_x}(m') + T_{C^*_x}(m') + T_D(m') + O(m' + n')`.
- **Message Complexity:** `n^*_x + m' + n' + 2k + 14` prover and `c(LB_x) + 1 + c_{V,+} + c_{V,x}` verifier field elements, where `n^*_x` is the message length of `C^*_x`.

Furthermore, this protocol takes the form of an interaction phase in which no queries are made to the oracles followed by a query phase in which `k` i.i.d. uniform queries are made.

#### 3.3.1 Proof of Lemma 3.8

The commitment algorithm and evaluation protocol are described, respectively, in Figs. 5 and 6.

**Figure 5: R1CS Evaluation Commitment**

Parameters: zk-linear-eval code `C_+` on vectors of length `n' + 6`
Input: witness `w in F^(n')`, R1CS matrices `A, B, C in F^(m' x n')`

1. `P` samples `x_1, y_1, x_2, y_2 in F` i.i.d. uniformly at random. Then
   - (a) `P` pads `w` by `(x_1, y_1, x_2, y_2, x_1 y_1, x_2 y_2)` to produce `w' in F^(n'+6)`.
   - (b) `(P, V)` pad `A, B, C` with two rows each realizing the tautological multiplicative relations on the new entries of `w'` to produce `A', B', C' in F^((m'+2) x (n'+6))`.
2. `P` sends the linear-eval commitment `C_+` of `w'`.

**Figure 6: R1CS Evaluation Protocol**

Parameters: Linear bias generator `LB_x ~ F^(m'+2)`; zk-Hadamard-check parameters `(C_x, C^*_x, D, PG_x, PG^*_x, LB)` on vectors of length `m' + 2`; zk-linear-eval proximity generator `PG_+`
Public Input: commitment `C_+` from commitment scheme, padded R1CS matrices `A', B', C'` as defined in commitment.
Prover Private Input: `w'` and linear-eval intermediate data from commitment scheme.

1. `P` commits to the Hadamard-check (Fig. 3) oracle `C_x` for the triple `a := A' w'`, `b := B' w'`, `c := C' w'`.
2. `V` samples `ell_x <- LB_x`. Use `ell_x` to also denote the linear function `v -> ell_x · v`.
3. `P` sends `alpha_* = ell_x(*)` for `* in {a, b, c}`.
4. `V` sends `rho_2 in F` sampled uniformly at random and defines linear functional

   ```
   ell_+ : v -> ell_x(A' v) + rho_2 ell_x(B' v) + rho_2^2 ell_x(C' v).
   ```

5. `(P, V)` run zk-Hadamard-Check (Fig. 4) using oracle `C_x` to prove that `a * b = c` and that `alpha_* = ell_x(*)` for `* = a, b, c`.
6. `(P, V)` run zk-linear-evaluation (Fig. 2) using oracle `C_+` to check that `ell_+(w') = alpha_a + rho_2 alpha_b + rho_2^2 alpha_c`.

**Completeness.** Suppose `(A w) * (B w) = C w`. We show that `V` accepts with probability 1 when interacting with an honest `P`.

First, the padded R1CS condition `(A' w') * (B' w') = C' w'` holds: on the first `m'` coordinates, this is the original R1CS condition. The two additional rows encode `x_1 · y_1 = x_1 y_1` and `x_2 · y_2 = x_2 y_2`, which hold by construction of `w'`.

Let `a = A' w'`, `b = B' w'`, `c = C' w'`. By the above, `a * b = c`. The prover sends `alpha_a = ell_x(a), alpha_b = ell_x(b), alpha_c = ell_x(c)`. By completeness of zk-Hadamard-Check (Lemma 3.6), the check in Step 5 passes with probability 1.

For Step 6, by linearity of `ell_x` and the definition of `ell_+`:

```
ell_+(w') = ell_x(A' w') + rho_2 ell_x(B' w') + rho_2^2 ell_x(C' w')
         = ell_x(a) + rho_2 ell_x(b) + rho_2^2 ell_x(c)
         = alpha_a + rho_2 alpha_b + rho_2^2 alpha_c.
```

By completeness of zk-linear-evaluation (Lemma 3.4), this check also passes with probability 1.

**Binding.** Let `w' in F^(n'+6)` be the bound witness of `C_+` under zk-linear-eval (Fig. 2), with `w := prefix_{n'}(w')`. Let `(a, b, c) in (F^(m'+2))^3` be the bound witness of `C_x` under zk-Hadamard-check (Fig. 4). The bound witness is `w`.

Fix a cheating prover `P*` with `(A w) * (B w) != C w`. Let `alpha_a, alpha_b, alpha_c` be the prover's messages in Step 3.

*The sub-protocol claims are false.* We show that except with probability `3 eps^•_{LB_x} + 2/|F|` over `ell_x, rho_2`, at least one sub-protocol receives a false claim about its bound witness. Suppose for contradiction that both claims are true: `a * b = c` with `alpha_* = ell_x(*)`, and `ell_+(w') = alpha_a + rho_2 alpha_b + rho_2^2 alpha_c`. By definition of `ell_+`:

```
ell_x(A' w') + rho_2 ell_x(B' w') + rho_2^2 ell_x(C' w') = alpha_a + rho_2 alpha_b + rho_2^2 alpha_c.
```

If `(alpha_a, alpha_b, alpha_c) != (ell_x(A' w'), ell_x(B' w'), ell_x(C' w'))`, this is a nonzero degree-2 polynomial in `rho_2`, vanishing with probability `<= 2/|F|`. Therefore consider the case when `alpha_* = ell_x(a) = ell_x(A' w')`, etc. If `a != A' w'` then `ell_x · (a - A' w')` is a nonzero linear form in `ell_x`, vanishing with probability `<= eps^•_{LB_x}`; likewise for `b, c`. Hence consider the case `(a, b, c) = (A' w', B' w', C' w')`. Combining with `a * b = c` yields `(A' w') * (B' w') = C' w'`. The padding rows are tautologies by construction, so the first `m'` rows give `(A w) * (B w) = C w` which contradicts. A union bound gives non-contradiction probability `3 eps^•_{LB_x} + 2/|F|`.

*Sub-protocols catch the cheater.* By the above, at least one sub-protocol receives a false claim. If lin-eval receives a false claim, Step 6 rejects except with the binding error of Lemma 3.4. If Hadamard-check receives a false claim, Step 5 rejects except with the binding error of Lemma 3.6. Taking the minimum and then a union bound gives the claimed binding error.

**Zero-knowledge.** A valid `Sim` would be given as input the matrices `A', B', C'`. It is also given the verifier randomness `rho_1, rho_2`, the zk-lin-eval (Fig. 2) randomness `r_+`, and the zk-Hadamard-check (Fig. 4) randomness `r_x` (and therefore both `ell_+` and `ell_x`). It needs to generate the `alpha_*` for `* in {a, b, c}`, the zk-lin-eval prover messages `M_+`, and the zk-Hadamard-check prover messages `M_x`. Do so as follows:

1. Generate `alpha_a, alpha_b, alpha_c` i.i.d. uniformly.
2. Generate `M_+` using the simulator `Sim_+` for zk-lin-eval (Lemma 3.4) on linear functional `ell_+`, claimed evaluation `alpha_a + rho_2 alpha_b + rho_2^2 alpha_c`, and randomness `r_+`.
3. Generate `M_x` using the simulator `Sim_x` for zk-Hadamard-check (Lemma 3.6) on linear functional `ell_x`, claimed evaluations `alpha_a, alpha_b, alpha_c`, and randomness `r_x`.

We now check that `V`'s view interacting with an honest `P` is distributed the same. First, since `x_1, y_1` and `x_2 y_2` are i.i.d. random, so are `alpha_a, alpha_b, alpha_c`. Next, zk-ness for zk-lin-eval and zk-Hadamard-check show that `M_+` and `M_x` are individually distributed the same as the outputs of the sub-protocols zk-lin-eval and zk-Hadamard-check given any possible values of their inputs.

It remains to show that the `alpha_*` for `* in {a, b, c}` and `M_+, M_x` are jointly distributed the same as for `Sim`. This follows since in both the simulator and true protocol (1) zk-lin-eval and zk-Hadamard-check are independent conditioned on the `alpha_*` for `* in {a, b, c}` and (2) zk-lin-eval and zk-Hadamard-check are conditionally independent of the `alpha_*` given their inputs.

**Remark 3.9.** The Ligero protocol [AHIV17] gives an alternate zero-knowledge arithmetic circuit interactive oracle commitment scheme with a square-root improvement to proof length and verification time over the one presented above. However, in our eventual application to MIOPs, the proof length is usually dominated by oracle commitments and openings instead of the field element messages so the optimization is negligible. This version makes the final compilation scheme easier to implement — see Remark 4.4.

---

## 4. Compiling into a ZK IOP

We now describe how to use the above protocols to build our compiler.

### 4.1 Intermediate Compilation to Partial ZK

This first step is a method producing a fully-zk protocol from a protocol satisfying a certain notion of being "partially zero-knowledge"—intuitively, allowing information to be leaked through some specified subset of prover messages.

**Definition 4.1 (Partially Zero-Knowledge Commit-and-Prove Scheme).** A commit-and-prove IOP (Definition 3.1) is partially zero-knowledge if:

- Messages from `P` are partitioned into exposed and shielded messages; oracle query responses are always shielded.
- There exists a PPT simulator `Sim` such that for all verifier randomness `r in {0,1}^*`, commitment `C = Commit(w)`, and input `x` with `(w, x) in R`, the output `Sim(r, x)` is distributed identically to the shielded prover messages and oracle query responses produced in an honest execution of `(P, V)` on `C, x` with randomness `r`.

We also need a notion restricting how the true verifier is allowed to use the exposed prover messages:

**Definition 4.2.** A partially-zk IOP with input `x` is called arithmetically partially zk if `V` accepts if and only if `C_{s, x, r}(v) = 0`, where `v` is the vector of exposed messages sent by `P`, `s` is the vector of shielded messages sent by `P` and oracle query responses received by `V`, and `C_{s, x, r}` is an arithmetic circuit depending only on `s`, the input `x`, and the verifier randomness `r` (without loss of generality, we assume `C_{s, x, r}` is written in the form of an R1CS instance).

Now, we describe how to compile an arithmetically partially-zk IOP into a fully-zk protocol (later we show how to obtain the partially zk protocol).

**Lemma 4.3.** Let `(P_0, V_0)` be an arithmetically partially zk IOP for relation `R` on inputs `x`, with prover time `P_0`, verifier time `V_0`, `s` exposed messages, and message complexity `M_0`. Let `(Commit_c, P_c, V_c)` be a circuit evaluation interactive oracle scheme, operating on witness vectors of length `s`, and have commit time `T_{c, Commit}(n)`, prove time `T_{c, P}(n)`, verify time `V_c(n)`, and `M_c(n)` on input circuits of size `n`.

Then, there is a fully zk IOP `(P, V)` for `R` with the following parameters:

- **Oracle Complexity:** that for `(P_0, V_0)` plus that for `(Commit_c, P_c, V_c)` on circuits of size `s + V_0`.
- **Soundness error:** if `(Commit_c, P_c, V_c)` and `(P_0, V_0)` have binding error `2^(-lambda)`, then `(P, V)` has error `2^(-lambda+1)`.
- **Prover Time:** `P_0 + T_{c, Commit}(s + V_0) + T_{c, P}(s + V_0) + O(s + V_0)`.
- **Verifier Time:** `V_0 + V_c(s + V_0) + O(s + V_0)`.
- **Message Complexity:** `M_0 + M_c(s + V_0)`.

#### 4.1.1 Proof of Lemma 4.3

The compilation is described in Fig. 7.

**Figure 7: Intermediate Compilation Protocol**

Parameters: Arithmetically partially-zk IOP `(P_0, V_0)` with `s` exposed messages and verification circuit `C_{s, x, r}`; zk-circuit evaluation scheme `(Commit_c, P_c, V_c)`.
Public Input: Input `x` to the original protocol `(P_0, V_0)`.

1. `P` generates a uniform random hiding vector `h = (h_i)_i in F^s` and sends the commitment oracle `Commit_c(h)`.
2. `(P, V)` run the protocol `(P_0, V_0)` with the following modification:
   - Whenever `P` would send the `i`-th exposed element `v_i`, it instead sends `v'_i := v_i + h_i`.
3. `(P, V)` construct the circuit `C'_{s, x, r, v'}(z) := C_{s, x, r}(v' - z)`.
4. `(P, V)` run the circuit evaluation protocol `(P_c, V_c)` on the shifted circuit `C'_{s, x, r, v'}` with respect to commitment `Commit_c(h)`.

**Completeness.** If `(w, x) in R`, then an honest execution of `(P_0, V_0)` satisfies `C_{s, x, r}(v) = 0`. Since `v' - h = v`, we have `C'_{s, x, r, v'}(h) = C_{s, x, r}(v' - h) = C_{s, x, r}(v) = 0`, so completeness of the R1CS evaluation scheme implies `V` accepts.

**Soundness.** Let `P*` be a cheating prover on input `x` with `(w, x) not in R` for all `w`, and suppose `P*` sends commitment `C`, exposed messages `v'`, and shielded messages `s`. By the binding property of `(Commit_c, P_c, V_c)`, there exists a value `h` bound to `C` such that `V_c` rejects with probability at least `1 - 2^(-lambda)` whenever `C'_{s, x, r, v'}(h) != 0`.

Now consider the prover `P*_0` for `(P_0, V_0)` that sends exposed messages `v' - h` and shielded messages `s`. Since `(w, x) not in R` for all `w`, soundness of `(P_0, V_0)` gives that `V_0` rejects with probability at least `1 - 2^(-lambda)`, i.e., `C_{s, x, r}(v' - h) != 0`. By construction `C_{s, x, r}(v' - h) = C'_{s, x, r, v'}(h)`, so `C'_{s, x, r, v'}(h) != 0`, and therefore `V_c` rejects with probability at least `1 - 2^(-lambda)`.

A union bound over the two failure events gives that `V` rejects with probability at least `1 - 2^(-lambda+1)`.

**Zero-knowledge.** We construct a simulator `Sim` as follows:

1. Run `Sim_0` (the simulator for the partially-zk protocol `(P_0, V_0)`) to obtain simulated shielded messages and oracle query responses `s`.
2. Sample the exposed messages `v'_i` independently and uniformly at random.
3. Run `Sim_c` (the simulator for `(Commit_c, P_c, V_c)`) on the shifted circuit `C'_{s, x, r, v'}` to generate the circuit evaluation protocol's messages.

We argue that `Sim` produces a view identically distributed to the real protocol. Fix the verifier randomness `r` (that for `V` is the union of that for `V_0` and `V_c`) and consider an honest execution. By definition of `Sim_0`, the shielded messages and oracle query responses have the same distribution in the real and simulated executions. In the real protocol, since the hiding entries `h_i` are i.i.d. uniform and independent of `s`, the masked messages `v'_i = v_i + h_i` are also i.i.d. uniform and independent of `s`—exactly matching the distribution of the `v'_i` sampled by `Sim`. Finally, conditioned on any fixed values of `s, v', x`, and verifier randomness, the zero-knowledge property of `Sim_c` ensures that the circuit evaluation messages have the same distribution in both executions. Therefore the entire verifier view is identically distributed in the real and simulated protocols.

**Remark 4.4 (Practical optimizations).** In our application, the acceptance conditions for `V` need not be given as a single arithmetic circuit. Rather, they consist of a long list of affine linear constraints `(ell_i)_i` together with a short list of general polynomial constraints on `v`. The polynomial constraints can be compiled into a small-height R1CS instance determined by `A, B, C`.

To avoid the overhead of converting between circuit representations, we do not explicitly compute `C'_{s, r}` and run a circuit evaluation protocol as in Fig. 7 Items 3 and 4. Instead, we:

1. Use a modified version of the R1CS protocol Fig. 6 to prove the small-height R1CS instance:
   - (a) Rather than setting `a := A'(v)`, we instead define `a := A'(v') - A'(h)`, and similarly for `b` and `c`.
   - (b) The internal linear constraint in Item 6 is replaced by `ell_+(h) = ell_+(v') - (alpha_a + rho_2 alpha_b + rho_2^2 alpha_c)`.
   - (c) Instead of running zk-lin eval in Item 6, we append the above constraint to the `ell_i`.
2. Take a random linear combination of all the `ell_i` to produce a single constraint `ell(v) = r`. This is verified by proving `ell(h) = ell(v') - r` using the committed hiding vector and zk-dot-product (Fig. 2).

Denote the number of affine linear constraints by `n_ell` and their total sparsity (sum of nonzero coefficients across all `ell_i`) by `sigma_ell`. Let `m'` be the R1CS height and `sigma_R` the total number of nonzero entries in `A, B, C`. Let the sub-protocol codes `C_+, C_x, C^*_x, D` have parameters as in Lemma 3.8, applied to vectors of length `s + 6` (for zk-lin-eval) and `m' + 2` (for zk-Hadamard-check). Then the compiled protocol (Lemma 4.3) using this optimization has the following costs:

- **Prove Time:** `P_0 + sigma_R + sigma_ell + 2 T_{C_+}(s) + 4 T_{C_x}(m') + 2 T_{C^*_x}(m') + T_D(m') + O(m' + s)`.
- **Verify Time:** `V_0 + sigma_ell + T_{C_+}(s) + T_{C_x}(m') + T_{C^*_x}(m') + T_D(m') + O(m' + s)`.

In the prove time, `2 T_{C_+}(s)` and `4 T_{C_x}(m') + T_{C^*_x}(m')` are the costs of the zk-lin-eval and zk-Hadamard-check commitments respectively, `sigma_R` accounts for computing `a, b, c` via sparse matrix-vector products, and `sigma_ell` accounts for evaluating the combined linear constraint `ell = sum_i rho^i ell_i`. The remaining `O(m' + s)` terms come from the sub-protocol internals (Lemmas 3.4 and 3.6). The key savings over the generic circuit evaluation (Lemma 4.3) are twofold: the Hadamard-check operates on vectors of length `m'` (the small R1CS height) rather than `s`, and the linear constraints are handled via a single dot product of cost `sigma_ell + O(s)` rather than passing through a circuit of size `O(n_ell · s)`.

### 4.2 ZK Multilinear PCS

The final protocol commits a multilinear polynomial `f_hat : F^n -> F`. We can later use that commitment to give a partially-zk proof that `f_hat` evaluates to a given value at a publicly-known point `x in F^n`.

**Definition 4.5 (Multilinear Commitment Scheme [DP24a, BFRW25]).** A multilinear polynomial oracle commitment scheme or MCS is a commit-and-prove IOP (Definition 3.1) with:

- Witness space `W = F^(2^n)` (evaluation vectors of `n`-variate multilinear polynomials),
- Explicit input space `X = F^n x F` (a single evaluation pair `(x, y)`),
- Relation `R = {(f, (x, y)) : f_hat(x) = y}`, where `f_hat` is the multilinear polynomial with evaluation vector `f`,

together with an auxiliary input space `R` and error-correcting code `C` with minimum distance `Delta` and message space `W x R` such that, with probability one, for all `w in W`, `Commit(w) = C(w, r)` for some `r in R`. In addition, we require an extra binding property:

(2') **C-IOPP Binding:** There exists a constant `mu` (IOPP-strength) such that if `w' = (w, r) in W x R` is a witness bound to oracle `C` (as in Item (2)), then the verifier accepts with probability at most `2^(-mu · d)` for any `d <= d_rel(C, C w')`.

Finally, if `R` is empty, we call the MCS simple.

**Remark 4.6.** We need to allow for the extra complication of the auxiliary input `R` to achieve zero-knowledge—`P` needs to mask the original input so that information is not revealed by oracle queries to the commitment.

Recall our conventions from Section 2.3.1 representing an `n`-variable multilinear polynomial `f_hat` by its evaluation vector `f in F^(2^n)` on `{0,1}^n`.

We build our zk multilinear PCS out of an arbitrary simple PCS for the same code (e.g., in practice we will use the Reed-Solomon code and a simple PCS for it such as [ZCF24, ACFY25, NA25]). For some choices of `n` and `p`, let `C : F^(2^(n-p)+k) -> F^(2^m)` be a `k`-zk code with minimum relative distance `Delta` and encoding time `T_C(2^(n-p))`. Let `PG ~ F^(2^p+1)` be a zk `(delta, eps_PG)`-proximity-generator for `C` with `delta <= Delta/2`.

Let `C_0 : F^(2^(n-p)) -> F^(2^m)` be the restriction of `C` to the first `2^(n-p)` coordinates. Let `(Commit_0, P_0, V_0)` be a base simple MCS (Definition 4.5) associated to `C_0` with binding error `2^(-lambda_0)` and IOPP-strength `mu_0`, commit time `T_{Commit_0}(2^(n_0))`, prove time `T_{P_0}(2^(n_0))`, and verifier time `T_{V_0}(2^(n_0))` on `n_0`-variable inputs. Finally, let `(P_0, V_0)` involve `k_{0, n_0}` queries to the oracle generated by `Commit_0`.

**Lemma 4.7.** Let `C_0, C` and base simple MCS `(Commit_M, P_M, V_M)` be as specified above. Then there exists an arithmetically partially zk multilinear evaluation interactive oracle commitment scheme `(P, V, Commit)`. When applied to `n`-variable inputs, it depends on a choice of log stacking height `p < n` and padding `k > k_{0, n}` and has the following parameters:

- **Associated code:** the interleaved code `C_int : F^((2^p+1) x (2^(n-p)+k)) -> F^((2^p+1) x 2^m)` defined by `(C_int M)_{ell, i} = (C M_ell)_i` where `M_ell` is the `ell`-th row of `M`. Here, we interpret `W` as the top-right `F^(2^p x 2^(n-p))`-block and the rest of the coordinates as the auxiliary input `R`.
- **Binding error:** `eps_PG(m, |F|) + max{eps^•_PG + 2^(-lambda_0), 2^(-mu_0 delta)}`.
- **IOPP-strength:** `mu_0 (1 - eps^•_PG)`.
- **Query Complexity:** `k_{0, n-p}` queries to `C` with alphabet size `2^p + 1` field elements (via the virtual oracle `C_rho`).
- **Commit Time:** `(2^p + 1) · T_C(2^(n-p) + k) + O(2^n)`.
- **Prove Time:** `T_{P_0}(2^(n-p)) + O(2^n)`.
- **Verify Time:** `T_{V_0}(2^(n-p)) + O(k_{0, n-p} · (k + 2^p))`.
- **Message Complexity:** `2^p + k + 2` prover and `c(PG)` verifier field elements, plus the base protocol's messages.

Furthermore, this protocol takes the form of an interaction phase in which no queries are made to the oracles followed by the base protocol's query phase in which `k_{0, n-p}` queries are made to `C` (via the virtual oracle `C_rho`).

#### 4.2.1 Proof of Lemma 4.7

The commitment algorithm and opening protocol are described, respectively, in Figs. 8 and 9. We let `(Commit_M, P_M, V_M)` be the input MCS based on `C_0`.

**Figure 8: Multilinear Evaluation Commitment**

Parameters: Variable count `n`, log stacking height `p`, `k`-zk code `C : F^(2^(n-p)+k) -> F^(2^m)` (and `C_0` its restriction to the first `2^(n-p)` coordinates)
Input: Multilinear polynomial `F : F^n -> F` (represented as evaluation vector `f in F^(2^n)`)

1. `P` decomposes `f` into `2^p` vectors `f_ell`, each of length `2^(n-p)` and consisting of the coordinates `i` with their first `p` binary digits representing `ell`.
2. `P` pads each `f_ell` with a uniformly random `f_{ell, 1} in F^k` to produce `f'_ell in F^(2^(n-p)+k)`.
3. `P` generates a uniformly random `f'_{2^p+1} in F^(2^(n-p)+k)`.
4. `P` sends as an oracle the interleaved codeword `C in F^((2^p+1) x 2^m)` where `C_{ell, i} = (C f'_ell)_i`.

**Figure 9: Multilinear Evaluation Opening Protocol**

Parameters: Zk proximity generator `PG ~ F^(2^p+1)` for `C`, base MCS `(Commit_0, P_0, V_0)` for `C_0`
Public Input: Commitment `C` and parameters from Fig. 8, point `x in F^n`, claimed evaluation `y in F`.
Prover Private Input: `f'_ell` for `0 <= ell <= 2^p` from commitment scheme.

As notation, we decompose `x = (x^(1) in F^p, x^(2) in F^(n-p))`.

1. `P` sends as exposed `y_ell := f_ell(x^(2))` for `ell in {0, 1}^p ∪ {2^p + 1}`.
2. `V` sends `rho = (rho_ell)_{ell in {0,1}^p ∪ {2^p+1}} <- PG`.
3. `P` sends:
   - (a) as shielded, the last `k` (padding) coordinates `g_1` of

     ```
     g' := sum_{ell in {0,1}^p} rho_ell f'_ell + rho_{2^p+1} · f'_{2^p+1},
     ```

   - (b) as shielded, `a := g(x^(2))`, where `g` is the length-`2^(n-p)` prefix of `g'`.
4. `P, V` define a virtual oracle `C_rho` for which queries are resolved by querying `C` and computing

   ```
   C_{rho, i} = sum_{ell in {0,1}^p} rho_ell C_{ell, i_j} + rho_{2^p+1} · C_{2^p+1, i_j} - (C(0, g_1))_{i_j}.
   ```

   (individually computing each of the values `(C(0, g_1))_{i_j}` using that `g_1` is short).
5. `P, V` run the base evaluation protocol `(P_M, V_M)` with the claim `g(x^(2)) = a` and input oracle `C_rho`. All prover messages sent within are shielded. (Note that `C_rho = C_0 g = Commit_0(g)`).
6. `V` checks:
   - (a) `Y_hat(x^(1)) = y`, where `Y_hat` is the multilinear extension of `Y : {0,1}^p -> F : ell -> y_ell`,
   - (b) `sum_{ell in {0,1}^p} rho_ell y_ell + rho_{2^p+1} · y_{2^p+1} = a`.

**Completeness.** Step 6a passes since `Y_hat` is the multilinear extension of `ell -> f_ell(x^(2))`, so `Y_hat(x^(1)) = F(x^(1), x^(2)) = y`. Step 6b passes since `y_ell = f_ell(x^(2))` so by linearity, `g(x^(2)) = sum_ell rho_ell y_ell + rho_{2^p+1} · y_{2^p+1} = a`. Finally, note that `C_rho = (C g') - C(0, g_1) = C_0 g`. Then, Step 5 passes by the completeness of `(P_0, V_0)`.

**Binding.** Let `C in F^((2^p+1) x 2^m)` be a commitment oracle. Let `[N'_1, ..., N'_{2^p+1}] in F^((2^p+1) x (2^(n-p)+k))` denote the nearest preimage of `C` under `C^(2^p+1)` (breaking ties arbitrarily), and let `f^hat_ell := prefix_{2^(n-p)}(N'_ell)`. The bound witness is `f^hat`, the evaluation vector obtained by interleaving `(f^hat_ell)_{ell in [2^p]}`, with auxiliary data consisting of the remaining components of the `N'_ell` (the padding entries and extra row).

Fix a cheating prover `P*` and claim `(x, y)`. Decompose `x = (x^(1), x^(2))`. Let `y_ell` denote the prover's Step 1 messages and `a, g_1` the prover's Step 3 messages. Define

```
C'_rho := C g' = C_rho + C(0, g_1).
```

*Evaluation claim binding.* We show that if `F^hat(x) != y`, the verifier accepts with low probability. We show each type of violation is caught by three cases that parallel the argument from zk-linear-eval (Lemma 3.4).

*Step 6a forces a lie.* If `y_ell = f^hat_ell(x^(2))` for all `ell in [2^p]`, then `Y_hat(x^(1)) = F^hat(x) != y`, so the verifier rejects. Hence some `y_ell != f^hat_ell(x^(2))`. We may also assume Step 6b passes, i.e., `a = sum_{ell in {0,1}^p} rho_ell y_ell + rho_{2^p+1} · y_{2^p+1}`. Define

```
T^C(rho) := sum_{ell in {0,1}^p} rho_ell C N'_ell + rho_{2^p+1} · C N'_{2^p+1},
g'^hat := sum_{ell in {0,1}^p} rho_ell N'_ell + rho_{2^p+1} · N'_{2^p+1},
```

with prefix `g^hat` and padding suffix `g^hat_1`, so that `T^C(rho) = C g'^hat`.

*The base IOPP catches malformed oracles.* Either `d_rel(C, C^(2^p+1)) < delta` or not. In the second case, the proximity gaps property (Definition 2.14) gives `d_rel(C'_rho, C) >= delta` except with probability `<= eps_PG(m, |F|)` over `rho <- PG`. When the distance bound holds,

```
d_rel(C_rho, C_0) >= d_rel(C_rho, C) = d_rel(C'_rho, C) >= delta.
```

using `C(0, g_1) in C` and that `C` is linear for the equality. Therefore, by the IOPP-strength of the base MCS, the base IOP accepts with probability at most `eps_PG(m, |F|) + 2^(-mu_0 delta)`.

*Steps 5–6 catch false evaluations.* We may therefore restrict to well-formed oracles: `d_rel(C, C^(2^p+1)) < delta`. Let `g*` be the input bound to oracle `C_rho` under the base IOPP. Consider the case `g_1 = g^hat_1` and `g^hat = g*`. Since some `y_ell != f^hat_ell(x^(2))`, the difference `g^hat(x^(2)) - a` is a nonzero linear form in the PG coefficients `rho`, so the claim `g*(x^(2)) = g^hat(x^(2)) = a` is false except with probability `<= eps^•_PG` over `rho`. When false, the base protocol's evaluation binding gives pass probability `<= 2^(-lambda_0)` for an overall acceptance probability upper bound of `<= eps^•_PG + 2^(-lambda_0)`.

*The base IOPP catches inconsistent responses.* We may therefore further restrict to `g_1 != g^hat_1` or `g^hat != g*`. We have `C'_rho - T^C(rho) = C_rho - C(g^hat, g^hat_1 - g_1)`. Since by definition of the `N'_ell`

```
d_rel(C, [C N'_1, ..., C N'_{2^p+1}]) = d_rel(C, C^(2^p+1)) < delta,
```

we have

```
delta >= d_rel(C'_rho, T^C(rho)) = d_rel(C_rho, C(g^hat, g^hat_1 - g_1)).
```

The definition of minimum distance gives `d_rel(C(g^hat, g^hat_1 - g_1), C_0 g*) >= Delta`, so the reverse triangle inequality gives

```
d_rel(C_rho, C_0 g*) >= Delta - delta >= delta
```

implying acceptance probability at most `2^(-mu_0 delta)` by the IOPP-strength of the base MCS.

*Overall Bound.* The oracle is either malformed or well-formed. In the malformed case, the total chance of acceptance is `<= eps_PG(m, |F|) + 2^(-mu_0 delta)`. In the well-formed case, taking a maximum over the two subcases gives acceptance probability at most

```
max{eps^•_PG + 2^(-lambda_0), 2^(-mu_0 delta)}.
```

Finally, since `max(A + C, max(B, C)) <= A + max(B, C)` for `A, B, C >= 0`, the overall acceptance probability is at most `eps_PG(m, |F|) + max{eps^•_PG + 2^(-lambda_0), 2^(-mu_0 delta)}`.

*Code Proximity Binding.* Write `epsilon := d_rel(C, C w')` where `w'` is the bound witness (`f^hat` together with its auxiliary data).

Since the oracle is queried column-wise, `epsilon` is the fraction of columns `i` where `C_{ell, i} != (C N'_ell)_i` for some row `ell`. For each such bad column `i`, the linear form

```
p_i(rho) := sum_{ell in {0,1}^p} rho_ell (C_{ell, i} - (C N'_ell)_i) + rho_{2^p+1} (C_{2^p+1, i} - (C N'_{2^p+1})_i)
```

is nonzero in the PG coefficients, so `Pr_{rho <- PG}[p_i(rho) = 0] <= eps^•_PG`. Since `T(rho)_i - T^C(rho)_i = p_i(rho)`, linearity of expectation gives

```
E_{rho <- PG}[d_rel(T(rho), T^C(rho))] >= epsilon (1 - eps^•_PG) =: delta'.
```

In particular, there exists `rho_0` in the support of PG with `d_rel(T(rho_0), T^C(rho_0)) >= delta'`.

Fix any `epsilon_0 < min(delta', delta)`. We claim `d_rel(T(rho_0), C) > epsilon_0`. If not, then `d_rel(T(rho_0), C) <= epsilon_0 < delta`, so the nearest codeword `c` satisfies `d_rel(T(rho_0), c) <= epsilon_0`. If `c = T^C(rho_0)`, then `d_rel(T(rho_0), T^C(rho_0)) <= epsilon_0 < delta'`, contradicting the choice of `rho_0`. If `c != T^C(rho_0)`, the triangle inequality gives `Delta <= d_rel(c, T^C(rho_0)) <= epsilon_0 + d_rel(T(rho_0), T^C(rho_0)) <= epsilon_0 + epsilon`; but `epsilon_0 < delta' = epsilon (1 - eps^•_PG)`, so `epsilon_0 + epsilon < epsilon (2 - eps^•_PG) <= Delta` whenever `epsilon <= delta`, a contradiction. (For `epsilon > delta`, see below.)

Therefore, applying the proximity gaps property (Definition 2.14) gives

```
Pr_{rho <- PG}[d_rel(T(rho), C) <= epsilon_0] <= eps_PG(m, |F|).
```

When `d_rel(T(rho), C) > epsilon_0`, the same `alpha + beta` tradeoff as in the malformed-oracles case (with `epsilon_0` in place of `delta`) gives combined accept probability `<= 2^(-mu_0 epsilon_0)`. Taking `epsilon_0 -> min(delta', delta)`, the overall accept probability is at most `eps_PG(m, |F|) + 2^(-mu_0 · min(delta', delta))`.

For `epsilon > delta`: the same argument applies with `epsilon_0 < delta`; the unique-decoding contradiction `c != T^C(rho_0)` may no longer close, but one can verify that `epsilon_0 + epsilon < Delta` still holds whenever `epsilon < Delta/(2 - eps^•_PG)`, which covers a neighbourhood above `delta`. In any case the bound above with `min(delta', delta) = delta` gives IOPP-strength `mu_0 (1 - eps^•_PG)`.

**Partial Zero-knowledge.** A valid `Sim` gets as input `(x, y)` and the verifier randomness: `rho` and the randomness `rho_b` used in the base protocol. It has to generate all prover messages in Step 3 and the base evaluation protocol in Step 5. In the true base evaluation protocol, prover messages come in two forms: either oracle queries `(C_{rho, j_i})_i` to `C_rho`, or messages `mu_s` that only depend on `g`. In the true Step 5, the verifier instead sees the `(C_{ell, j_i})_{ell, i}` and the `mu_s`.

We define `Sim` as follows:

1. Generate a `g' in F^(2^(n-p)+k)` uniformly at random.
2. For each `i` generate the oracle queries `C_{ell, j_i}` for `ell in {0, 1}^p` uniformly at random and set

   ```
   C_{2^p+1, j_i} = rho_{2^p+1}^(-1) ((C g')_{j_i} - sum_{ell in {0,1}^p} rho_ell C_{ell, j_i})
   ```

3. Steps 3–5 form a subprotocol that only requires `x, g'` as prover inputs and `x, g_1, (C_{ell, j_i})_{ell, i}` as verifier inputs. Run both sides of this subprotocol to generate all non-`(C_{ell, i})_{ell, i}` messages in Steps 3–5.

All outputs produced by `Sim` and in the true protocol with an honest prover only depend on public inputs, verifier randomness, the `(C_rho)_{j_i}`, and `g'`. It therefore suffices to show that `g'` and `(C_rho)_{j_i}` have the same distribution in `Sim` and the true protocol.

First, since `f'_{2^p+1}` is uniformly random and `rho_{2^p+1} != 0` (as `PG` is zk), the term `rho_{2^p+1} · f'_{2^p+1}` is uniformly random implying `g'` is uniform as well.

Next, since the `f_{ell, 1}` for `ell in {0,1}^p ∪ {2^p+1}` are i.i.d. uniform, `k > k_{0, n}` and `C` is a `k`-zk-code, the `C_{ell, j_i}` are i.i.d. uniform and independent of `g`. In addition, since `f_{2^p+1, 1}` is uniform and `rho_{2^p+1} != 0`, `g_1` is uniform and independent of `g` and the `C_{ell, j_i}`. In total, these `C_{ell, j_i}` are i.i.d. uniform and independent of `g'`, which suffices since this determines the final `C_{2^p+1, j_i}` in both `Sim` and the true protocol.

*Arithmetic:* The verifier checks are in step 6 and the base protocol. The former are linear expressions in shielded and exposed messages and the latter only involve shielded messages and public inputs.

### 4.3 Final Compilation

Our final compilation combines Lemma 4.3 with the following:

**Lemma 4.8.** Let `(P_0, V_0)` be an MIOP for relation `R` on inputs `x` with soundness error `epsilon_0`. In addition, let `(Commit_ml, P_ml, V_ml)` be an arithmetically partially zk multilinear evaluation interactive oracle commitment scheme with binding error `epsilon_bind`. Then the protocol described in Fig. 10 is an arithmetically partially zk IOP `(P, V)` for relation `R` with soundness error at most `epsilon_0 + epsilon_bind`.

#### 4.3.1 Proof of Lemma 4.8

Without loss of generality, we may assume that the input MIOP `(P_0, V_0)` makes at most one evaluation query to each multilinear oracle — see [RR24] for a standard technique to convert MIOPs into this form. The compilation is then described in Fig. 10.

**Figure 10: Final Compilation: MIOP to Arithmetically Partially-ZK IOP**

Parameters: MIOP `(P_0, V_0)`; zk-Multilinear-PCS `(Commit_M, P_M, V_M)`.
Public Input: Input `x` to the original protocol `(P_0, V_0)`.

1. `(P, V)` run the protocol `(P_0, V_0)` with the following modifications:
   - If `P` would send a field element `alpha_i in F`, it sends it as exposed.
   - If `P` would send a multilinear oracle `f`, it instead sends the zk-Multilinear-PCS (Fig. 8) commitment oracle `Commit_M(f)`.
   - If `V` would query a multilinear oracle `f` at point `z` to receive `y`, `P` instead sends `y` as exposed.
   - At the end, for each multilinear commitment, `(P, V)` runs the `(P_M, V_M)` proof protocol on its evaluation claim.

**Completeness.** The protocol consists of two steps: first running the original protocol. Then doing the end checks of the zk-Multilinear-PCS (Lemma 4.7). If `(w, x) in R`, then, with an honest `P` the first step is accepted because `(P_0, V_0)` is complete. The second step is accepted since the zk-Multilinear-PCS is complete.

**Soundness.** Assume no `w` satisfies `(w, x) in R`, and fix an arbitrary prover `P*`. For each commitment oracle `C_j` sent by `P*`, let `f^hat_j` be the bound witness under the PCS. We partition the event that the compiled verifier accepts into two cases.

*All evaluation claims consistent.* Suppose every claimed evaluation `y_j` equals `f^hat_j(z_j)`. Then the MIOP verifier's view is identical to an execution with oracles `f^hat_j`. Since no `w` satisfies `(w, x) in R`, the MIOP soundness gives acceptance probability `<= epsilon_0`.

*Some evaluation claim inconsistent.* Suppose `y_j != f^hat_j(z_j)` for some `j`. Since the compiled verifier accepts only if all PCS proofs pass, and in particular the PCS proof for commitment `j` must pass with a false evaluation claim, the PCS binding gives acceptance probability `<= epsilon_bind`.

Since these two cases are exhaustive, the overall acceptance probability is at most `epsilon_0 + epsilon_bind`.

**Partial Zero-knowledge.** The only shielded messages are sent within the zk-Multilinear-PCS (Lemma 4.7) openings. There is exactly one opening per commitment, and these are independent, so the simulators generating the shielded messages for each may be composed.

Finally, all oracle queries only happen within the zk-Multilinear-PCS where they are shielded.

**Arithmetic.** The only checks the verifier runs come from the original MIOP or the internal zk-Multilinear-PCS openings. These are all polynomial.

---

## 5. Concrete Analysis

The full compilation combines the final compilation (Lemma 4.8) with the intermediate compilation (Lemma 4.3). This section analyzes the resulting overhead: first in terms of abstract sub-protocol parameters (Section 5.1), then with concrete code and proximity generator choices (Section 5.2).

For simplicity, suppose the MIOP sends a single multilinear oracle with `n` variables, stacking height `p`, and padding `k`. The case of multiple oracles is analogous, with the PCS contributions replaced by sums over the individual oracles. We assume the base MIOP uses a "stacked" variant of the base simple MCS `(Commit_M, P_M, V_M)`—a simpler version of Fig. 9/Fig. 8 that omits the padding and mask, using only the virtual oracle `C_rho := sum_{ell in {0,1}^p} rho_ell C_ell`. This base PCS has commit time `2^p T_{C_0}(2^(n-p)) + O(2^n)`, prove time `T_{P_M}(2^(n-p)) + O(2^n)`, and verify time `T_{V_M}(2^(n-p)) + O(k_{0, n-p} · 2^p)`.

### 5.1 End-to-End Abstract Analysis

Let `P_MIOP, V_MIOP` denote the base MIOP prove and verify times (including the base PCS costs above), and let `sigma_R, sigma_ell, m', s` and the sub-protocol codes `C_+, C_x, C^*_x, D` be as in Remark 4.4.

#### 5.1.1 Timing

The zk compilation replaces the base PCS with the zk-multilinear-PCS (Lemma 4.7), then applies the intermediate compilation. Both PCS variants invoke the same base simple MCS `(P_M, V_M)` on input length `2^(n-p)`, so the MCS prove and verify costs cancel. The changes are the PCS commit overhead

```
DeltaC := (2^p + 1) T_C(2^(n-p) + k) - 2^p T_{C_0}(2^(n-p)),
```

from encoding one additional mask row and `k` extra padding coordinates per row, and the PCS verify overhead `DeltaV := O(k_{0, n-p} · k)`, from the enlarged query alphabet (each query to `C_rho` requires evaluating `C(0, g_1)` at one coordinate, costing `O(k)`).

The final compilation (Lemma 4.8) thus produces a partially-zk protocol with `P_0 = P_MIOP + DeltaC` and `V_0 = V_MIOP + DeltaV`. Substituting into Remark 4.4:

- **Prove Time:** `P_MIOP + DeltaC + sigma_R + sigma_ell + 4 T_{C_x}(m') + 2 T_{C^*_x}(m') + 2 T_{C_+}(s) + T_D(m') + O(m' + s)`.
- **Verify Time:** `V_MIOP + DeltaV + sigma_ell + T_{C_x}(m') + T_{C^*_x}(m') + T_{C_+}(s) + T_D(m') + O(m' + s)`.

#### 5.1.2 Soundness

Let `epsilon_0` denote the soundness error of the base MIOP, `epsilon_{bind, PCS}` the binding error of the multilinear PCS (Lemma 4.7), and `epsilon_{bind, CE}` the binding error of the circuit evaluation scheme (Lemma 3.8):

```
epsilon_{bind, PCS} = eps_PG(m, |F|) + max{eps^•_PG + 2^(-lambda_0), 2^(-mu_0 delta)},
epsilon_{bind, CE} = 3 eps^•_{LB_x} + 2/|F| + max{eps_+, eps_x},
```

where `eps_+, eps_x` are the binding errors of the zk-linear-eval (Lemma 3.4) and zk-Hadamard-check (Lemma 3.6), and `eps^•_{LB_x}` is the linear bias of `LB_x`.

By Lemma 4.8, the partially-zk protocol has soundness error at most `epsilon_0 + epsilon_{bind, PCS}`. The intermediate compilation (Lemma 4.3) adds `epsilon_{bind, CE}`: let `h` be the witness bound to the circuit evaluation commitment. When `C'_{s, x, r, v'}(h) = 0` (probability `<= epsilon_0 + epsilon_{bind, PCS}`), the circuit evaluation accepts by completeness. When `C'_{s, x, r, v'}(h) != 0`, acceptance requires the circuit evaluation binding to fail (probability `<= epsilon_{bind, CE}`). The total soundness error is at most

```
epsilon_0 + epsilon_{bind, PCS} + epsilon_{bind, CE}.
```

### 5.2 Concrete Instantiation

#### 5.2.1 Code and Proximity Generator Choice

We choose coefficient-to-evaluation Reed-Solomon codes (Example 2.9) for every non-multiplicative code and interpolation Reed-Solomon codes (Example 2.10) for each multiplicative code with `C^*, D`. All RS codes have rate `1/16`, giving block lengths `m_+ = 16(n' + 6 + lambda)` and `m_x = 16(m' + 2 + lambda)` for the circuit evaluation codes, and `2^m = 16(2^(n-p) + k)` for the PCS code, where `lambda` is the sub-protocol zk padding and `k >= k_{0, n-p}` is the PCS zk padding.

As in Example 2.21, the proximity generators in zk-lin-eval and zk-Hadamard-check are zk-degree-`t` for the appropriate `t`, and the PCS proximity generator is augmented `t`-MLE. For all linear bias generators (`LB` in zk-Hadamard-check and `LB_x` in zk-circuit-eval, each on vectors of length `n`), we use the degree-`n` distribution `(1, rho, ..., rho^(n-1)) in F^n` for `rho` uniform over `F`, giving linear bias `(n - 1)/|F|` and randomness complexity 1.

#### 5.2.2 Oracle Handling

We realize oracles as follows: Each entry of the oracle is hashed and then all hashes are committed as a Merkle tree whose root `P` sends to `V`. If `V` needs to open a proof, it asks `P` for the full Merkle path proving the Merkle-tree opening.

For an oracle of length `n` with entries of size `x` field elements, generating the tree takes `O(n x)` prover time (hashing `n` leaves and `n - 1` internal nodes). Each query requires the prover to send the entry (`x` field elements) and a Merkle path (`ceil(log_2 n)` hash digests). The verifier hashes the entry and walks up the path, costing `O(x + log n)` time.

#### 5.2.3 Explicit Overhead

We target `b` bits of security and substitute the choices of Section 5.2.1 into the abstract analysis of Section 5.1.

**Soundness.** The concrete binding errors are

```
epsilon_{bind, CE} = (3 m' + 5)/|F| + max{eps_+, eps_x},
eps_+ = m_+/|F| + (17/32)^lambda,
eps_x = (65 m' + 64 lambda + 129)/|F| + (9/16)^lambda,
epsilon_{bind, PCS} = (m p)/|F| + max{p/|F| + 2^(-lambda_0), 2^(-15 mu_0 / 32)},
```

where `lambda_0` is the base MCS binding exponent and `mu_0` its IOPP-strength. To achieve `epsilon_{bind, CE}, epsilon_{bind, PCS} <= 2^(-b)` (giving total soundness `<= epsilon_0 + 2^(-b+1)`), it suffices to require:

- `lambda >= ceil((b + 1)/log_2(32/17))`,
- `|F| >= max{16 n' + 3 m' + 16 lambda + 101, (m + 1) p} · 2^(b+1)`,
- `lambda_0 >= b + 1` and `mu_0 >= ceil(32(b + 1)/15)`.

For `b = 100`: `lambda >= 111`, `lambda_0 >= 101`, `mu_0 >= 216`, and `log_2|F| >= max{log_2(16 n' + 3 m' + 1877), log_2((m + 1) p)} + 101`.

**Timing and proof size.** Since `C_0` and `C` share the same RS evaluation domain, `T_{C_0}(2^(n-p)) = T_C(2^(n-p) + k) = O(m · 2^m)`, so the PCS commit overhead is one additional RS encoding (for the mask row). The circuit evaluation requires 2 coefficient-to-evaluation encodings with `C_+` (domain size `m_+`) and 6 interpolation encodings with `C_x` (domain size `m_x`, message size `m' + 2`). A coefficient-to-evaluation encoding on domain size `N` costs one size-`N` FFT; an interpolation encoding on domain `N` with message size `d` costs one size-`d` inverse FFT plus one size-`N` forward FFT (Example 2.10). Each size-`N` FFT costs `(N/2) log_2 N` field multiplications and `N log_2 N` additions.

The compiled protocol produces three oracles beyond those of the base MIOP: `C_+` (length `m_+`, entry size 2, queried `lambda` times), `C_x` (length `m_x`, entry size 5, queried `lambda` times), and the PCS oracle `C` (length `2^m`, entry size `2^p + 1`, queried `k_{0, n-p}` times). Merkle-committing these requires `2^m + m_+ + m_x` leaf hashes and the same number of internal-node hashes. In the Merkle-committed protocol, the verifier does not perform full encodings; instead, it evaluates the target codeword polynomials at the queried positions via Horner's method, costing `lambda(s + 2 m' + 10)` multiplications for the circuit evaluation codes and `k_{0, n-p} · k` for the PCS code. Each query also requires hashing the opened entry and verifying a Merkle path.

The ZK overhead beyond the base protocol is:

- **Prove Time:** `sigma_R + sigma_ell` field multiplications for constraint evaluation; `(1/2)(m · 2^m + 2 m_+ log_2 m_+ + 6(m' + 2) log_2(m' + 2) + 6 m_x log_2 m_x)` multiplications for encoding (1 PCS FFT, 2 `C_+` FFTs, 6 `C_x` iFFT+FFT pairs); `2(2^m + m_+ + m_x)` hashes for Merkle commitment.
- **Verify Time:** `sigma_ell + lambda(s + 2 m' + 10) + k_{0, n-p} · k` field multiplications; `k_{0, n-p}(m + 1) + lambda(ceil(log_2 m_+) + ceil(log_2 m_x) + 2)` hashes for Merkle verification.
- **Proof Size:**
  - `k_{0, n-p} · m + lambda(ceil(log_2 m_+) + ceil(log_2 m_x)) + 3` hash digests,
  - `(k_{0, n-p} + 1)(2^p + 1) + 3 m' + n' + 11 lambda + k + p + 25` field elements.

### 5.3 Experimental Results

Using a proof-of-concept implementation in Rust, we test a standard protocol that (separately) commits two randomly generated multilinears `f, g` over a 31-bit prime field and proves a Hadamard sumcheck of the form

```
sum_{x in {0,1}^n} f(x) g(x).
```

For soundness, the sumcheck is run relative to a degree 4 extension of the base field. The sumcheck reduces the claim to evaluation claims on `f` and `g`, which are proved with a stacking height of `p = 8` and using Basefold [ZCF24] for the base PCS (in a future version we plan to change to the WHIR [ACFY25] protocol which has shorter proofs). We target 100 bits of security while using the proximity gap theorem for the unique-decoding regime of [BCI+23]. The IOP is compiled into a succinct argument using the Poseidon2 hash function (see [CY24] for details). We compare the direct non-zk variant of the protocol vs. one compiled to be zk using VEIL.

The benchmarking was done on a MacBook Pro with an M4 processor and 36GB of RAM. We also made some common optimizations for both the zk and non-zk protocol. Many heavy computations—Reed-Solomon encoding, taking RLC's of the sub-MLE's `f_ell`, etc — were multithreaded using the Rayon package. Finally, the two final evaluation claims at a common point were batched.

We run each experiment 10 times and take the median for timings. The results are presented in Table 5.1.

**Table 5.1: End-to-end ZK overhead for varying trace size.**

| log(trace) | Prover Non-ZK (s) | Prover ZK (s) | Prover Factor | Verifier Non-ZK (ms) | Verifier ZK (ms) | Verifier Factor | Proof Non-ZK (KB) | Proof ZK (KB) | Proof Factor |
|---|---|---|---|---|---|---|---|---|---|
| 25 | 3.19 | 3.32 | 1.04× | 12.49 | 15.94 | 1.28× | 747 | 872 | 1.17× |
| 27 | 13.00 | 13.48 | 1.04× | 14.75 | 18.76 | 1.27× | 868 | 993 | 1.14× |
| 29 | 52.47 | 54.09 | 1.03× | 17.34 | 21.13 | 1.22× | 1001 | 1126 | 1.12× |

---

## References

[ACFY25] Gal Arnon, Alessandro Chiesa, Giacomo Fenzi, and Eylon Yogev. WHIR: Reed-Solomon proximity testing with super-fast verification. In *Advances in Cryptology - EUROCRYPT 2025*, volume 15604 of LNCS, pages 214–243. Springer, 2025.

[AHIV17] Scott Ames, Carmit Hazay, Yuval Ishai, and Muthuramakrishnan Venkitasubramaniam. Ligero: Lightweight sublinear arguments without a trusted setup. In *CCS 2017*, pages 2087–2104. ACM, 2017.

[BCF+17] Eli Ben-Sasson, Alessandro Chiesa, Michael A. Forbes, Ariel Gabizon, Michael Riabzev, and Nicholas Spooner. Zero knowledge protocols from succinct constraint detection. In *TCC 2017*, volume 10678 of LNCS, pages 172–206. Springer, 2017.

[BCI+23] Eli Ben-Sasson, Dan Carmon, Yuval Ishai, Swastik Kopparty, and Shubhangi Saraf. Proximity gaps for Reed-Solomon codes. *J. ACM*, 70(5):31:1–31:57, 2023.

[BCL22] Jonathan Bootle, Alessandro Chiesa, and Siqi Liu. Zero-knowledge IOPs with linear-time prover and polylogarithmic-time verifier. In *EUROCRYPT 2022*, volume 13276 of LNCS, pages 275–304. Springer, 2022.

[BCR+19] Eli Ben-Sasson, Alessandro Chiesa, Michael Riabzev, Nicholas Spooner, Madars Virza, and Nicholas P. Ward. Aurora: Transparent succinct arguments for R1CS. In *EUROCRYPT 2019*, pages 103–128, 2019.

[BCS16] Eli Ben-Sasson, Alessandro Chiesa, and Nicholas Spooner. Interactive oracle proofs. In *TCC 2016-B*, pages 31–60, 2016.

[BFLS91] László Babai, Lance Fortnow, Leonid A. Levin, and Mario Szegedy. Checking computations in polylogarithmic time. In *STOC 1991*, pages 21–31, 1991.

[BFRW25] Benedikt Bünz, Giacomo Fenzi, Ron D. Rothblum, and William Wang. TensorSwitch: Nearly optimal polynomial commitments from tensor codes. *IACR Cryptol. ePrint Arch.*, page 2065, 2025.

[BGG+88] Michael Ben-Or, Oded Goldreich, Shafi Goldwasser, Johan Håstad, Joe Kilian, Silvio Micali, and Phillip Rogaway. Everything provable is provable in zero-knowledge. In *CRYPTO '88*, volume 403 of LNCS, pages 37–56. Springer, 1988.

[CFS17] Alessandro Chiesa, Michael A. Forbes, and Nicholas Spooner. A zero knowledge sumcheck and its applications. *CoRR*, abs/1704.02086, 2017.

[CFW26] Alessandro Chiesa, Giacomo Fenzi, and Guy Weissenberg. Zero-knowledge IOPPs for constrained interleaved codes. *Cryptology ePrint Archive*, Paper 2026/391, 2026.

[CY24] Alessandro Chiesa and Eylon Yogev. *Building Cryptographic Proofs from Hash Functions*. 2024.

[DGR20] Scott E. Decatur, Oded Goldreich, and Dana Ron. A probabilistic error-correcting scheme that provides partial secrecy. In *Computational Complexity and Property Testing*, volume 12050 of LNCS, pages 1–8. Springer, 2020.

[Dia25] Benjamin E. Diamond. Zero-knowledge polynomial commitment in binary fields. *IACR Cryptol. ePrint Arch.*, page 1015, 2025.

[DP24a] Benjamin E. Diamond and Jim Posen. Polylogarithmic proofs for multilinears over binary towers. *Cryptology ePrint Archive*, 2024.

[DP24b] Benjamin E. Diamond and Jim Posen. Proximity testing with logarithmic randomness. *IACR Commun. Cryptol.*, 1(1):2, 2024.

[FS86] Amos Fiat and Adi Shamir. How to prove yourself: Practical solutions to identification and signature problems. In *CRYPTO '86*, volume 263 of LNCS, pages 186–194. Springer, 1986.

[FS24] Matteo Frigo and Abhi Shelat. Anonymous credentials from ECDSA. *IACR Cryptol. ePrint Arch.*, page 2010, 2024.

[GMR89] Shafi Goldwasser, Silvio Micali, and Charles Rackoff. The knowledge complexity of interactive proof systems. *SIAM Journal on Computing*, 18(1):186–208, 1989.

[Gro16] Jens Groth. On the size of pairing-based non-interactive arguments. In *EUROCRYPT 2016*, volume 9666 of LNCS, pages 305–326. Springer, 2016.

[GWC19] Ariel Gabizon, Zachary J. Williamson, and Oana Ciobotaru. PLONK: permutations over Lagrange-bases for oecumenical noninteractive arguments of knowledge. *IACR Cryptol. ePrint Arch.*, page 953, 2019.

[HK24] Ulrich Haböck and Al Kindi. A note on adding zero-knowledge to STARKs. *IACR Cryptol. ePrint Arch.*, page 1037, 2024.

[ISVW13] Yuval Ishai, Amit Sahai, Michael Viderman, and Mor Weiss. Zero knowledge LTCs and their applications. In *APPROX/RANDOM 2013*, volume 8096 of LNCS, pages 607–622. Springer, 2013.

[Kil92] Joe Kilian. A note on efficient zero-knowledge proofs and arguments (extended abstract). In *STOC 1992*, pages 723–732, 1992.

[KR08] Yael Tauman Kalai and Ran Raz. Interactive PCP. In *ICALP 2008*, pages 536–547, 2008.

[KS25] Darya Kaviani and Srinath Setty. Vega: Low-latency zero-knowledge proofs over existing credentials. *Cryptology ePrint Archive*, Paper 2025/2094, 2025.

[Mic00] Silvio Micali. Computationally sound proofs. *SIAM J. Comput.*, 30(4):1253–1298, 2000.

[NA25] Andrija Novakovic and Guillermo Angeris. Ligerito: A small and concretely fast polynomial commitment scheme. *IACR Cryptol. ePrint Arch.*, page 1187, 2025.

[NN93] Joseph Naor and Moni Naor. Small-bias probability spaces: Efficient constructions and applications. *SIAM J. Comput.*, 22(4):838–856, 1993.

[RR24] Noga Ron-Zewi and Ron Rothblum. Local proofs approaching the witness length. *J. ACM*, 71(3):18, 2024.

[RRR21] Omer Reingold, Guy N. Rothblum, and Ron D. Rothblum. Constant-round interactive proofs for delegating computation. *SIAM J. Comput.*, 50(3), 2021.

[RW24] Noga Ron-Zewi and Mor Weiss. Zero-knowledge IOPs approaching witness length. In *CRYPTO 2024*, volume 14929 of LNCS, pages 105–137. Springer, 2024.

[SP1] SP1 Hypercube. https://github.com/succinctlabs/sp1.

[WTS+18] Riad S. Wahby, Ioanna Tzialla, Abhi Shelat, Justin Thaler, and Michael Walfish. Doubly-efficient zkSNARKs without trusted setup. In *IEEE S&P 2018*, pages 926–943. IEEE Computer Society, 2018.

[XZS22] Tiancheng Xie, Yupeng Zhang, and Dawn Song. Orion: Zero knowledge proof with linear prover time. In *CRYPTO 2022*, volume 13510 of LNCS, pages 299–328. Springer, 2022.

[XZZ+19] Tiancheng Xie, Jiaheng Zhang, Yupeng Zhang, Charalampos Papamanthou, and Dawn Song. Libra: Succinct zero-knowledge proofs with optimal prover computation. In *CRYPTO 2019*, volume 11694 of LNCS, pages 733–764. Springer, 2019.

[ZCF24] Hadas Zeilberger, Binyi Chen, and Ben Fisch. Basefold: Efficient field-agnostic polynomial commitment schemes from foldable codes. In *CRYPTO 2024*, volume 14929 of LNCS, pages 138–169. Springer, 2024.
