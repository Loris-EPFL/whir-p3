# IVC Implementation Guide

## Overview

This document describes the IVC (Incrementally Verifiable Computation) stack built on top of the whir-p3 Quasar+WARP accumulation scheme. The implementation spans three layers:

1. **Accumulation infrastructure** — standalone decider, lightweight verifier split
2. **Circuit infrastructure** — R1CS builder, Poseidon2 gadget, extension field arithmetic, duplex sponge
3. **IVC loop** — step circuit trait, recursive verifier circuit, unified prover/verifier

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        IVC Loop                              │
│                                                              │
│   Step i:                                                    │
│   ┌──────────────────────────────────────┐                   │
│   │  Unified Circuit (R1CS)              │                   │
│   │  ┌──────────┐  ┌──────────────────┐  │                   │
│   │  │ Step     │  │ Accumulation     │  │                   │
│   │  │ Circuit  │  │ Verifier         │  │                   │
│   │  │ (user)   │  │ (Fiat-Shamir +   │  │                   │
│   │  │          │  │  sumcheck + EF   │  │                   │
│   │  │          │  │  arithmetic)     │  │                   │
│   │  └──────────┘  └──────────────────┘  │                   │
│   └──────────────────────────────────────┘                   │
│                        │                                     │
│                   Spartan prove                              │
│                        │                                     │
│                   Linearize into accumulator                 │
│                        │                                     │
│                   WARP fold with running accumulator          │
│                        │                                     │
│                   Output: new IVCState                        │
│                                                              │
│   Final: AccumulationDecider.prove() + verify()              │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Map

### `src/circuit/` — R1CS Circuit Infrastructure

| File | Purpose | Key Types/Functions |
|------|---------|-------------------|
| `builder.rs` | R1CS constraint builder | `CircuitBuilder`, `Var`, `LinearCombination` |
| `poseidon2.rs` | Poseidon2 permutation as R1CS (generic WIDTH) | `Poseidon2CircuitConfig`, `poseidon2_permute_circuit` |
| `ext_field.rs` | BinomialExtensionField<F,4> arithmetic | `ExtVar`, `ExtVal`, `ext_mul`, `ext_add`, `ext_scale` |
| `sponge.rs` | DuplexChallenger replica as R1CS | `CircuitChallenger` |
| `bits.rs` | Bit decomposition gadget | `decompose_low_bits`, `bits_to_index` |

### `src/ivc/` — IVC Loop

| File | Purpose | Key Types/Functions |
|------|---------|-------------------|
| `step.rs` | User step circuit trait | `StepCircuit`, `TrivialStepCircuit` |
| `verifier_circuit.rs` | Recursive accumulation verifier | `synthesize_accumulation_verifier`, `synthesize_unified_ivc_circuit` |
| `ivc.rs` | IVC prover/verifier orchestration | `IVCProver`, `IVCVerifier`, `IVCState` |

### `src/accumulation/` — Accumulation Extensions

| File | Purpose | Key Types/Functions |
|------|---------|-------------------|
| `decider.rs` | Standalone decider (fresh WHIR proof) | `AccumulationDecider`, `DeciderProof` |
| `compact_instance.rs` | Compact `(r, y)` accumulator representation | `CompactAccumulatorInstance` |
| `scheme.rs` | Lightweight verifier (extracted) | `accumulation_verify_lightweight` |

---

## How the Recursive Circuit Works

The recursive circuit (`synthesize_accumulation_verifier`) arithmetizes the lightweight accumulation verifier as R1CS constraints. It verifies that the **previous** accumulation step was performed correctly by:

### 1. Fiat-Shamir Transcript Re-derivation

The `CircuitChallenger` exactly replicates `DuplexChallenger<F, Perm, 16, 8>`:
- **Observe**: overwrite sponge state positions with input, permute when rate (8) is full
- **Sample**: pop from output buffer after permutation
- **Permutation**: full Poseidon2 as R1CS constraints via `poseidon2_permute_circuit`

The circuit observes the same data as the real challenger (commitment roots, linear claim targets, sumcheck messages) and samples the same challenges. Any deviation causes the derived challenges to mismatch, making the constraints unsatisfiable.

### 2. Constraint Batching Sumcheck Verification

For each of `num_vars` rounds, the circuit verifies:
```
s1 = claimed_sum - s0
d = s1 - s0 - s2
new_claimed = s0 + d*r + s2*r²
```

All operations are in the extension field (BinomialExtensionField<KoalaBear, 4>), using `ext_mul` (20 R1CS constraints per EF multiplication) for `d*r`, `r²`, and `s2*r²`.

### 3. Combined Evaluation

```
combined_eval = Σᵢ ηⁱ · fᵢ(r)
```

where `η` is the codeword batching challenge and `fᵢ(r)` are individual evaluations from the sumcheck.

### 4. OOD + Shift Query Consistency

The circuit derives the OOD point and shift query indices from the sponge and constrains them to match the transcript values. Shift queries use `decompose_low_bits` for bit decomposition with boolean constraints.

### Constraint Budget

For k=2 accumulators with num_vars=3:
- ~20 Poseidon2 permutations × ~580 constraints each ≈ 11,600
- ~3 EF sumcheck rounds × ~100 constraints each ≈ 300
- Combined eval + OOD/shift ≈ 200
- **Total: ~12,000–16,000 R1CS constraints**

---

## Unified Circuit Sizing

All IVC steps must produce accumulators with the same polynomial size for WARP folding compatibility. The **unified circuit** (`synthesize_unified_ivc_circuit`) embeds both:
1. The user's `StepCircuit`
2. The accumulation verifier

For the first IVC step (no previous accumulation), the circuit pads to the target witness count with trivial constraints (`v * 1 = v`). The target is pre-computed by probing a sample circuit with the verifier.

```rust
// Pre-compute target by building one sample circuit
let target_witness = {
    let mut probe_builder = CircuitBuilder::new();
    // ... synthesize with dummy verifier witness ...
    probe_builder.num_witness_vars()
};

// Init pads to target
ivc_prover.init_unified(..., Some(target_witness), ...);

// Subsequent steps naturally match (verifier present)
ivc_prover.prove_step_recursive(...);
```

---

## Extension Field Arithmetic

`BinomialExtensionField<KoalaBear, 4>` uses irreducible polynomial X⁴ - 11.

### Multiplication (20 R1CS constraints)

```
res[0] = a₀b₀ + 11·(a₁b₃ + a₂b₂ + a₃b₁)
res[1] = a₀b₁ + a₁b₀ + 11·(a₂b₃ + a₃b₂)
res[2] = a₀b₂ + a₁b₁ + a₂b₀ + 11·a₃b₃
res[3] = a₀b₃ + a₁b₂ + a₂b₁ + a₃b₀
```

Implementation: 16 cross-product multiplication constraints (`aᵢ * bⱼ`) + 4 linear combination constraints for the result coefficients.

### Addition/Subtraction (0 R1CS constraints)

Component-wise, handled via `LinearCombination`.

### Scaling by base field (0 R1CS constraints)

`[c·a₀, c·a₁, c·a₂, c·a₃]` via `LinearCombination`.

---

## Standalone Decider

The `AccumulationDecider` verifies the final accumulated instance:

1. **`prove()`**: generates a fresh, standalone WHIR PCS proof for the accumulator (independent of any accumulation transcript)
2. **`verify()`**: checks algebraic satisfaction + WHIR PCS verification

```rust
let decider = AccumulationDecider::new(&whir_config);

// Prover side
let decider_proof = decider.prove(&dft, &mut challenger, &accumulator)?;

// Verifier side
decider.verify(&mut challenger, &accumulator, &decider_proof)?;
```

---

## Compact Accumulator Instance

For IVC, the full `AccumulatorInstance` stores a `LinearStatement` with a 2^m-entry weight table. The `CompactAccumulatorInstance` stores only `(r, y)`:

```rust
struct CompactAccumulatorInstance<F, EF, W, DIGEST_ELEMS> {
    commitment_root: [W; DIGEST_ELEMS],
    evaluation_point: MultilinearPoint<EF>,  // r
    evaluation_value: EF,                     // y = f(r)
}
```

- `expand()` reconstructs the full weight table via `eq(r, ·)`
- `to_field_elements()` flattens for in-circuit hashing

---

## IVC API

### Step Circuit Trait

```rust
pub trait StepCircuit<F: Field> {
    fn state_size(&self) -> usize;
    fn synthesize(
        &self,
        builder: &mut CircuitBuilder<F>,
        input_state: &[Var],
    ) -> Vec<Var>;
}
```

### IVC Flow

```rust
// 1. Initialize
let state0 = ivc_prover.init_unified(
    &step_circuit, &input_state, &mut challenger,
    &poseidon_config, &poseidon_perm, w_param,
    Some(target_witness), public_state,
);

// 2. Non-recursive fold (creates first accumulation proof)
let state1 = ivc_prover.prove_step(
    &dft, &shape, &instance, &mut spartan_chal,
    &mut acc_chal, &state0, new_state,
)?;

// 3. Recursive step (verifies previous accumulation in-circuit)
let state2 = ivc_prover.prove_step_recursive(
    &dft, &step_circuit, &input, &mut spartan_chal,
    &mut acc_chal, &state1, new_state,
    &poseidon_config, &poseidon_perm, w_param,
    &recursive_whir_config,
)?;

// 4. Final verification
let decider = AccumulationDecider::new(&recursive_whir_config);
let proof = decider.prove(&dft, &mut chal, &state.accumulator)?;
decider.verify(&mut chal, &state.accumulator, &proof)?;
```

---

## Test Coverage

| Module | Tests | Notes |
|--------|-------|-------|
| `circuit::builder` | 9 | mul, add, equality, constants, LCs, public inputs, Spartan integration |
| `circuit::poseidon2` | 2 | R1CS satisfaction, constraint count |
| `circuit::ext_field` | 4 | mul/add/scale match actual EF arithmetic, constraint count |
| `circuit::sponge` | 2 | Exact match with `DuplexChallenger` for observe+sample sequences |
| `circuit::bits` | 3 | Decomposition round-trip, index extraction, large values |
| `accumulation::decider` | 3 | Prove+verify, tampered witness rejection, algebraic check |
| `accumulation::compact_instance` | 2 | Expand round-trip, field element serialization |
| `ivc::step` | 1 | Trivial step circuit |
| `ivc::verifier_circuit` | 2 | Standalone recursive circuit verification, sumcheck round |
| `ivc::ivc` | 3 | 2-step IVC, 3-step IVC with decider, recursive step (ignored: slow) |

**Total: 334 passing, 1 ignored** (recursive end-to-end test takes ~90 min due to multiple Spartan proofs of 15-variable circuits).

---

## Known Limitations

1. **Domain separator not replayed in-circuit**: Tests use zero-initialized challengers. Production would need domain separator observation in the `CircuitChallenger`.

2. **Unified circuit padding**: The first IVC step uses trivial padding (`v * 1 = v`) to match the verifier's witness count. This wastes constraints but ensures size compatibility.

3. **Single accumulator stream**: Step and recursive accumulators share one WHIR config via the unified circuit. The alternative (two streams) would avoid padding overhead.

4. **W → F conversion**: Uses `W: Into<F>` bound which works for the common case `W = F` but may need extension for packed field types.

5. **Performance**: The recursive circuit (~16K constraints, 15 polynomial variables) makes Spartan proving slow for tests. Production would use larger step circuits where the overhead is proportionally smaller.
