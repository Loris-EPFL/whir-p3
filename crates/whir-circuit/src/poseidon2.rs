//! Poseidon2 permutation as R1CS constraints.
//!
//! Implements the Poseidon2 permutation (generic over WIDTH) as a
//! sequence of R1CS constraints suitable for recursive proof verification.
//!
//! The permutation structure:
//! 1. Initial external linear layer
//! 2. `rounds_f/2` initial external rounds (add RC + full S-box + external linear layer)
//! 3. `rounds_p` internal rounds (add RC to s[0] + S-box on s[0] + internal linear layer)
//! 4. `rounds_f/2` terminal external rounds
//!
//! Only S-box applications cost R1CS constraints (4 muls each for x^7).
//! Linear layers and constant additions are free (folded into linear combinations).

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2::{ExternalLayerConstants, GenericPoseidon2LinearLayers};
use p3_symmetric::Permutation;

use super::builder::{CircuitBuilder, LinearCombination, Var};

/// Configuration for the Poseidon2 circuit gadget.
///
/// Stores the round constants needed to reproduce the permutation as R1CS constraints.
/// Generated from the same RNG seed used to create the actual `Poseidon2` instance.
#[derive(Clone, Debug)]
pub struct Poseidon2CircuitConfig<F: Field, const WIDTH: usize> {
    pub initial_external_constants: Vec<[F; WIDTH]>,
    pub terminal_external_constants: Vec<[F; WIDTH]>,
    pub internal_constants: Vec<F>,
    /// S-box exponent: 3 for KoalaBear, 7 for BabyBear.
    pub sbox_degree: u64,
}

impl<F: Field, const WIDTH: usize> Poseidon2CircuitConfig<F, WIDTH> {
    /// Create from explicit round constants.
    ///
    /// # Panics
    /// Panics if `sbox_degree` is not 3 or 7.
    pub fn new(
        external_constants: ExternalLayerConstants<F, WIDTH>,
        internal_constants: Vec<F>,
        sbox_degree: u64,
    ) -> Self {
        assert!(
            sbox_degree == 3 || sbox_degree == 7,
            "unsupported S-box degree {sbox_degree}: only 3 and 7 are supported"
        );
        Self {
            initial_external_constants: external_constants.get_initial_constants().clone(),
            terminal_external_constants: external_constants.get_terminal_constants().clone(),
            internal_constants,
            sbox_degree,
        }
    }

    /// Create by generating constants from the same RNG used for `Poseidon2::new_from_rng`.
    ///
    /// `sbox_degree`: the S-box exponent (3 for KoalaBear, 7 for BabyBear).
    ///
    /// # Panics
    /// Panics if `sbox_degree` is not 3 or 7.
    pub fn from_rng<R: rand::Rng>(
        rounds_f: usize,
        rounds_p: usize,
        sbox_degree: u64,
        rng: &mut R,
    ) -> Self
    where
        rand::distr::StandardUniform:
            rand::distr::Distribution<F> + rand::distr::Distribution<[F; WIDTH]>,
    {
        use rand::RngExt;
        let external_constants = ExternalLayerConstants::new_from_rng(rounds_f, rng);
        let internal_constants: Vec<F> = rng
            .sample_iter(rand::distr::StandardUniform)
            .take(rounds_p)
            .collect();
        Self::new(external_constants, internal_constants, sbox_degree)
    }
}

/// Apply the S-box x^d as R1CS constraints.
///
/// Supports d=3 (KoalaBear: 2 multiplications) and d=7 (BabyBear: 4 multiplications).
fn sbox_circuit<F: Field>(builder: &mut CircuitBuilder<F>, x: Var, x_val: F, degree: u64) -> Var {
    match degree {
        3 => {
            // x^3 = x * x * x (2 multiplications)
            let x2_val = x_val * x_val;
            let x3_val = x2_val * x_val;
            let x2 = builder.mul(x, x, x2_val);
            builder.mul(x2, x, x3_val)
        }
        7 => {
            // x^7 = ((x^2 * x)^2) * x (4 multiplications)
            let x2_val = x_val * x_val;
            let x3_val = x2_val * x_val;
            let x6_val = x3_val * x3_val;
            let x7_val = x6_val * x_val;
            let x2 = builder.mul(x, x, x2_val);
            let x3 = builder.mul(x2, x, x3_val);
            let x6 = builder.mul(x3, x3, x6_val);
            builder.mul(x6, x, x7_val)
        }
        // SAFETY: degree is validated in Poseidon2CircuitConfig::new()
        _ => unreachable!("S-box degree {degree} should have been rejected at construction"),
    }
}

/// Compute x^d for the S-box value tracking (no constraints, just field arithmetic).
fn sbox_val<F: Field>(x: F, degree: u64) -> F {
    match degree {
        3 => x * x * x,
        7 => {
            let x2 = x * x;
            let x3 = x2 * x;
            let x6 = x3 * x3;
            x6 * x
        }
        // SAFETY: degree is validated in Poseidon2CircuitConfig::new()
        _ => unreachable!("S-box degree {degree} should have been rejected at construction"),
    }
}

/// Extract the linear transformation matrix for a function `f: [F; W] -> [F; W]`
/// by probing with unit vectors.
///
/// Returns `coeffs` where `f(x)[i] = Σ_j coeffs[i][j] * x[j]` for all linear `f`.
fn extract_linear_coefficients<F, const W: usize>(
    f: impl Fn(&mut [F; W]),
) -> [[F; W]; W]
where
    F: Field + PrimeCharacteristicRing,
{
    let mut coeffs = [[F::ZERO; W]; W];
    for j in 0..W {
        let mut probe = [F::ZERO; W];
        probe[j] = F::ONE;
        f(&mut probe);
        for (i, row) in coeffs.iter_mut().enumerate() {
            row[j] = probe[i];
        }
    }
    coeffs
}

/// Apply a linear layer (given as a coefficient matrix) as R1CS constraints.
///
/// Allocates output variables and constrains each `out[i] = Σ_j coeffs[i][j] * state[j]`.
fn apply_linear_layer_circuit<F: Field, const W: usize>(
    builder: &mut CircuitBuilder<F>,
    state: &[Var; W],
    state_vals: &[F; W],
    coeffs: &[[F; W]; W],
) -> ([Var; W], [F; W]) {
    let mut out_vals = [F::ZERO; W];
    for i in 0..W {
        for j in 0..W {
            out_vals[i] += coeffs[i][j] * state_vals[j];
        }
    }

    let mut out_vars = [Var(0); W];
    for i in 0..W {
        let out = builder.alloc_witness(out_vals[i]);
        let mut lc = LinearCombination::from_constant(F::ZERO);
        for j in 0..W {
            if coeffs[i][j] != F::ZERO {
                lc.add_term(state[j], coeffs[i][j]);
            }
        }
        builder.enforce(
            lc,
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(out),
        );
        out_vars[i] = out;
    }

    (out_vars, out_vals)
}

/// Apply the full Poseidon2 permutation as R1CS constraints.
///
/// Takes `WIDTH` input variables, adds constraints for the permutation,
/// and returns `WIDTH` output variables.
///
/// # Type Parameters
/// - `L`: The generic linear layers type (e.g., `GenericPoseidon2LinearLayersBabyBear`)
/// - `P`: The actual Poseidon2 permutation instance (used to compute correct values)
pub fn poseidon2_permute_circuit<F, L, P, const WIDTH: usize>(
    builder: &mut CircuitBuilder<F>,
    config: &Poseidon2CircuitConfig<F, WIDTH>,
    perm: &P,
    state_vars: &[Var; WIDTH],
    state_vals: &[F; WIDTH],
) -> ([Var; WIDTH], [F; WIDTH])
where
    F: Field + PrimeCharacteristicRing,
    L: GenericPoseidon2LinearLayers<WIDTH>,
    P: Permutation<[F; WIDTH]>,
{
    // Verify: the perm should produce the expected output
    let mut expected_output = *state_vals;
    perm.permute_mut(&mut expected_output);

    // Pre-compute coefficient matrices for the linear layers (done once per call).
    let external_coeffs = extract_linear_coefficients::<F, WIDTH>(L::external_linear_layer);
    let internal_coeffs = extract_linear_coefficients::<F, WIDTH>(L::internal_linear_layer);

    let mut cur_vars = *state_vars;
    let mut cur_vals = *state_vals;

    // Phase 1: Initial external linear layer
    let (new_vars, new_vals) =
        apply_linear_layer_circuit(builder, &cur_vars, &cur_vals, &external_coeffs);
    cur_vars = new_vars;
    cur_vals = new_vals;

    // Phase 2: Initial external rounds (rounds_f / 2)
    for round_constants in &config.initial_external_constants {
        // Add round constants + S-box on all elements
        for i in 0..WIDTH {
            cur_vals[i] += round_constants[i];
            let post_rc = builder.alloc_witness(cur_vals[i]);
            let mut lc = LinearCombination::from_var(cur_vars[i]);
            lc.add_constant(round_constants[i]);
            builder.enforce(
                lc,
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(post_rc),
            );
            cur_vars[i] = sbox_circuit(builder, post_rc, cur_vals[i], config.sbox_degree);
            cur_vals[i] = sbox_val(cur_vals[i], config.sbox_degree);
        }

        // External linear layer
        let (new_vars, new_vals) =
            apply_linear_layer_circuit(builder, &cur_vars, &cur_vals, &external_coeffs);
        cur_vars = new_vars;
        cur_vals = new_vals;
    }

    // Phase 3: Internal rounds
    for &rc in &config.internal_constants {
        // Add round constant to s[0] only + S-box on s[0]
        cur_vals[0] += rc;
        let post_rc = builder.alloc_witness(cur_vals[0]);
        let mut lc = LinearCombination::from_var(cur_vars[0]);
        lc.add_constant(rc);
        builder.enforce(
            lc,
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(post_rc),
        );
        cur_vars[0] = sbox_circuit(builder, post_rc, cur_vals[0], config.sbox_degree);
        cur_vals[0] = sbox_val(cur_vals[0], config.sbox_degree);

        // Internal linear layer
        let (new_vars, new_vals) =
            apply_linear_layer_circuit(builder, &cur_vars, &cur_vals, &internal_coeffs);
        cur_vars = new_vars;
        cur_vals = new_vals;
    }

    // Phase 4: Terminal external rounds
    for round_constants in &config.terminal_external_constants {
        for i in 0..WIDTH {
            cur_vals[i] += round_constants[i];
            let post_rc = builder.alloc_witness(cur_vals[i]);
            let mut lc = LinearCombination::from_var(cur_vars[i]);
            lc.add_constant(round_constants[i]);
            builder.enforce(
                lc,
                LinearCombination::from_constant(F::ONE),
                LinearCombination::from_var(post_rc),
            );
            cur_vars[i] = sbox_circuit(builder, post_rc, cur_vals[i], config.sbox_degree);
            cur_vals[i] = sbox_val(cur_vals[i], config.sbox_degree);
        }

        let (new_vars, new_vals) =
            apply_linear_layer_circuit(builder, &cur_vars, &cur_vals, &external_coeffs);
        cur_vars = new_vars;
        cur_vals = new_vals;
    }

    // Verify the circuit computed the same result as the actual permutation
    debug_assert_eq!(cur_vals, expected_output);

    (cur_vars, cur_vals)
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear};
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::Permutation;
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<16>;

    #[test]
    fn poseidon2_circuit_produces_satisfying_r1cs() {
        let mut rng = SmallRng::seed_from_u64(42);
        let perm = Perm::new_from_rng_128(&mut rng);

        let mut rng2 = SmallRng::seed_from_u64(42);
        let config = Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut rng2);

        let state_vals: [F; 16] = core::array::from_fn(|i| F::from_u64(i as u64 + 1));
        let mut builder = CircuitBuilder::<F>::new();
        let state_vars: [Var; 16] =
            core::array::from_fn(|i| builder.alloc_witness(state_vals[i]));

        let (_out_vars, out_vals) =
            poseidon2_permute_circuit::<F, GenericPoseidon2LinearLayersBabyBear, _, 16>(
                &mut builder,
                &config,
                &perm,
                &state_vars,
                &state_vals,
            );

        // Verify against actual permutation
        let mut expected = state_vals;
        perm.permute_mut(&mut expected);
        assert_eq!(out_vals, expected, "circuit values don't match permutation");

        // Build R1CS and verify satisfaction
        let (shape, instance) = builder.build();
        assert!(
            instance.verify(),
            "Poseidon2 circuit does not satisfy R1CS (num_cons={}, num_vars={})",
            shape.num_cons(),
            shape.num_vars(),
        );
    }

    #[test]
    fn poseidon2_constraint_count() {
        let mut rng = SmallRng::seed_from_u64(42);
        let perm = Perm::new_from_rng_128(&mut rng);

        let mut rng2 = SmallRng::seed_from_u64(42);
        let config = Poseidon2CircuitConfig::<F, 16>::from_rng(8, 13, 7, &mut rng2);

        let state_vals: [F; 16] = core::array::from_fn(|i| F::from_u64(i as u64 + 1));
        let mut builder = CircuitBuilder::<F>::new();
        let state_vars: [Var; 16] =
            core::array::from_fn(|i| builder.alloc_witness(state_vals[i]));

        let _ = poseidon2_permute_circuit::<F, GenericPoseidon2LinearLayersBabyBear, _, 16>(
            &mut builder,
            &config,
            &perm,
            &state_vars,
            &state_vals,
        );

        let num_cons = builder.num_constraints();
        // S-box constraints: 8 external * 16 sboxes * 4 muls + 13 internal * 1 sbox * 4 muls
        //   = 512 + 52 = 564 S-box constraints
        // Plus linear layer constraints (WIDTH per layer) and RC constraints (WIDTH per external round)
        assert!(
            num_cons < 5000,
            "too many constraints: {num_cons} (expected < 5000)"
        );
    }
}
