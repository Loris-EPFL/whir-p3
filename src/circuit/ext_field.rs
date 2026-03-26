//! Extension field arithmetic as R1CS constraints.
//!
//! Implements `BinomialExtensionField<F, D>` operations (with D=4 and irreducible X⁴ - W)
//! as R1CS constraints. Element representation: `[a₀, a₁, a₂, a₃]` for `a₀ + a₁·X + a₂·X² + a₃·X³`.
//!
//! Multiplication uses the quartic formula (17 base field muls per EF mul).
//! Addition/subtraction are linear and cost zero constraints.

use p3_field::Field;

use super::builder::{CircuitBuilder, LinearCombination, Var};

/// An extension field element in the circuit, represented as D base field variables.
#[derive(Clone, Copy, Debug)]
pub struct ExtVar<const D: usize> {
    pub vars: [Var; D],
}

/// An extension field element's concrete values (prover-side).
#[derive(Clone, Copy, Debug)]
pub struct ExtVal<F: Field, const D: usize> {
    pub vals: [F; D],
}

impl<F: Field, const D: usize> ExtVal<F, D> {
    pub const fn new(vals: [F; D]) -> Self {
        Self { vals }
    }
}

impl<const D: usize> ExtVar<D> {
    pub const fn new(vars: [Var; D]) -> Self {
        Self { vars }
    }
}

/// Allocate an extension field element as D witness variables.
pub fn alloc_ext<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F>,
    vals: &ExtVal<F, D>,
) -> ExtVar<D> {
    ExtVar {
        vars: core::array::from_fn(|i| builder.alloc_witness(vals.vals[i])),
    }
}

/// Constrain `a + b = c` for extension field elements (free in R1CS — linear).
pub fn enforce_ext_add<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F>,
    a: &ExtVar<D>,
    b: &ExtVar<D>,
    c: &ExtVar<D>,
) {
    for i in 0..D {
        builder.enforce(
            LinearCombination::from_var(a.vars[i]) + LinearCombination::from_var(b.vars[i]),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(c.vars[i]),
        );
    }
}

/// Multiply two extension field elements in F[X]/(X⁴ - W) and constrain the result.
///
/// For D=4 with irreducible polynomial X⁴ - W:
/// ```text
/// res[0] = a₀·b₀ + W·(a₁·b₃ + a₂·b₂ + a₃·b₁)
/// res[1] = a₀·b₁ + a₁·b₀ + W·(a₂·b₃ + a₃·b₂)
/// res[2] = a₀·b₂ + a₁·b₁ + a₂·b₀ + W·a₃·b₃
/// res[3] = a₀·b₃ + a₁·b₂ + a₂·b₁ + a₃·b₀
/// ```
///
/// Returns the output `ExtVar` and `ExtVal`.
pub fn ext_mul<F: Field>(
    builder: &mut CircuitBuilder<F>,
    a: &ExtVar<4>,
    a_val: &ExtVal<F, 4>,
    b: &ExtVar<4>,
    b_val: &ExtVal<F, 4>,
    w: F,
) -> (ExtVar<4>, ExtVal<F, 4>) {
    let av = a_val.vals;
    let bv = b_val.vals;

    // Compute all needed cross-products as witness variables
    // a_i * b_j for the needed pairs
    let mut cross = [[Var(0); 4]; 4];
    let mut cross_val = [[F::ZERO; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            let val = av[i] * bv[j];
            cross_val[i][j] = val;
            cross[i][j] = builder.mul(a.vars[i], b.vars[j], val);
        }
    }

    // Compute result coefficients as linear combinations of cross-products
    let res0_val = cross_val[0][0] + w * (cross_val[1][3] + cross_val[2][2] + cross_val[3][1]);
    let res1_val = cross_val[0][1] + cross_val[1][0] + w * (cross_val[2][3] + cross_val[3][2]);
    let res2_val = cross_val[0][2] + cross_val[1][1] + cross_val[2][0] + w * cross_val[3][3];
    let res3_val = cross_val[0][3] + cross_val[1][2] + cross_val[2][1] + cross_val[3][0];

    let out_vals = ExtVal::new([res0_val, res1_val, res2_val, res3_val]);

    // Allocate output variables
    let out = alloc_ext(builder, &out_vals);

    // Constrain each output coefficient as a linear combination of cross-products
    // res[0] = cross[0][0] + W*(cross[1][3] + cross[2][2] + cross[3][1])
    let mut lc0 = LinearCombination::from_var(cross[0][0]);
    lc0.add_term(cross[1][3], w);
    lc0.add_term(cross[2][2], w);
    lc0.add_term(cross[3][1], w);
    builder.enforce(
        lc0,
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(out.vars[0]),
    );

    // res[1] = cross[0][1] + cross[1][0] + W*(cross[2][3] + cross[3][2])
    let mut lc1 = LinearCombination::from_var(cross[0][1]);
    lc1.add_term(cross[1][0], F::ONE);
    lc1.add_term(cross[2][3], w);
    lc1.add_term(cross[3][2], w);
    builder.enforce(
        lc1,
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(out.vars[1]),
    );

    // res[2] = cross[0][2] + cross[1][1] + cross[2][0] + W*cross[3][3]
    let mut lc2 = LinearCombination::from_var(cross[0][2]);
    lc2.add_term(cross[1][1], F::ONE);
    lc2.add_term(cross[2][0], F::ONE);
    lc2.add_term(cross[3][3], w);
    builder.enforce(
        lc2,
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(out.vars[2]),
    );

    // res[3] = cross[0][3] + cross[1][2] + cross[2][1] + cross[3][0]
    let mut lc3 = LinearCombination::from_var(cross[0][3]);
    lc3.add_term(cross[1][2], F::ONE);
    lc3.add_term(cross[2][1], F::ONE);
    lc3.add_term(cross[3][0], F::ONE);
    builder.enforce(
        lc3,
        LinearCombination::from_constant(F::ONE),
        LinearCombination::from_var(out.vars[3]),
    );

    (out, out_vals)
}

/// Multiply an extension field element by a base field scalar.
///
/// This is free (linear combination): `[c·a₀, c·a₁, c·a₂, c·a₃]`.
pub fn ext_scale<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F>,
    a: &ExtVar<D>,
    a_val: &ExtVal<F, D>,
    scalar: F,
) -> (ExtVar<D>, ExtVal<F, D>) {
    let out_vals = ExtVal::new(core::array::from_fn(|i| a_val.vals[i] * scalar));
    let out = alloc_ext(builder, &out_vals);
    for i in 0..D {
        builder.enforce(
            LinearCombination::from_scaled(a.vars[i], scalar),
            LinearCombination::from_constant(F::ONE),
            LinearCombination::from_var(out.vars[i]),
        );
    }
    (out, out_vals)
}

/// Add two extension field elements and constrain the result.
pub fn ext_add<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F>,
    a: &ExtVar<D>,
    a_val: &ExtVal<F, D>,
    b: &ExtVar<D>,
    b_val: &ExtVal<F, D>,
) -> (ExtVar<D>, ExtVal<F, D>) {
    let out_vals = ExtVal::new(core::array::from_fn(|i| a_val.vals[i] + b_val.vals[i]));
    let out = alloc_ext(builder, &out_vals);
    enforce_ext_add(builder, a, b, &out);
    (out, out_vals)
}

/// Lift a base field element to extension field: `[f, 0, 0, 0]`.
pub fn ext_from_base<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F>,
    var: Var,
    val: F,
) -> (ExtVar<D>, ExtVal<F, D>) {
    let mut vals = [F::ZERO; D];
    vals[0] = val;
    let out_vals = ExtVal::new(vals);
    let mut vars = core::array::from_fn(|_| builder.alloc_witness(F::ZERO));
    vars[0] = var;
    // Constrain that vars[0] == var (already the same variable)
    // and vars[1..D] == 0 (already constrained by allocating as zero)
    // Actually we need explicit constraints for the zeros
    for i in 1..D {
        builder.enforce_constant(vars[i], F::ZERO);
    }
    (ExtVar::new(vars), out_vals)
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, extension::BinomialExtensionField};

    use super::*;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;

    fn ef_from_fn(f: impl Fn(usize) -> F) -> EF {
        EF::from_basis_coefficients_fn(f)
    }

    fn to_arr(ef: &EF) -> [F; 4] {
        let s = ef.as_basis_coefficients_slice();
        [s[0], s[1], s[2], s[3]]
    }

    #[test]
    fn ext_mul_matches_field_mul() {
        let a_ef = ef_from_fn(|i| F::from_u64(i as u64 + 1));
        let b_ef = ef_from_fn(|i| F::from_u64(i as u64 + 5));
        let expected = a_ef * b_ef;

        let mut builder = CircuitBuilder::<F>::new();
        let a_val = ExtVal::new(to_arr(&a_ef));
        let b_val = ExtVal::new(to_arr(&b_ef));
        let a_var = alloc_ext(&mut builder, &a_val);
        let b_var = alloc_ext(&mut builder, &b_val);

        // W = 11 for BabyBear degree-4 extension
        let w = F::from_u64(11);
        let (_, result_val) = ext_mul(&mut builder, &a_var, &a_val, &b_var, &b_val, w);

        assert_eq!(result_val.vals, to_arr(&expected), "EF mul values mismatch");

        let (_, instance) = builder.build();
        assert!(instance.verify(), "EF mul R1CS not satisfied");
    }

    #[test]
    fn ext_add_matches_field_add() {
        let a_ef = ef_from_fn(|i| F::from_u64(i as u64 + 1));
        let b_ef = ef_from_fn(|i| F::from_u64(i as u64 + 5));
        let expected = a_ef + b_ef;

        let mut builder = CircuitBuilder::<F>::new();
        let a_val = ExtVal::new(to_arr(&a_ef));
        let b_val = ExtVal::new(to_arr(&b_ef));
        let a_var = alloc_ext(&mut builder, &a_val);
        let b_var = alloc_ext(&mut builder, &b_val);

        let (_, result_val) = ext_add(&mut builder, &a_var, &a_val, &b_var, &b_val);

        assert_eq!(result_val.vals, to_arr(&expected));

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }

    #[test]
    fn ext_scale_matches_field_scale() {
        let a_ef = ef_from_fn(|i| F::from_u64(i as u64 + 1));
        let scalar = F::from_u64(7);
        let expected = a_ef * EF::from(scalar);

        let mut builder = CircuitBuilder::<F>::new();
        let a_val = ExtVal::new(to_arr(&a_ef));
        let a_var = alloc_ext(&mut builder, &a_val);

        let (_, result_val) = ext_scale(&mut builder, &a_var, &a_val, scalar);

        assert_eq!(result_val.vals, to_arr(&expected));

        let (_, instance) = builder.build();
        assert!(instance.verify());
    }

    #[test]
    fn ext_mul_constraint_count() {
        let mut builder = CircuitBuilder::<F>::new();
        let a_val = ExtVal::new([F::from_u64(1); 4]);
        let b_val = ExtVal::new([F::from_u64(2); 4]);
        let a_var = alloc_ext(&mut builder, &a_val);
        let b_var = alloc_ext(&mut builder, &b_val);

        let w = F::from_u64(11);
        let _ = ext_mul(&mut builder, &a_var, &a_val, &b_var, &b_val, w);

        // 16 cross-product muls + 4 output constraints = 20
        assert_eq!(builder.num_constraints(), 20);
    }
}
