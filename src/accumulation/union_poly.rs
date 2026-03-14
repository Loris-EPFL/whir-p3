use alloc::{vec, vec::Vec};

use crate::poly::evals::EvaluationsList;
use p3_field::Field;

/// Implements the union polynomial via jagged concatenation.
///
/// Converts `l` multilinear polynomials of size `n` into a single multilinear
/// polynomial of size `l * n`. The new polynomial effectively maps the boolean
/// hypercube selector `eq(Bits(k), Y)` to the `k`-th original polynomial.
pub fn build_union_polynomial<F: Field>(polynomials: &[EvaluationsList<F>]) -> EvaluationsList<F> {
    if polynomials.is_empty() {
        return EvaluationsList::new(vec![]);
    }

    let n = polynomials[0].num_variables();
    let l = polynomials.len();

    // Ensure all polynomials have the same size (padding to a power of 2 is expected
    // prior to this function if jagged polynomials are used).
    for poly in polynomials {
        assert_eq!(
            poly.num_variables(),
            n,
            "All polynomials must have the same number of variables"
        );
    }

    // In memory, the union polynomial is just a contiguous concatenation of all evaluations.
    let mut union_evals = Vec::with_capacity(l * (1 << n));
    for poly in polynomials {
        union_evals.extend_from_slice(poly.as_slice());
    }

    EvaluationsList::new(union_evals)
}

/// Builds a union polynomial from borrowed evaluation tables without cloning inputs first.
pub fn build_union_polynomial_from_refs<F: Field>(
    polynomials: &[&EvaluationsList<F>],
) -> EvaluationsList<F> {
    if polynomials.is_empty() {
        return EvaluationsList::new(vec![]);
    }

    let n = polynomials[0].num_variables();
    let l = polynomials.len();

    for poly in polynomials {
        assert_eq!(
            poly.num_variables(),
            n,
            "All polynomials must have the same number of variables"
        );
    }

    let mut union_evals = Vec::with_capacity(l * (1 << n));
    for poly in polynomials {
        union_evals.extend_from_slice(poly.as_slice());
    }

    EvaluationsList::new(union_evals)
}
