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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    #[test]
    fn build_union_concatenates_evaluations() {
        let p1 =
            EvaluationsList::new(vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let p2 = EvaluationsList::new(vec![
            F::from_u64(5),
            F::from_u64(6),
            F::from_u64(7),
            F::from_u64(8),
        ]);

        let union = build_union_polynomial(&[p1.clone(), p2.clone()]);

        assert_eq!(union.as_slice().len(), 8);
        assert_eq!(&union.as_slice()[..4], p1.as_slice());
        assert_eq!(&union.as_slice()[4..], p2.as_slice());
    }

    #[test]
    #[should_panic(expected = "Evaluation list length must be a power of two")]
    fn build_union_empty_panics() {
        let _ = build_union_polynomial::<F>(&[]);
    }

    #[test]
    fn build_union_single_poly() {
        let p = EvaluationsList::new(vec![F::ONE, F::from_u64(2)]);
        let union = build_union_polynomial(&[p.clone()]);
        assert_eq!(union.as_slice(), p.as_slice());
    }

    #[test]
    fn build_union_from_refs_matches_owned() {
        let p1 =
            EvaluationsList::new(vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let p2 = EvaluationsList::new(vec![
            F::from_u64(5),
            F::from_u64(6),
            F::from_u64(7),
            F::from_u64(8),
        ]);

        let owned = build_union_polynomial(&[p1.clone(), p2.clone()]);
        let refs = build_union_polynomial_from_refs(&[&p1, &p2]);

        assert_eq!(owned.as_slice(), refs.as_slice());
    }

    #[test]
    #[should_panic(expected = "Evaluation list length must be a power of two")]
    fn build_union_from_refs_empty_panics() {
        let _ = build_union_polynomial_from_refs::<F>(&[]);
    }

    #[test]
    fn build_union_from_refs_single() {
        let p = EvaluationsList::new(vec![F::ONE, F::from_u64(2)]);
        let union = build_union_polynomial_from_refs(&[&p]);
        assert_eq!(union.as_slice(), p.as_slice());
    }

    #[test]
    fn build_union_four_polys() {
        let polys: Vec<_> = (0..4)
            .map(|i| {
                EvaluationsList::new(vec![
                    F::from_u64(i * 4 + 1),
                    F::from_u64(i * 4 + 2),
                    F::from_u64(i * 4 + 3),
                    F::from_u64(i * 4 + 4),
                ])
            })
            .collect();

        let union = build_union_polynomial(&polys);
        assert_eq!(union.as_slice().len(), 16);
        for (i, poly) in polys.iter().enumerate() {
            assert_eq!(&union.as_slice()[i * 4..(i + 1) * 4], poly.as_slice());
        }
    }

    #[test]
    #[should_panic(expected = "All polynomials must have the same number of variables")]
    fn build_union_mismatched_sizes_panics() {
        let p1 = EvaluationsList::new(vec![F::ONE, F::from_u64(2)]);
        let p2 =
            EvaluationsList::new(vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let _ = build_union_polynomial(&[p1, p2]);
    }

    #[test]
    #[should_panic(expected = "All polynomials must have the same number of variables")]
    fn build_union_from_refs_mismatched_sizes_panics() {
        let p1 = EvaluationsList::new(vec![F::ONE, F::from_u64(2)]);
        let p2 =
            EvaluationsList::new(vec![F::ONE, F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let _ = build_union_polynomial_from_refs(&[&p1, &p2]);
    }
}
