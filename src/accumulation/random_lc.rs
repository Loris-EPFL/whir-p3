use alloc::vec;

use p3_field::Field;

use crate::poly::evals::EvaluationsList;

/// Computes `f = Σᵢ γⁱ fᵢ` — a random linear combination of same-size polynomials.
///
/// Unlike union polynomial concatenation (which produces a polynomial of size `ℓ·n`),
/// this produces a polynomial of the **same size** `n` as each input.
/// This enables unbounded-depth accumulation because the witness size stays constant.
pub fn random_linear_combination<F: Field>(
    polys: &[&EvaluationsList<F>],
    gamma: F,
) -> EvaluationsList<F> {
    assert!(!polys.is_empty(), "need at least one polynomial");
    let n = polys[0].num_evals();
    for p in polys {
        assert_eq!(
            p.num_evals(),
            n,
            "all polynomials must have the same number of evaluations"
        );
    }

    let mut result = vec![F::ZERO; n];
    let mut coeff = F::ONE;
    for poly in polys {
        for (r, &v) in result.iter_mut().zip(poly.as_slice().iter()) {
            *r += coeff * v;
        }
        coeff *= gamma;
    }
    EvaluationsList::new(result)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    type F = BabyBear;

    #[test]
    fn single_poly_is_identity() {
        let p = EvaluationsList::new(vec![F::from_u64(1), F::from_u64(2)]);
        let result = random_linear_combination(&[&p], F::from_u64(7));
        assert_eq!(result.as_slice(), p.as_slice());
    }

    #[test]
    fn two_polys_combined_correctly() {
        let p0 = EvaluationsList::new(vec![F::from_u64(1), F::from_u64(2)]);
        let p1 = EvaluationsList::new(vec![F::from_u64(10), F::from_u64(20)]);
        let gamma = F::from_u64(3);
        // f = p0 + 3*p1 = [1+30, 2+60] = [31, 62]
        let result = random_linear_combination(&[&p0, &p1], gamma);
        assert_eq!(result.as_slice()[0], F::from_u64(31));
        assert_eq!(result.as_slice()[1], F::from_u64(62));
    }

    #[test]
    fn four_polys_uses_gamma_powers() {
        let polys: Vec<EvaluationsList<F>> = (0..4)
            .map(|i| EvaluationsList::new(vec![F::from_u64(i + 1)]))
            .collect();
        let refs: Vec<&EvaluationsList<F>> = polys.iter().collect();
        let gamma = F::from_u64(2);
        // f = 1 + 2*2 + 3*4 + 4*8 = 1 + 4 + 12 + 32 = 49
        let result = random_linear_combination(&refs, gamma);
        assert_eq!(result.as_slice()[0], F::from_u64(49));
    }
}
