//! ProtoGalaxy-style binary fold primitive.
//!
//! This implements the core folding operation used inside WARP's twin-constraint
//! sumcheck. Given 2^k univariate polynomials, the fold reduces them to a single
//! polynomial via k rounds of pairwise combination using verifier challenges.
//!
//! At each level, pairs (p_0, p_1) are combined as:
//!   p_0 + (a + b·X) · (p_1 - p_0)
//!
//! where (a, b) are the linear interpolation coefficients derived from the
//! sumcheck challenge at that level. This is the Lagrange-basis fold from
//! ProtoGalaxy (Eagen-Gabizon 2024), specialized to the binary hypercube {0,1}.
//!
//! Reference: compsec-epfl/efficient-sumcheck folding::protogalaxy

use alloc::{vec, vec::Vec};
use p3_field::Field;

/// A univariate polynomial in coefficient form: coeffs[i] is the coefficient of X^i.
#[derive(Clone, Debug, PartialEq)]
pub struct UnivariatePoly<F> {
    pub coeffs: Vec<F>,
}

impl<F: Field> UnivariatePoly<F> {
    pub fn zero() -> Self {
        Self {
            coeffs: Vec::new(),
        }
    }

    pub fn constant(c: F) -> Self {
        if c.is_zero() {
            Self::zero()
        } else {
            Self { coeffs: vec![c] }
        }
    }

    pub fn from_coeffs(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }

    /// Degree of the polynomial (-1 for the zero polynomial).
    pub fn degree(&self) -> Option<usize> {
        self.coeffs
            .iter()
            .rposition(|c| !c.is_zero())
    }

    /// Evaluate at a point using Horner's method.
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs
            .iter()
            .rfold(F::ZERO, |acc, &c| acc * x + c)
    }

    /// Multiply by (a + b·X), producing a polynomial of degree one higher.
    pub fn mul_linear(&self, a: F, b: F) -> Self {
        if self.coeffs.is_empty() {
            return Self::zero();
        }
        let n = self.coeffs.len();
        let mut result = vec![F::ZERO; n + 1];
        for (i, &c) in self.coeffs.iter().enumerate() {
            result[i] += a * c;
            result[i + 1] += b * c;
        }
        Self { coeffs: result }
    }

    /// Add two polynomials.
    pub fn add(&self, other: &Self) -> Self {
        let len = self.coeffs.len().max(other.coeffs.len());
        let mut coeffs = vec![F::ZERO; len];
        for (i, &c) in self.coeffs.iter().enumerate() {
            coeffs[i] += c;
        }
        for (i, &c) in other.coeffs.iter().enumerate() {
            coeffs[i] += c;
        }
        Self { coeffs }
    }

    /// Subtract: self - other.
    pub fn sub(&self, other: &Self) -> Self {
        let len = self.coeffs.len().max(other.coeffs.len());
        let mut coeffs = vec![F::ZERO; len];
        for (i, &c) in self.coeffs.iter().enumerate() {
            coeffs[i] += c;
        }
        for (i, &c) in other.coeffs.iter().enumerate() {
            coeffs[i] -= c;
        }
        Self { coeffs }
    }

    /// Pad coefficients to exactly `n` elements (truncates trailing zeros or extends).
    pub fn pad_to(&mut self, n: usize) {
        self.coeffs.resize(n, F::ZERO);
    }

    /// Scale all coefficients by a scalar.
    pub fn scale(&self, s: F) -> Self {
        Self {
            coeffs: self.coeffs.iter().map(|&c| c * s).collect(),
        }
    }

    /// Naive polynomial multiplication (schoolbook).
    pub fn naive_mul(&self, other: &Self) -> Self {
        if self.coeffs.is_empty() || other.coeffs.is_empty() {
            return Self::zero();
        }
        let n = self.coeffs.len() + other.coeffs.len() - 1;
        let mut result = vec![F::ZERO; n];
        for (i, &a) in self.coeffs.iter().enumerate() {
            for (j, &b) in other.coeffs.iter().enumerate() {
                result[i + j] += a * b;
            }
        }
        Self { coeffs: result }
    }
}

/// ProtoGalaxy binary fold: reduces 2^k polynomials to 1 via k rounds.
///
/// `coeffs` provides one (a, b) pair per round (k pairs total).
/// `polys` must have length 2^k.
///
/// At each round, pairs of polynomials (p_0, p_1) are combined as:
///   p_0 + (a + b·X) · (p_1 - p_0)
///
/// This is the ProtoGalaxy Lagrange-basis fold over {0,1}:
/// - At X=0: result = p_0 + a·(p_1 - p_0) = (1-a)·p_0 + a·p_1
/// - At X=1: result = p_0 + (a+b)·(p_1 - p_0) = (1-a-b)·p_0 + (a+b)·p_1
pub fn fold<F: Field>(
    coeffs: impl Iterator<Item = (F, F)>,
    mut polys: Vec<UnivariatePoly<F>>,
) -> UnivariatePoly<F> {
    for (a, b) in coeffs {
        assert!(
            polys.len() % 2 == 0 || polys.len() == 1,
            "number of polynomials must be even at each fold level"
        );
        polys = polys
            .chunks(2)
            .map(|pair| {
                let diff = pair[1].sub(&pair[0]);
                let scaled = diff.mul_linear(a, b);
                pair[0].add(&scaled)
            })
            .collect();
    }
    assert_eq!(polys.len(), 1, "fold must reduce to exactly 1 polynomial");
    polys.pop().unwrap()
}

/// Convenience: fold constant polynomials (degree-0) — used for folding scalar tables.
///
/// Given 2^k scalars and k challenge pairs, returns the folded scalar.
pub fn fold_scalars<F: Field>(
    coeffs: impl Iterator<Item = (F, F)>,
    scalars: &[F],
) -> F {
    let polys: Vec<UnivariatePoly<F>> = scalars
        .iter()
        .map(|&s| UnivariatePoly::constant(s))
        .collect();
    let result = fold(coeffs, polys);
    result.evaluate(F::ZERO) // constant polynomial, any point works
}

/// Convenience: fold degree-1 polynomials defined by (lo, hi) pairs.
///
/// Each entry defines p_i(X) = lo + (hi - lo)·X (linear interpolation of two values).
/// This is the typical case in the twin-constraint sumcheck where we interpolate
/// between the values at the two accumulator inputs.
pub fn fold_linear<F: Field>(
    coeffs: impl Iterator<Item = (F, F)>,
    lo_hi_pairs: &[(F, F)],
) -> UnivariatePoly<F> {
    let polys: Vec<UnivariatePoly<F>> = lo_hi_pairs
        .iter()
        .map(|&(lo, hi)| UnivariatePoly::from_coeffs(vec![lo, hi - lo]))
        .collect();
    fold(coeffs, polys)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    type F = BabyBear;

    #[test]
    fn fold_two_constant_polys() {
        // p0 = 3, p1 = 7, (a, b) = (1, 0)
        // result = p0 + (1 + 0·X)·(p1 - p0) = p0 + (p1 - p0) = p1 = 7
        let p0 = UnivariatePoly::constant(F::from_u64(3));
        let p1 = UnivariatePoly::constant(F::from_u64(7));
        let result = fold(vec![(F::ONE, F::ZERO)].into_iter(), vec![p0, p1]);
        assert_eq!(result.evaluate(F::ZERO), F::from_u64(7));
    }

    #[test]
    fn fold_two_linear_polys() {
        // p0 = 1, p1 = X, (a, b) = (3, 5)
        // result = 1 + (3 + 5X)(X - 1) = 1 + 3X - 3 + 5X^2 - 5X = -2 - 2X + 5X^2
        let p0 = UnivariatePoly::from_coeffs(vec![F::ONE]);
        let p1 = UnivariatePoly::from_coeffs(vec![F::ZERO, F::ONE]);
        let a = F::from_u64(3);
        let b = F::from_u64(5);
        let result = fold(vec![(a, b)].into_iter(), vec![p0, p1]);

        assert_eq!(result.coeffs.len(), 3);
        assert_eq!(result.coeffs[0], F::ONE - a); // 1 - 3 = -2
        assert_eq!(result.coeffs[1], a - b); // 3 - 5 = -2
        assert_eq!(result.coeffs[2], b); // 5
    }

    #[test]
    fn fold_four_constants_selects_last() {
        // 4 constants [1, 2, 3, 4], coeffs = (1, 0) at each level
        // (a + b·X) = 1, so fold picks p[1] each time: [1,2,3,4] → [2,4] → [4]
        let polys: Vec<UnivariatePoly<F>> = (1..=4u64)
            .map(|c| UnivariatePoly::constant(F::from_u64(c)))
            .collect();
        let coeffs = vec![(F::ONE, F::ZERO); 2];
        let result = fold(coeffs.into_iter(), polys);
        assert_eq!(result.evaluate(F::ZERO), F::from_u64(4));
    }

    #[test]
    fn fold_four_constants_selects_first() {
        // coeffs = (0, 0) at each level → always picks p[0]
        // [1,2,3,4] → [1,3] → [1]
        let polys: Vec<UnivariatePoly<F>> = (1..=4u64)
            .map(|c| UnivariatePoly::constant(F::from_u64(c)))
            .collect();
        let coeffs = vec![(F::ZERO, F::ZERO); 2];
        let result = fold(coeffs.into_iter(), polys);
        assert_eq!(result.evaluate(F::ZERO), F::from_u64(1));
    }

    #[test]
    fn fold_scalars_basic() {
        // fold_scalars with (1,0) selects the second element at each level
        let scalars: Vec<F> = (1..=4u64).map(F::from_u64).collect();
        let result = fold_scalars(
            vec![(F::ONE, F::ZERO); 2].into_iter(),
            &scalars,
        );
        assert_eq!(result, F::from_u64(4));
    }

    #[test]
    fn fold_linear_basic() {
        // Two elements with lo_hi pairs: (1,2) and (3,4)
        // p0(X) = 1 + X, p1(X) = 3 + X
        // fold with (a=0, b=0): picks p0 → result = 1 + X
        let pairs = vec![(F::from_u64(1), F::from_u64(2)), (F::from_u64(3), F::from_u64(4))];
        let result = fold_linear(vec![(F::ZERO, F::ZERO)].into_iter(), &pairs);
        assert_eq!(result.evaluate(F::ZERO), F::from_u64(1));
        assert_eq!(result.evaluate(F::ONE), F::from_u64(2));
    }

    #[test]
    fn univariate_poly_evaluate() {
        // p(X) = 2 + 3X + 5X^2
        let p = UnivariatePoly::from_coeffs(vec![
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(5),
        ]);
        // p(0) = 2
        assert_eq!(p.evaluate(F::ZERO), F::from_u64(2));
        // p(1) = 2 + 3 + 5 = 10
        assert_eq!(p.evaluate(F::ONE), F::from_u64(10));
        // p(2) = 2 + 6 + 20 = 28
        assert_eq!(p.evaluate(F::from_u64(2)), F::from_u64(28));
    }
}
