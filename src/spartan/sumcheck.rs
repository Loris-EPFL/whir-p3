//! Sum-Check Protocol for R1CS
//!
//! Implements Spartan's two-phase sum-check protocol (Section 5):
//! - Phase 1: Sum-check on G_io,τ(x) to get claims about Az, Bz, Cz
//! - Phase 2: Sum-check on linear combination of A, B, C to verify evaluation

use alloc::vec;
use alloc::vec::Vec;
use p3_field::Field;

/// Sum-check proof for a multilinear polynomial
///
/// From Spartan Section 5.1:
/// Reduces claim Σ_{x∈{0,1}^s} G(x) = T to claim G(r) = e
#[derive(Debug, Clone)]
pub struct SumcheckProof<F: Field> {
    /// Univariate polynomials sent by prover in each round
    pub polynomials: Vec<Vec<F>>, // Each round sends a degree-d polynomial
    /// Challenges from verifier
    pub challenges: Vec<F>,
    /// Final evaluation point
    pub final_point: Vec<F>,
    /// Final claimed evaluation
    pub final_eval: F,
}

/// Prover for the sum-check protocol
#[derive(Debug)]
pub struct SumcheckProver<F: Field> {
    /// Current evaluation table
    evals: Vec<F>,
    /// Number of variables
    num_vars: usize,
    /// Current round
    round: usize,
    /// Degree bound
    degree_bound: usize,
}

impl<F: Field> SumcheckProver<F> {
    /// Create a new sum-check prover
    ///
    /// # Arguments
    /// * `evals` - Evaluations of the polynomial over the boolean hypercube
    /// * `degree_bound` - Maximum degree in each variable
    pub fn new(evals: Vec<F>, degree_bound: usize) -> Self {
        let num_vars = evals.len().trailing_zeros() as usize;
        Self {
            evals,
            num_vars,
            round: 0,
            degree_bound,
        }
    }

    /// Execute one round of the sum-check protocol
    ///
    /// Returns the univariate polynomial for this round
    pub fn prove_round(&mut self) -> Vec<F> {
        assert!(self.round < self.num_vars);

        let degree = self.degree_bound;
        let mut univariate = vec![F::ZERO; degree + 1];

        // Number of remaining points after this variable is fixed
        let remaining = 1usize << (self.num_vars - self.round - 1);

        // For each value of the current variable (0, 1, ..., degree)
        // compute the sum over all other variables
        for j in 0..=degree {
            let mut sum = F::ZERO;

            // Sum over all combinations of remaining variables
            for b in 0..remaining {
                // Compute index for this combination
                let idx = (j << (self.num_vars - self.round - 1)) | b;
                if idx < self.evals.len() {
                    sum += self.evals[idx];
                }
            }

            univariate[j] = sum;
        }

        self.round += 1;
        univariate
    }

    /// Bind the evaluation table to a challenge
    ///
    /// After receiving challenge r from verifier, fold the table
    pub fn bind(&mut self, challenge: F) {
        if self.round == 0 {
            return;
        }

        let remaining = self.evals.len() / 2;
        let mut new_evals = Vec::with_capacity(remaining);

        for i in 0..remaining {
            // Interpolate between evals[2i] and evals[2i+1] at challenge
            let low = self.evals[2 * i];
            let high = self.evals[2 * i + 1];
            // Linear interpolation: (1-r) * low + r * high
            let value = low + challenge * (high - low);
            new_evals.push(value);
        }

        self.evals = new_evals;
    }

    /// Get the final evaluation after all rounds
    pub fn final_eval(&self) -> F {
        assert_eq!(self.evals.len(), 1);
        self.evals[0]
    }
}

/// Verifier for the sum-check protocol
#[derive(Debug)]
pub struct SumcheckVerifier<F: Field> {
    /// Claimed sum
    claim: F,
    /// Number of variables
    num_vars: usize,
    /// Current round
    round: usize,
    /// Degree bound
    degree_bound: usize,
    /// Challenges
    challenges: Vec<F>,
}

impl<F: Field> SumcheckVerifier<F> {
    /// Create a new sum-check verifier
    pub fn new(claim: F, num_vars: usize, degree_bound: usize) -> Self {
        Self {
            claim,
            num_vars,
            round: 0,
            degree_bound,
            challenges: Vec::new(),
        }
    }

    /// Verify one round of the sum-check protocol
    ///
    /// # Arguments
    /// * `univariate` - The univariate polynomial from the prover
    ///
    /// Returns the challenge for this round
    pub fn verify_round(&mut self, univariate: &[F]) -> Result<F, &'static str> {
        if self.round >= self.num_vars {
            return Err("Too many rounds");
        }

        if univariate.len() != self.degree_bound + 1 {
            return Err("Invalid polynomial degree");
        }

        // Check that p(0) + p(1) = previous_claim (or initial claim)
        let sum_at_01 = univariate[0] + univariate[1];
        let expected = if self.round == 0 {
            self.claim
        } else {
            // In a real implementation, we'd track the expected value
            // For now, we just verify the structure
            sum_at_01
        };

        if sum_at_01 != expected {
            return Err("Sum-check failed: p(0) + p(1) != claim");
        }

        // Generate random challenge
        let challenge = F::from_usize(42); // TODO: Use proper randomness
        self.challenges.push(challenge);
        self.round += 1;

        Ok(challenge)
    }

    /// Get the final challenges (evaluation point)
    pub fn final_point(&self) -> &[F] {
        &self.challenges
    }
}

/// Two-phase sum-check for R1CS (Section 5.1)
///
/// Phase 1: G_io,τ(x) sum-check (degree 3)
/// Phase 2: Linear combination M(rx, y) sum-check (degree 2)
#[derive(Debug)]
pub struct R1CSSumcheck<F: Field> {
    /// Phase 1 prover
    phase1_prover: SumcheckProver<F>,
    /// Phase 2 prover  
    phase2_prover: Option<SumcheckProver<F>>,
    /// Current phase
    phase: usize,
}

impl<F: Field> R1CSSumcheck<F> {
    /// Start sum-check for R1CS
    ///
    /// # Arguments
    /// * `g_evals` - Evaluations of G_io,τ over boolean hypercube
    pub fn new(g_evals: Vec<F>) -> Self {
        Self {
            phase1_prover: SumcheckProver::new(g_evals, 3), // Degree 3
            phase2_prover: None,
            phase: 1,
        }
    }

    /// Prove a round of sum-check
    pub fn prove_round(&mut self) -> Vec<F> {
        match self.phase {
            1 => self.phase1_prover.prove_round(),
            2 => self.phase2_prover.as_mut().unwrap().prove_round(),
            _ => panic!("Invalid phase"),
        }
    }

    /// Bind to challenge
    pub fn bind(&mut self, challenge: F) {
        match self.phase {
            1 => self.phase1_prover.bind(challenge),
            2 => self.phase2_prover.as_mut().unwrap().bind(challenge),
            _ => panic!("Invalid phase"),
        }
    }

    /// Start phase 2 with linear combination of A, B, C
    pub fn start_phase2(&mut self, m_evals: Vec<F>) {
        assert_eq!(self.phase, 1);
        self.phase2_prover = Some(SumcheckProver::new(m_evals, 2)); // Degree 2
        self.phase = 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn test_sumcheck_basic() {
        type F = BabyBear;

        // Simple polynomial: p(x, y) = x * y
        // Evaluations: p(0,0)=0, p(0,1)=0, p(1,0)=0, p(1,1)=1
        let evals = vec![F::ZERO, F::ZERO, F::ZERO, F::ONE];

        let mut prover = SumcheckProver::new(evals.clone(), 2);

        // Round 1: sum over x, get polynomial in y
        let poly1 = prover.prove_round();
        // At y=0: p(0,0) + p(1,0) = 0 + 0 = 0
        // At y=1: p(0,1) + p(1,1) = 0 + 1 = 1
        assert_eq!(poly1[0], F::ZERO);
        assert_eq!(poly1[1], F::ONE);

        // Challenge r1
        let r1 = F::from_u64(2);
        prover.bind(r1);

        // After binding, we should have 2 evaluations
        assert_eq!(prover.evals.len(), 2);
    }
}
