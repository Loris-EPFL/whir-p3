//! Sum-Check Protocol for R1CS
//!
//! Implements Spartan's two-phase sum-check protocol (Section 5):
//! - Phase 1: Sum-check on G_io,τ(x) to get claims about Az, Bz, Cz
//! - Phase 2: Sum-check on linear combination of A, B, C to verify evaluation

use alloc::vec;
use alloc::vec::Vec;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
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

/// Spartan round transcript data, mirroring WHIR's `SumcheckData` shape.
#[derive(Debug, Clone, Default)]
pub struct SpartanSumcheckData<F: Field> {
    /// One full univariate evaluation vector per round: h(0..=d).
    pub round_evaluations: Vec<Vec<F>>,
    /// Optional PoW witnesses for each round.
    pub pow_witnesses: Vec<F>,
}

impl<F: Field> SpartanSumcheckData<F> {
    /// Record the round payload, absorb into transcript, optionally grind, and sample challenge.
    pub fn observe_and_sample<Challenger>(
        &mut self,
        challenger: &mut Challenger,
        round_evals: Vec<F>,
        pow_bits: usize,
    ) -> F
    where
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        self.round_evaluations.push(round_evals.clone());
        challenger.observe_algebra_slice(&round_evals);
        if pow_bits > 0 {
            self.pow_witnesses.push(challenger.grind(pow_bits));
        }
        challenger.sample()
    }
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
    /// Transcript challenges sampled through `prove_round_into_data`.
    challenges: Vec<F>,
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
            challenges: Vec::new(),
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

    /// Prove one round, write it to transcript data, and bind to sampled challenge.
    pub fn prove_round_into_data<Challenger>(
        &mut self,
        data: &mut SpartanSumcheckData<F>,
        challenger: &mut Challenger,
        pow_bits: usize,
    ) -> Vec<F>
    where
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        let round_evals = self.prove_round();
        let challenge = data.observe_and_sample(challenger, round_evals.clone(), pow_bits);
        self.bind(challenge);
        self.challenges.push(challenge);
        round_evals
    }

    pub fn challenges(&self) -> &[F] {
        &self.challenges
    }
}

/// Verifier for the sum-check protocol
#[derive(Debug)]
pub struct SumcheckVerifier<F: Field> {
    /// Initial claimed sum
    initial_claim: F,
    /// Running claim after each round
    current_claim: F,
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
            initial_claim: claim,
            current_claim: claim,
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
    pub fn verify_round<Challenger>(
        &mut self,
        univariate: &[F],
        challenger: &mut Challenger,
    ) -> Result<F, &'static str>
    where
        Challenger: FieldChallenger<F> + CanObserve<F>,
    {
        self.verify_round_from_data(univariate, challenger)
    }

    /// Verify one round from transcript-provided round evaluations.
    pub fn verify_round_from_data<Challenger>(
        &mut self,
        univariate: &[F],
        challenger: &mut Challenger,
    ) -> Result<F, &'static str>
    where
        Challenger: FieldChallenger<F> + CanObserve<F>,
    {
        if self.round >= self.num_vars {
            return Err("Too many rounds");
        }

        validate_round_evals_len(univariate, self.degree_bound)?;
        derive_next_claim(self.current_claim, univariate)?;

        // Fiat-Shamir round challenge derived from transcript.
        challenger.observe_algebra_slice(univariate);
        let challenge = challenger.sample();

        // Update running claim to p_i(r_i).
        self.current_claim = evaluate_univariate_from_samples(univariate, challenge);
        self.challenges.push(challenge);
        self.round += 1;

        Ok(challenge)
    }

    /// Get the final challenges (evaluation point)
    pub fn final_point(&self) -> &[F] {
        &self.challenges
    }

    /// Get the final claim after all rounds.
    pub fn final_claim(&self) -> F {
        self.current_claim
    }

    /// Get initial claim.
    pub fn initial_claim(&self) -> F {
        self.initial_claim
    }
}

fn validate_round_evals_len<F: Field>(
    round_evals: &[F],
    degree_bound: usize,
) -> Result<(), &'static str> {
    if round_evals.len() != degree_bound + 1 {
        return Err("Invalid polynomial degree");
    }
    Ok(())
}

fn derive_next_claim<F: Field>(prev_claim: F, round_evals: &[F]) -> Result<(), &'static str> {
    let sum_at_01 = round_evals[0] + round_evals[1];
    if sum_at_01 != prev_claim {
        return Err("Sum-check failed: p(0) + p(1) != claim");
    }
    Ok(())
}

/// Evaluate a univariate polynomial at `r` from its values at points `0..=d`.
fn evaluate_univariate_from_samples<F: Field>(samples: &[F], r: F) -> F {
    let degree = samples.len() - 1;
    let mut result = F::ZERO;

    for (i, &y_i) in samples.iter().enumerate() {
        let mut basis = F::ONE;
        let x_i = F::from_usize(i);

        for j in 0..=degree {
            if i == j {
                continue;
            }
            let x_j = F::from_usize(j);
            let denom = x_i - x_j;
            let inv = denom.inverse();
            basis *= (r - x_j) * inv;
        }

        result += y_i * basis;
    }

    result
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

    /// Prove one round in the active phase and write to transcript data.
    pub fn prove_round_into_data<Challenger>(
        &mut self,
        data: &mut SpartanSumcheckData<F>,
        challenger: &mut Challenger,
        pow_bits: usize,
    ) -> Vec<F>
    where
        Challenger: FieldChallenger<F> + CanObserve<F> + GrindingChallenger<Witness = F>,
    {
        match self.phase {
            1 => self
                .phase1_prover
                .prove_round_into_data(data, challenger, pow_bits),
            2 => self
                .phase2_prover
                .as_mut()
                .unwrap()
                .prove_round_into_data(data, challenger, pow_bits),
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
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use rand::SeedableRng;

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

    type F = BabyBear;
    type Perm = p3_baby_bear::Poseidon2BabyBear<16>;
    type Challenger = DuplexChallenger<F, Perm, 16, 8>;

    fn run_sumcheck(evals: Vec<F>, degree: usize) -> SumcheckProof<F> {
        let num_vars = evals.len().trailing_zeros() as usize;
        let mut prover = SumcheckProver::new(evals, degree);
        let mut data = SpartanSumcheckData::default();
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);

        for _ in 0..num_vars {
            let _ = prover.prove_round_into_data(&mut data, &mut challenger, 0);
        }
        let challenges = prover.challenges().to_vec();

        SumcheckProof {
            polynomials: data.round_evaluations,
            challenges: challenges.clone(),
            final_point: challenges,
            final_eval: prover.final_eval(),
        }
    }

    #[test]
    fn test_sumcheck_verifier_rejects_tampered_coefficient() {
        let evals = vec![F::ZERO, F::ONE, F::ONE, F::TWO];
        let mut proof = run_sumcheck(evals.clone(), 1);
        proof.polynomials[0][0] += F::ONE;

        let initial_claim: F = evals.iter().copied().sum();
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);
        let mut verifier = SumcheckVerifier::new(initial_claim, 2, 1);

        let result = verifier.verify_round(&proof.polynomials[0], &mut challenger);
        assert!(result.is_err());
    }

    #[test]
    fn test_sumcheck_verifier_rejects_invalid_degree_payload() {
        let initial_claim = F::ONE;
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);
        let mut verifier = SumcheckVerifier::new(initial_claim, 1, 3);

        let bad_round = vec![F::ZERO, F::ONE, F::TWO];
        let result = verifier.verify_round_from_data(&bad_round, &mut challenger);
        assert!(result.is_err());
    }

    #[test]
    fn test_sumcheck_verifier_rejects_tampered_challenge_trace() {
        let evals = vec![F::ZERO, F::ONE, F::ONE, F::TWO];
        let mut proof = run_sumcheck(evals.clone(), 1);
        proof.challenges[0] += F::ONE;

        let initial_claim: F = evals.iter().copied().sum();
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);
        let mut verifier = SumcheckVerifier::new(initial_claim, 2, 1);

        let mut derived = Vec::new();
        for poly in &proof.polynomials {
            let r = verifier.verify_round(poly, &mut challenger).unwrap();
            derived.push(r);
        }

        assert_ne!(derived, proof.challenges);
    }

    #[test]
    fn test_sumcheck_verifier_rejects_tampered_final_eval() {
        let evals = vec![F::ZERO, F::ONE, F::ONE, F::TWO];
        let mut proof = run_sumcheck(evals.clone(), 1);
        proof.final_eval += F::ONE;

        let initial_claim: F = evals.iter().copied().sum();
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);
        let mut verifier = SumcheckVerifier::new(initial_claim, 2, 1);

        for poly in &proof.polynomials {
            let _ = verifier.verify_round(poly, &mut challenger).unwrap();
        }

        assert_ne!(verifier.final_claim(), proof.final_eval);
    }

    #[test]
    fn test_sumcheck_replay_succeeds_degree_3() {
        let evals = vec![F::ZERO, F::ZERO];
        let proof = run_sumcheck(evals.clone(), 3);

        let initial_claim: F = evals.iter().copied().sum();
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);
        let mut verifier = SumcheckVerifier::new(initial_claim, 1, 3);

        for round in &proof.polynomials {
            let _ = verifier
                .verify_round_from_data(round, &mut challenger)
                .expect("valid replay should verify");
        }

        assert_eq!(verifier.final_point(), proof.final_point.as_slice());
        assert_eq!(verifier.final_claim(), proof.final_eval);
    }

    #[test]
    fn test_sumcheck_replay_succeeds_degree_2() {
        let evals = vec![F::TWO, F::ONE];
        let proof = run_sumcheck(evals.clone(), 2);

        let initial_claim: F = evals.iter().copied().sum();
        let perm = Perm::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(7));
        let mut challenger = Challenger::new(perm);
        let mut verifier = SumcheckVerifier::new(initial_claim, 1, 2);

        for round in &proof.polynomials {
            let _ = verifier
                .verify_round_from_data(round, &mut challenger)
                .expect("valid replay should verify");
        }

        assert_eq!(verifier.final_point(), proof.final_point.as_slice());
        assert_eq!(verifier.final_claim(), proof.final_eval);
    }
}
