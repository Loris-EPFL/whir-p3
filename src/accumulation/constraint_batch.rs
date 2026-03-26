//! Constraint batching sumcheck for accumulation.
//!
//! Reduces `ℓ` linear claims `Σ_b λᵢ(b) · fᵢ(b) = σᵢ` to point evaluations
//! at a single random point `r`, enabling codeword batching via random linear
//! combination without cross-term issues.
//!
//! After the sumcheck, the prover provides individual evaluations `fᵢ(r)` and
//! the verifier checks `Σᵢ γⁱ · λᵢ(r) · fᵢ(r) = final_claimed_sum`.

use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{Algebra, ExtensionField, TwoAdicField};

use crate::{
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    sumcheck::extrapolate_012,
    whir::verifier::errors::VerifierError,
};

/// Prover messages for the constraint batching sumcheck.
#[derive(Clone, Debug)]
pub struct ConstraintBatchProof<EF> {
    /// `[s(0), s(2)]` for each sumcheck round. `s(1)` is derived as `claimed - s(0)`.
    pub round_polys: Vec<[EF; 2]>,
    /// Individual polynomial evaluations `fᵢ(r)` at the sumcheck reduction point.
    pub individual_evals: Vec<EF>,
}

/// Runs the constraint batching sumcheck (prover side).
///
/// Proves that `Σᵢ γⁱ · (Σ_b λᵢ(b) · fᵢ(b)) = Σᵢ γⁱ · σᵢ` by running a standard
/// sumcheck over `m` variables, reducing to point evaluations at a random `r ∈ EF^m`.
///
/// # Arguments
/// - `gamma`: batching challenge (constraint batching, in base field for efficiency)
/// - `weights`: weight tables `λᵢ` from each accumulator's linear claim (in EF)
/// - `targets`: target values `σᵢ` from each accumulator's linear claim
/// - `polys`: witness polynomials `fᵢ` in base field
/// - `challenger`: Fiat-Shamir challenger
///
/// # Returns
/// The proof (round polynomials + individual evaluations) and the reduction point `r`.
pub fn constraint_batch_prove<F, EF, Challenger>(
    gamma: F,
    weights: &[EvaluationsList<EF>],
    targets: &[EF],
    polys: &[EvaluationsList<F>],
    challenger: &mut Challenger,
) -> (ConstraintBatchProof<EF>, MultilinearPoint<EF>)
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F>,
{
    let k = polys.len();
    assert_eq!(weights.len(), k);
    assert_eq!(targets.len(), k);
    assert!(k > 0);

    let num_vars = polys[0].num_variables();
    for p in polys {
        assert_eq!(p.num_variables(), num_vars);
    }
    for w in weights {
        assert_eq!(w.num_variables(), num_vars);
    }

    // Compute batching coefficients γⁱ
    let coeffs: Vec<EF> = {
        let gamma_ef = EF::from(gamma);
        let mut c = Vec::with_capacity(k);
        let mut power = EF::ONE;
        for _ in 0..k {
            c.push(power);
            power *= gamma_ef;
        }
        c
    };

    // Initial claimed sum: Σᵢ γⁱ σᵢ
    let initial_sum: EF = coeffs.iter().zip(targets.iter()).map(|(&c, &s)| c * s).sum();

    // Promote witness polys to extension field for uniform handling after round 1
    let mut ext_polys: Vec<EvaluationsList<EF>> = polys
        .iter()
        .map(|p| EvaluationsList::new(p.as_slice().iter().map(|&v| EF::from(v)).collect()))
        .collect();
    let mut ext_weights: Vec<EvaluationsList<EF>> = weights.to_vec();

    let mut round_polys = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);
    let mut claimed_sum = initial_sum;

    for _round in 0..num_vars {
        // Compute s(0) and s(2) by summing contributions from all (poly, weight) pairs
        let mut s0 = EF::ZERO;
        let mut s2 = EF::ZERO;
        for i in 0..k {
            let (c0, c2) = ext_polys[i].sumcheck_coefficients(&ext_weights[i]);
            s0 += coeffs[i] * c0;
            s2 += coeffs[i] * c2;
        }

        // Observe round polynomial and sample challenge
        challenger.observe_algebra_slice(&[s0, s2]);
        let r: EF = challenger.sample_algebra_element();

        round_polys.push([s0, s2]);
        challenges.push(r);

        // Compress all polynomials and weights with challenge r
        for poly in &mut ext_polys {
            poly.compress(r);
        }
        for w in &mut ext_weights {
            w.compress(r);
        }

        // Update claimed sum: evaluate s(r) via Lagrange interpolation at {0, 1, 2}
        let s1 = claimed_sum - s0;
        claimed_sum = extrapolate_012(s0, s1, s2, r);
    }

    // After all rounds, each polynomial is a single value = fᵢ(r)
    let individual_evals: Vec<EF> = ext_polys.iter().map(|p| p.as_slice()[0]).collect();

    // Observe individual evals so verifier can reproduce
    for &eval in &individual_evals {
        challenger.observe_algebra_element(eval);
    }

    let reduction_point = MultilinearPoint::new(challenges);
    let proof = ConstraintBatchProof {
        round_polys,
        individual_evals,
    };
    (proof, reduction_point)
}

/// Verifies the constraint batching sumcheck (verifier side).
///
/// Checks the sumcheck rounds, then verifies the final claim:
/// `Σᵢ γⁱ · λᵢ(r) · fᵢ(r) = final_claimed_sum`
///
/// # Returns
/// On success, returns `(reduction_point, combined_eval)` where `combined_eval = Σ ηⁱ fᵢ(r)`
/// is the expected evaluation of the codeword-batched polynomial at `r`.
pub fn constraint_batch_verify<F, EF, Challenger>(
    gamma: F,
    weights: &[EvaluationsList<EF>],
    targets: &[EF],
    proof: &ConstraintBatchProof<EF>,
    challenger: &mut Challenger,
) -> Result<MultilinearPoint<EF>, VerifierError>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F>,
{
    let k = weights.len();
    assert_eq!(targets.len(), k);
    assert_eq!(proof.individual_evals.len(), k);

    let num_vars = weights[0].num_variables();

    // Compute batching coefficients γⁱ
    let coeffs: Vec<EF> = {
        let gamma_ef = EF::from(gamma);
        let mut c = Vec::with_capacity(k);
        let mut power = EF::ONE;
        for _ in 0..k {
            c.push(power);
            power *= gamma_ef;
        }
        c
    };

    // Initial claimed sum: Σᵢ γⁱ σᵢ
    let mut claimed_sum: EF = coeffs.iter().zip(targets.iter()).map(|(&c, &s)| c * s).sum();

    // Verify sumcheck rounds
    if proof.round_polys.len() != num_vars {
        return Err(VerifierError::SumcheckFailed {
            round: 0,
            expected: alloc::format!("{num_vars} rounds"),
            actual: alloc::format!("{} rounds", proof.round_polys.len()),
        });
    }

    let mut challenges = Vec::with_capacity(num_vars);
    for (round, &[s0, s2]) in proof.round_polys.iter().enumerate() {
        let s1 = claimed_sum - s0;

        // Observe and sample (must match prover)
        challenger.observe_algebra_slice(&[s0, s2]);
        let r: EF = challenger.sample_algebra_element();
        challenges.push(r);

        // Update claimed sum
        let new_claimed = extrapolate_012(s0, s1, s2, r);

        // Verify: s(0) + s(1) == previous claimed_sum (implicit in the derivation)
        // This is guaranteed by construction: s1 = claimed_sum - s0, so s0 + s1 = claimed_sum
        let _ = round; // suppress unused warning
        claimed_sum = new_claimed;
    }

    let reduction_point = MultilinearPoint::new(challenges);

    // Observe individual evals (must match prover)
    for &eval in &proof.individual_evals {
        challenger.observe_algebra_element(eval);
    }

    // Final check: Σᵢ γⁱ · λᵢ(r) · fᵢ(r) = final claimed_sum
    let mut final_check = EF::ZERO;
    for i in 0..k {
        let weight_at_r: EF = weights[i].evaluate_hypercube_ext::<F>(&reduction_point);
        final_check += coeffs[i] * weight_at_r * proof.individual_evals[i];
    }

    if final_check != claimed_sum {
        return Err(VerifierError::SumcheckFailed {
            round: num_vars,
            expected: alloc::format!("final check {claimed_sum:?}"),
            actual: alloc::format!("got {final_check:?}"),
        });
    }

    Ok(reduction_point)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    fn make_challenger() -> MyChallenger {
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(42));
        MyChallenger::new(perm)
    }

    #[test]
    fn single_claim_round_trip() {
        // Single claim: Σ_b λ(b) · f(b) = σ
        let f = EvaluationsList::<F>::new(vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
        ]);
        let lambda = EvaluationsList::<EF>::new(vec![
            EF::from_u64(10),
            EF::from_u64(20),
            EF::from_u64(30),
            EF::from_u64(40),
        ]);
        // σ = 1*10 + 2*20 + 3*30 + 4*40 = 10+40+90+160 = 300
        let sigma = EF::from_u64(300);

        let gamma = F::ONE;

        let mut prover_chal = make_challenger();
        let (proof, _point) =
            constraint_batch_prove(gamma, &[lambda.clone()], &[sigma], &[f], &mut prover_chal);

        let mut verifier_chal = make_challenger();
        let result =
            constraint_batch_verify(gamma, &[lambda], &[sigma], &proof, &mut verifier_chal);
        assert!(result.is_ok(), "verification failed: {result:?}");
    }

    #[test]
    fn two_claims_round_trip() {
        let f0 = EvaluationsList::<F>::new(vec![F::from_u64(1), F::from_u64(2)]);
        let f1 = EvaluationsList::<F>::new(vec![F::from_u64(3), F::from_u64(4)]);
        let w0 = EvaluationsList::<EF>::new(vec![EF::from_u64(5), EF::from_u64(6)]);
        let w1 = EvaluationsList::<EF>::new(vec![EF::from_u64(7), EF::from_u64(8)]);
        // σ₀ = 1*5 + 2*6 = 17
        let s0 = EF::from_u64(17);
        // σ₁ = 3*7 + 4*8 = 53
        let s1 = EF::from_u64(53);

        let gamma = F::from_u64(3);

        let mut prover_chal = make_challenger();
        let (proof, _) = constraint_batch_prove(
            gamma,
            &[w0.clone(), w1.clone()],
            &[s0, s1],
            &[f0, f1],
            &mut prover_chal,
        );

        let mut verifier_chal = make_challenger();
        let result =
            constraint_batch_verify(gamma, &[w0, w1], &[s0, s1], &proof, &mut verifier_chal);
        assert!(result.is_ok(), "verification failed: {result:?}");
    }

    #[test]
    fn tampered_eval_is_rejected() {
        let f = EvaluationsList::<F>::new(vec![F::from_u64(1), F::from_u64(2)]);
        let w = EvaluationsList::<EF>::new(vec![EF::from_u64(5), EF::from_u64(6)]);
        let sigma = EF::from_u64(17); // 1*5 + 2*6

        let gamma = F::ONE;

        let mut prover_chal = make_challenger();
        let (mut proof, _) =
            constraint_batch_prove(gamma, &[w.clone()], &[sigma], &[f], &mut prover_chal);

        // Tamper with individual eval
        proof.individual_evals[0] += EF::ONE;

        let mut verifier_chal = make_challenger();
        let result = constraint_batch_verify(gamma, &[w], &[sigma], &proof, &mut verifier_chal);
        assert!(result.is_err(), "tampered proof should be rejected");
    }
}
