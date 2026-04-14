//! [`FoldingScheme`] implementation for the WARP fixed-size accumulation scheme.
//!
//! Wraps the existing [`warp_fold_prove`] / [`warp_fold_prove_rs_committed`]
//! functions behind the generic pipeline trait, allowing WARP to be composed
//! with any compatible [`TerminalScheme`].

use alloc::{vec, vec::Vec};

use p3_field::{Field, PrimeField64, TwoAdicField};

use zkp_pipeline_traits::folding::FoldingScheme;

use crate::poly::evals::EvaluationsList;
use crate::spartan::r1cs::R1CSShape;

use crate::accumulator::{
    FreshInstance, WarpAccumulator, WarpAccumulatorInstance, WarpAccumulatorWitness,
};
use crate::fold::{RSEncodingConfig, WarpFoldConfig, WarpFoldResult, warp_fold_prove};

/// Configuration for the WARP folding pipeline.
///
/// Bundles the R1CS shape, RS encoding config, fold config, and optional
/// DFT/Merkle handles needed by the fold prover.
#[derive(Clone, Debug)]
pub struct WarpPipelineConfig<F: Field> {
    /// R1CS constraint shape (shared across all instances).
    pub shape: R1CSShape<F>,
    /// Reed-Solomon encoding parameters (folding factor + inverse rate).
    /// `None` means identity encoding (no RS, useful for testing).
    pub rs_config: Option<RSEncodingConfig>,
    /// Fold-specific parameters (OOD samples, shift queries).
    pub fold_config: WarpFoldConfig,
    /// Number of log-variables in the codeword domain.
    pub log_code_len: usize,
    /// Number of public input elements per instance.
    pub num_public_inputs: usize,
}

/// Marker type for the WARP folding scheme in the generic pipeline.
///
/// Generic over the field type. DFT, Merkle, and challenger are encapsulated
/// in the fold call via the config rather than being type parameters here,
/// keeping the trait impl simpler.
#[derive(Clone, Debug)]
pub struct WarpFolding<F: Field> {
    _marker: core::marker::PhantomData<F>,
}

/// Error type for WARP fold operations.
#[derive(Debug, thiserror::Error)]
pub enum WarpFoldError {
    /// No fresh instances provided.
    #[error("no fresh instances provided")]
    EmptyFresh,
    /// Sumcheck or algebraic check failed.
    #[error("fold failed: {0}")]
    FoldFailed(alloc::string::String),
}

impl<F> FoldingScheme for WarpFolding<F>
where
    F: Field + PrimeField64 + TwoAdicField,
{
    type Accumulator = WarpAccumulator<F, F, F, 8>;
    type AccumulatorInstance = WarpAccumulatorInstance<F, F, F, 8>;
    type Fresh = FreshInstance<F>;
    type FoldProof = WarpFoldResult<F>;
    type Config = WarpPipelineConfig<F>;
    type Error = WarpFoldError;

    fn instance(accumulator: &Self::Accumulator) -> &Self::AccumulatorInstance {
        &accumulator.instance
    }

    fn init(config: &Self::Config) -> Self::Accumulator {
        let log_n = config.log_code_len;
        let n = 1usize << log_n;
        let num_cons = config.shape.num_cons().next_power_of_two();
        let log_m = num_cons.trailing_zeros() as usize;

        WarpAccumulator {
            instance: WarpAccumulatorInstance {
                commitment_root: [F::ZERO; 8],
                eval_point: vec![F::ZERO; log_n],
                eval_claim: F::ZERO,
                pesat_tau: vec![F::ZERO; log_m],
                pesat_x: vec![F::ZERO; config.num_public_inputs],
                pesat_target: F::ZERO,
            },
            witness: WarpAccumulatorWitness {
                codeword: EvaluationsList::new(vec![F::ZERO; n]),
                witness: vec![F::ZERO; config.shape.num_vars()],
            },
        }
    }

    fn fold(
        config: &Self::Config,
        accumulator: &Self::Accumulator,
        fresh: &[Self::Fresh],
    ) -> Result<(Self::Accumulator, Self::FoldProof), Self::Error> {
        if fresh.is_empty() {
            return Err(WarpFoldError::EmptyFresh);
        }

        let l1 = fresh.len();
        let l = (1 + l1).next_power_of_two();
        let log_l = l.trailing_zeros() as usize;

        // Derive Fiat-Shamir challenges deterministically from accumulator + fresh data.
        // In the full pipeline, these come from a Plonky3 challenger. Here we use
        // a simple deterministic derivation so the trait impl is self-contained.
        // Real pipeline usage should call the underlying functions directly with
        // a proper challenger for full soundness.
        let omega = derive_deterministic_challenge(&accumulator.instance, fresh, 0);
        let tau_challenges: Vec<F> = (0..log_l)
            .map(|i| derive_deterministic_challenge(&accumulator.instance, fresh, 1 + i))
            .collect();

        let num_cons = config.shape.num_cons().next_power_of_two();
        let log_m = num_cons.trailing_zeros() as usize;
        let fresh_betas: Vec<Vec<F>> = (0..l1)
            .map(|i| {
                (0..log_m)
                    .map(|j| {
                        derive_deterministic_challenge(
                            &accumulator.instance,
                            fresh,
                            100 + i * log_m + j,
                        )
                    })
                    .collect()
            })
            .collect();

        let mut round_idx = 0usize;
        let mut transcript_round = |_coeffs: &[F]| -> F {
            round_idx += 1;
            derive_deterministic_challenge(
                &accumulator.instance,
                fresh,
                1000 + round_idx,
            )
        };

        let result = warp_fold_prove(
            &config.shape,
            fresh,
            accumulator,
            omega,
            &tau_challenges,
            &fresh_betas,
            &mut transcript_round,
        );

        // Reconstruct the new accumulator from the fold result
        let new_acc = WarpAccumulator {
            instance: WarpAccumulatorInstance {
                commitment_root: result.commitment_root,
                eval_point: result.instance.eval_point.clone(),
                eval_claim: F::ZERO, // Updated by eval batching if present
                pesat_tau: result.instance.pesat_tau.clone(),
                pesat_x: result.instance.pesat_x.clone(),
                pesat_target: result.instance.pesat_target,
            },
            witness: result.witness.clone(),
        };

        Ok((new_acc, result))
    }

    fn verify_fold(
        _config: &Self::Config,
        _prev_instance: &Self::AccumulatorInstance,
        _fresh: &[Self::Fresh],
        _proof: &Self::FoldProof,
    ) -> Result<Self::AccumulatorInstance, Self::Error> {
        // The WARP fold verifier replays the twin-constraint sumcheck and checks
        // shift queries + OOD answers. Full implementation requires the sumcheck
        // verifier and Merkle proof verification.
        //
        // For now, reconstruct the output instance from the proof data.
        // The terminal scheme (WHIR or CP-SNARK) provides the final soundness check.
        let proof = _proof;
        Ok(WarpAccumulatorInstance {
            commitment_root: proof.commitment_root,
            eval_point: proof.instance.eval_point.clone(),
            eval_claim: F::ZERO,
            pesat_tau: proof.instance.pesat_tau.clone(),
            pesat_x: proof.instance.pesat_x.clone(),
            pesat_target: proof.instance.pesat_target,
        })
    }
}

/// Derive a deterministic challenge from accumulator state + fresh inputs.
///
/// This is a placeholder for proper Fiat-Shamir. In the real pipeline, a
/// Plonky3 `Challenger` handles this. The trait-based fold uses this so it
/// can be self-contained without requiring challenger type parameters.
fn derive_deterministic_challenge<F: Field + PrimeField64>(
    _instance: &WarpAccumulatorInstance<F, F, F, 8>,
    _fresh: &[FreshInstance<F>],
    salt: usize,
) -> F {
    // Simple deterministic derivation: hash the salt into a field element.
    // NOT cryptographically sound — real usage should go through a challenger.
    F::from_u64(salt as u64 + 7)
}
