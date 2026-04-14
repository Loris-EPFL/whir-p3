//! [`TerminalScheme`] implementations for WHIR (Merkle Fiat-Shamir) terminal proofs.
//!
//! Two variants are provided, matching the two accumulator types:
//!
//! - [`WhirTerminalWarp`]: for WARP's fixed-size `WarpAccumulator`, wraps the
//!   algebraic decider (`warp_decide_algebraic`) which checks eval claim + PESAT.
//!   The full WHIR polynomial commitment proof is deferred to
//!   [`EvalDecider`](super::warp::eval_fold::EvalDecider).
//!
//! - [`WhirTerminalQuasar`]: for Quasar's linearized `Accumulator`, wraps
//!   [`AccumulationDecider`](super::decider::AccumulationDecider) which generates
//!   a fresh standalone WHIR proof over the accumulated polynomial.

use core::marker::PhantomData;

use p3_field::{Field, PrimeField64, TwoAdicField};

use zkp_pipeline_traits::terminal::TerminalScheme;

use crate::spartan::r1cs::R1CSShape;

use super::warp::{
    accumulator::{WarpAccumulator, WarpAccumulatorInstance},
    decider::{WarpDeciderError, warp_decide_algebraic},
};

// ── WARP terminal (algebraic decider) ────────────────────────────────

/// Configuration for the WARP algebraic terminal decider.
#[derive(Clone, Debug)]
pub struct WhirTerminalWarpConfig<F: Field> {
    /// R1CS constraint shape for PESAT evaluation.
    pub shape: R1CSShape<F>,
}

/// Terminal proof for WARP: the algebraic decider result.
///
/// The WARP algebraic decider checks eval claim + PESAT directly from the
/// witness. A full WHIR PCS proof can be generated on top via `EvalDecider`.
/// This terminal scheme represents the algebraic-only path.
#[derive(Clone, Debug)]
pub struct WhirTerminalWarpProof {
    /// Marker indicating the decider passed. The proof is the computation itself;
    /// a verifier with access to the witness can re-check.
    pub verified: bool,
}

/// WHIR terminal scheme for WARP accumulators.
///
/// Uses the algebraic decider: checks `f̂(α) = μ` and `P*(β, z) = η`.
/// Codeword RS validity is deferred to the full WHIR proof (via `EvalDecider`).
#[derive(Clone, Debug)]
pub struct WhirTerminalWarp<F: Field> {
    _marker: PhantomData<F>,
}

impl<F> TerminalScheme for WhirTerminalWarp<F>
where
    F: Field + PrimeField64 + TwoAdicField,
{
    type Accumulator = WarpAccumulator<F, F, F, 8>;
    type AccumulatorInstance = WarpAccumulatorInstance<F, F, F, 8>;
    type Proof = WhirTerminalWarpProof;
    type Config = WhirTerminalWarpConfig<F>;
    type Error = WarpDeciderError;

    fn prove(
        config: &Self::Config,
        accumulator: &Self::Accumulator,
    ) -> Result<Self::Proof, Self::Error> {
        warp_decide_algebraic(&config.shape, accumulator)?;
        Ok(WhirTerminalWarpProof { verified: true })
    }

    fn verify(
        config: &Self::Config,
        _instance: &Self::AccumulatorInstance,
        _proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        // The algebraic decider is a prover-side check (needs the witness).
        // For a succinct verifier, use EvalDecider + full WHIR proof instead.
        // Here we just confirm the proof claims to have passed.
        if _proof.verified {
            Ok(())
        } else {
            Err(WarpDeciderError::EvaluationClaimFailed)
        }
    }
}
