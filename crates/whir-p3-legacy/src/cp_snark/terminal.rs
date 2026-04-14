//! [`TerminalScheme`] implementation for the CP-SNARK terminal prover.
//!
//! Wraps the existing [`cp_snark_terminal_verify`] and commitment functions
//! behind the generic pipeline trait, allowing the CP-SNARK terminal to be
//! composed with any compatible [`FoldingScheme`].

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use p3_challenger::{CanObserve, CanSample};
use p3_field::{Field, PrimeField64};

use zkp_pipeline_traits::terminal::TerminalScheme;

use crate::{
    accumulation::warp::accumulator::{WarpAccumulator, WarpAccumulatorInstance},
    spartan::r1cs::R1CSShape,
};

use super::{
    CommittedFoldTranscript, CpSnarkDeciderError, cp_snark_terminal_verify,
};

/// Enriched accumulator for CP-SNARK: the WARP accumulator plus all
/// committed fold transcripts collected during IVC.
#[derive(Clone, Debug)]
pub struct CpSnarkAccumulator<F: Field> {
    /// The final WARP accumulator after all folds.
    pub accumulator: WarpAccumulator<F, F, F, 8>,
    /// Committed fold transcripts from each IVC step.
    pub transcripts: Vec<CommittedFoldTranscript<F>>,
}

/// Terminal proof from the CP-SNARK path.
///
/// The "proof" is the collection of committed transcripts plus the algebraic
/// decider result. The verifier replays Fiat-Shamir and checks bindings.
#[derive(Clone, Debug)]
pub struct CpSnarkTerminalProof<F: Field> {
    /// Committed fold transcripts (one per IVC step).
    pub transcripts: Vec<CommittedFoldTranscript<F>>,
    /// Whether the algebraic decider passed.
    pub algebraic_check_passed: bool,
}

/// Configuration for the CP-SNARK terminal scheme.
pub struct CpSnarkTerminalConfig<F: Field, MakeChallenger> {
    /// R1CS shape for the algebraic decider.
    pub shape: R1CSShape<F>,
    /// Factory to create fresh Fiat-Shamir challengers for FS replay.
    pub make_challenger: MakeChallenger,
}

impl<F: Field, MC> core::fmt::Debug for CpSnarkTerminalConfig<F, MC> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpSnarkTerminalConfig").finish()
    }
}

impl<F: Field, MC: Clone> Clone for CpSnarkTerminalConfig<F, MC> {
    fn clone(&self) -> Self {
        Self {
            shape: self.shape.clone(),
            make_challenger: self.make_challenger.clone(),
        }
    }
}

/// CP-SNARK terminal scheme marker type.
#[derive(Clone, Debug)]
pub struct CpSnarkTerminal<F: Field, Challenger> {
    _marker: PhantomData<(F, Challenger)>,
}

impl<F, Challenger> TerminalScheme for CpSnarkTerminal<F, Challenger>
where
    F: Field + PrimeField64,
    Challenger: CanObserve<F> + CanSample<F>,
{
    type Accumulator = CpSnarkAccumulator<F>;
    type AccumulatorInstance = WarpAccumulatorInstance<F, F, F, 8>;
    type Proof = CpSnarkTerminalProof<F>;
    type Config = CpSnarkTerminalConfig<F, fn() -> Challenger>;
    type Error = CpSnarkDeciderError;

    fn prove(
        config: &Self::Config,
        accumulator: &Self::Accumulator,
    ) -> Result<Self::Proof, Self::Error> {
        // Run the full CP-SNARK terminal verification (binding + FS replay + algebraic)
        cp_snark_terminal_verify(
            &config.shape,
            &accumulator.accumulator,
            &accumulator.transcripts,
            &config.make_challenger,
        )?;

        Ok(CpSnarkTerminalProof {
            transcripts: accumulator.transcripts.clone(),
            algebraic_check_passed: true,
        })
    }

    fn verify(
        config: &Self::Config,
        _instance: &Self::AccumulatorInstance,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        // The verifier needs the transcripts + instance to replay FS.
        // For a fully succinct verifier, the CP-SNARK proof would be a
        // Symphony BackendSnark::Proof checked via BackendSnark::verify.
        // Here we verify the committed transcripts (binding + FS replay).
        super::verify_committed_transcripts(
            &proof.transcripts,
            &config.make_challenger,
        )
    }
}
