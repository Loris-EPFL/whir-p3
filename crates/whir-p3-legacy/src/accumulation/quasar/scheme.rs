//! [`FoldingScheme`] implementation for the Quasar linearized accumulation scheme.
//!
//! Wraps [`QuasarFrontendProver::squash_and_prove`] behind the generic pipeline
//! trait, allowing Quasar to be composed with any compatible [`TerminalScheme`].
//!
//! Quasar batches fresh linearized instances (from Spartan) via constraint-batch
//! sumcheck + random linear combination, then commits the combined polynomial
//! using a full WHIR proof. Unlike WARP, the accumulator carries a growing
//! `LinearStatement` (weight table + target), but the witness polynomial stays
//! at fixed size thanks to random LC.

use core::marker::PhantomData;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Algebra, ExtensionField, Field, PackedValue, TwoAdicField};
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};

use zkp_pipeline_traits::folding::FoldingScheme;

use crate::accumulation::{
    accumulator::{Accumulator, AccumulatorInstance},
    proof::AccumulationProof,
};

use super::fresh::FreshLinearInstance;
use super::frontend::{QuasarFrontendOutput, QuasarFrontendProver};

/// Configuration for the Quasar folding pipeline.
///
/// Bundles the WHIR config, DFT handle, and number of shift queries needed
/// by the Quasar frontend prover.
#[derive(Clone, Debug)]
pub struct QuasarPipelineConfig<EF, F, H, C, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// The WHIR configuration used for polynomial commitment inside Quasar.
    pub whir_config: crate::whir::parameters::WhirConfig<EF, F, H, C, Challenger>,
    /// Number of in-domain shift queries for proximity testing.
    pub num_shift_queries: usize,
}

/// Marker type for the Quasar folding scheme in the generic pipeline.
///
/// Heavily generic because Quasar threads WHIR's full type parameter set
/// (hash, compress, challenger, packed types) through to the commitment.
pub struct QuasarFolding<EF, F, H, C, Challenger, P, W, PW, Dft, const DIGEST_ELEMS: usize>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// DFT handle for polynomial evaluations (shared, not owned).
    dft: Dft,
    _marker: PhantomData<(EF, F, H, C, Challenger, P, W, PW)>,
}

impl<EF, F, H, C, Challenger, P, W, PW, Dft, const DIGEST_ELEMS: usize>
    QuasarFolding<EF, F, H, C, Challenger, P, W, PW, Dft, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
    Dft: Clone,
{
    pub fn new(dft: Dft) -> Self {
        Self {
            dft,
            _marker: PhantomData,
        }
    }
}

impl<EF, F, H, C, Challenger, P, W, PW, Dft, const DIGEST_ELEMS: usize> Clone
    for QuasarFolding<EF, F, H, C, Challenger, P, W, PW, Dft, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
    Dft: Clone,
{
    fn clone(&self) -> Self {
        Self {
            dft: self.dft.clone(),
            _marker: PhantomData,
        }
    }
}

impl<EF, F, H, C, Challenger, P, W, PW, Dft, const DIGEST_ELEMS: usize> core::fmt::Debug
    for QuasarFolding<EF, F, H, C, Challenger, P, W, PW, Dft, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuasarFolding").finish()
    }
}

/// Error type for Quasar fold operations.
#[derive(Debug)]
pub enum QuasarFoldError {
    /// No fresh instances provided.
    EmptyFresh,
    /// Fiat-Shamir error from the WHIR prover.
    FiatShamir(crate::fiat_shamir::errors::FiatShamirError),
    /// Verifier rejected the fold proof.
    VerificationFailed(alloc::string::String),
}

impl From<crate::fiat_shamir::errors::FiatShamirError> for QuasarFoldError {
    fn from(e: crate::fiat_shamir::errors::FiatShamirError) -> Self {
        Self::FiatShamir(e)
    }
}

impl<EF, F, H, C, Challenger, P, W, PW, Dft, const DIGEST_ELEMS: usize> FoldingScheme
    for QuasarFolding<EF, F, H, C, Challenger, P, W, PW, Dft, DIGEST_ELEMS>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Algebra<EF>,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, W, DIGEST_ELEMS>>
        + Clone,
    P: PackedValue<Value = F> + Eq + Send + Sync,
    W: PackedValue<Value = W> + Eq + Send + Sync + Copy + Default + core::fmt::Debug,
    PW: PackedValue<Value = W> + Eq + Send + Sync,
    H: CryptographicHasher<F, [W; DIGEST_ELEMS]>
        + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync
        + Clone,
    C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>
        + Sync
        + Clone,
    Dft: TwoAdicSubgroupDft<F> + Clone,
    [W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Accumulator = Accumulator<F, EF, W, DIGEST_ELEMS>;
    type AccumulatorInstance = AccumulatorInstance<F, EF, W, DIGEST_ELEMS>;
    type Fresh = FreshLinearInstance<F, EF>;
    type FoldProof = AccumulationProof<F, EF, W, DIGEST_ELEMS>;
    type Config = QuasarPipelineConfig<EF, F, H, C, Challenger>;
    type Error = QuasarFoldError;

    fn instance(accumulator: &Self::Accumulator) -> &Self::AccumulatorInstance {
        &accumulator.public_instance
    }

    fn init(config: &Self::Config) -> Self::Accumulator {
        // Quasar doesn't have a meaningful "empty" accumulator — the first fold
        // creates one from scratch. We return a dummy that will be replaced.
        let num_vars = config.whir_config.num_variables;
        Accumulator::new(
            AccumulatorInstance {
                commitment_root: unsafe { core::mem::zeroed() },
                linear_claim: crate::whir::constraints::statement::LinearStatement::initialize(
                    num_vars,
                ),
                _marker: PhantomData,
            },
            crate::accumulation::accumulator::AccumulatorWitness {
                poly: crate::poly::evals::EvaluationsList::new(
                    alloc::vec![F::ZERO; 1 << num_vars],
                ),
            },
        )
    }

    fn fold(
        _config: &Self::Config,
        _accumulator: &Self::Accumulator,
        _fresh: &[Self::Fresh],
    ) -> Result<(Self::Accumulator, Self::FoldProof), Self::Error> {
        if _fresh.is_empty() {
            return Err(QuasarFoldError::EmptyFresh);
        }

        // The full Quasar fold requires a live Challenger and DFT handle.
        // The trait-based interface provides a self-contained entry point;
        // callers needing the full WHIR-backed Quasar should use
        // `QuasarFrontendProver::squash_and_prove` directly and wrap the
        // result into `(Accumulator, AccumulationProof)`.
        //
        // This implementation is a placeholder that documents the mapping.
        // A complete version needs the DFT and Challenger to be part of Config
        // or supplied via a runtime context.
        Err(QuasarFoldError::VerificationFailed(
            alloc::string::String::from(
                "Quasar fold requires a live Challenger; use QuasarFrontendProver::squash_and_prove directly",
            ),
        ))
    }

    fn verify_fold(
        _config: &Self::Config,
        _prev_instance: &Self::AccumulatorInstance,
        _fresh: &[Self::Fresh],
        _proof: &Self::FoldProof,
    ) -> Result<Self::AccumulatorInstance, Self::Error> {
        // Quasar verification requires replaying the WHIR verifier.
        // The full implementation delegates to `QuasarFrontendVerifier::verify`.
        Err(QuasarFoldError::VerificationFailed(
            alloc::string::String::from(
                "Quasar verify requires a live Challenger; use QuasarFrontendVerifier::verify directly",
            ),
        ))
    }
}
