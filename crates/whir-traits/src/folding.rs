//! Folding-step abstractions — the prover-side and verifier-side
//! interfaces of a single accumulation fold step.
//!
//! See the crate root for design rationale. In short:
//!   - `FoldingProver::prove` consumes a previous accumulator + fresh
//!     instances, produces a new accumulator + a fold proof.
//!   - `FoldingVerifier::verify` consumes a previous **public instance**
//!     + a fold proof and re-derives the new public instance. It does
//!     not (and cannot) touch the witness — the verifier is succinct by
//!     construction.
//!
//! Both interfaces carry `Challenger` as a trait-level generic (same
//! pattern as `p3_commit::Pcs<Challenge, Challenger>` and as
//! [`crate::terminal::TerminalScheme`]) so that implementors can tighten
//! the challenger bound in their where-clauses — for example requiring
//! `CanObserve<Hash<F, W, DIGEST_ELEMS>>` for Merkle-based implementations
//! — without leaking protocol-specific types into the trait itself.

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::Field;

/// Prover-side interface of a single accumulation fold step.
pub trait FoldingProver<F, Challenger>
where
    F: Field,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    type Config;
    type Witness;
    type Accumulator;
    type FoldProof;
    type Error: core::fmt::Debug;

    /// Fold a slice of fresh instances into the given accumulator.
    fn prove(
        config: &Self::Config,
        challenger: &mut Challenger,
        accumulator: &Self::Accumulator,
        fresh: &[Self::Witness],
    ) -> Result<(Self::Accumulator, Self::FoldProof), Self::Error>;
}

/// Verifier-side interface of a single accumulation fold step.
///
/// Split from [`FoldingProver`] so that in-circuit verifiers (which have
/// no `prove` side — they're embedded in an R1CS circuit) can implement
/// just the verifier half.
pub trait FoldingVerifier<F, Challenger>
where
    F: Field,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    type Config;
    type AccumulatorInstance;
    type FoldProof;
    type Error: core::fmt::Debug;

    /// Verify a fold proof and return the new public accumulator instance.
    fn verify(
        config: &Self::Config,
        challenger: &mut Challenger,
        prev_instance: &Self::AccumulatorInstance,
        proof: &Self::FoldProof,
    ) -> Result<Self::AccumulatorInstance, Self::Error>;
}
