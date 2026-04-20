//! Terminal-scheme abstraction — converts a final accumulator into a
//! succinct proof.
//!
//! The terminal scheme is the "end of the chain": a standalone prover
//! that takes the accumulator produced by the last fold step and emits a
//! proof that the accumulator's public instance is satisfiable. The
//! verifier consumes only the public instance and the proof (never the
//! witness), so it is succinct.
//!
//! Concretely, the `AccumulationDecider` in `crates/accumulation/src/`
//! is the terminal scheme for Spartan-linearized accumulators, and WARP's
//! eval-fold pipeline has its own `EvalDecider` in
//! `crates/warp/src/eval_fold.rs`.
//!
//! # Type-parameter layout
//!
//! We follow the `p3_commit::Pcs<Challenge, Challenger>` pattern: the
//! `Challenger` is a **trait-level** generic, not method-level. Different
//! terminal schemes may need different challenger capabilities beyond the
//! common `FieldChallenger<F> + GrindingChallenger<Witness = F>` (for
//! example, Merkle-committed schemes need
//! `CanObserve<Hash<F, W, DIGEST_ELEMS>>`), and we express that by adding
//! extra where-clauses on the specific impl.
//!
//! Callers pick a concrete implementor; the implementor picks the concrete
//! challenger family it supports.

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field};

/// Prover + verifier for the terminal stage of an accumulation chain.
///
/// # Type parameters
///
/// * `F` — the base field of the accumulator.
/// * `EF` — the extension field the terminal proof operates over
///   (typically a degree-4 binomial extension for KoalaBear /
///   BabyBear).
/// * `Challenger` — the Fiat-Shamir challenger type. Carries any extra
///   capabilities (e.g. `CanObserve<Hash<…>>`) the implementor needs via
///   its own where-clauses.
///
/// # Associated types
///
/// * `Config` — protocol parameters (e.g. `WhirConfig`).
/// * `Accumulator` — the **prover-side** accumulator type, carrying the
///   witness.
/// * `AccumulatorInstance` — the **public** part of the accumulator, which
///   is the only thing `verify` is allowed to see.
/// * `TerminalProof` — the succinct proof.
/// * `Error` — a protocol-specific error.
pub trait TerminalScheme<F, EF, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    type Config;
    type Accumulator;
    type AccumulatorInstance;
    type TerminalProof;
    type Error: core::fmt::Debug;

    /// Produce a succinct proof from the accumulator.
    fn prove(
        config: &Self::Config,
        challenger: &mut Challenger,
        accumulator: &Self::Accumulator,
    ) -> Result<Self::TerminalProof, Self::Error>;

    /// Verify a succinct terminal proof against a public accumulator
    /// instance. Deliberately takes `&instance` (public) rather than
    /// `&accumulator` (which would include the witness) so that the
    /// signature enforces succinct-verifier semantics.
    fn verify(
        config: &Self::Config,
        challenger: &mut Challenger,
        instance: &Self::AccumulatorInstance,
        proof: &Self::TerminalProof,
    ) -> Result<(), Self::Error>;
}
