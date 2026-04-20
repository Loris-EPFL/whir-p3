//! Shared trait definitions for the whir-p3 workspace.
//!
//! This crate is the **leaf** of the dependency graph: every other crate in
//! the workspace may depend on it; it depends on nothing except Plonky3's
//! field + challenger layers and `serde`. Its purpose is to expose a small
//! set of narrow, Plonky3-style traits so that WARP, Quasar, Spartan, and
//! the terminal decider can be composed via generic bounds — not via
//! concrete function signatures or `Box<dyn …>`.
//!
//! # Why these traits
//!
//! - [`CommitmentRoot`] — a fingerprint of a committed polynomial. Used by
//!   every `ParsedCommitment`-flavoured type across the workspace.
//! - [`OodStatement`] — the list of out-of-domain / in-domain evaluation
//!   constraints that must be verified alongside a commitment. This is
//!   what binds the commitment root to the accumulator's claim (see the
//!   WARP paper's Construction 7.2 and `ParsedCommitment.ood_statement`
//!   in `whir-pcs`).
//! - [`ParsedCommitmentView`] — a commitment root + its statement bundled
//!   as a single value, mirroring Plonky3's `BatchOpening<T, M>` pattern.
//! - [`FoldingProver`] / [`FoldingVerifier`] — the prover-side and
//!   verifier-side interfaces of an accumulation fold step. Split so that
//!   in-circuit verifiers (which have no prover side) can implement just
//!   the verifier half.
//! - [`TerminalScheme`] — the prover-side and verifier-side interfaces
//!   for converting a final accumulator into a succinct proof.
//!
//! # Design principles
//!
//! Mirrored from Plonky3:
//!
//! 1. **Narrow, single-responsibility traits.** Every trait does one thing.
//! 2. **Generic composition.** Challenger, hash, DFT are method-level
//!    generics, not trait-level. Callers pick the concrete types.
//! 3. **No `Box<dyn …>`.** Everything is statically dispatched.
//! 4. **Verifier takes the public instance only.** The `verify` methods
//!    on `FoldingVerifier` and `TerminalScheme` deliberately consume a
//!    `public_instance` / `AccumulatorInstance`, not the full witness.

#![no_std]

pub mod accumulator;
pub mod folding;
pub mod parsed;
pub mod terminal;

pub use accumulator::CommitmentRoot;
pub use folding::{FoldingProver, FoldingVerifier};
pub use parsed::{OodStatement, ParsedCommitmentView};
pub use terminal::TerminalScheme;
