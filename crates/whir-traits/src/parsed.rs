//! Out-of-domain / in-domain evaluation-statement abstractions, and the
//! `ParsedCommitmentView` wrapper that bundles a root with its statement.
//!
//! Mirrors `whir-pcs`'s existing `ParsedCommitment<F, D>` pattern but in a
//! trait form so that WARP folds (which also need to carry OOD + shift-query
//! data alongside a Merkle root) can implement the same interface.

use crate::accumulator::CommitmentRoot;

/// A set of evaluation constraints the verifier must carry alongside a
/// commitment. Each constraint asserts that the committed polynomial
/// evaluates to a known value at a known point.
///
/// The API mirrors `whir-pcs`'s `EqStatement`: `len` / `num_variables` for
/// shape queries, and `iter_constraints` for traversal. The trait is not
/// object-safe (the iterator uses return-position `impl Iterator`); all
/// uses should be via generic bounds.
pub trait OodStatement<F: Clone> {
    /// Number of `(point, value)` constraints.
    fn len(&self) -> usize;

    /// Convenience: is the statement empty?
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of variables the committed polynomial depends on. Every
    /// point yielded by [`Self::iter_constraints`] must have exactly
    /// this length.
    fn num_variables(&self) -> usize;

    /// Iterate `(point, value)` pairs. Point lifetimes are bounded by
    /// `&self`; values are returned by owned copy (`F: Clone`).
    fn iter_constraints<'a>(&'a self) -> impl Iterator<Item = (&'a [F], F)> + 'a
    where
        F: 'a;
}

/// A commitment root + its associated evaluation statement, bundled as a
/// single value.
///
/// This is the workspace-wide generalisation of
/// `whir_pcs::whir::committer::reader::ParsedCommitment<F, D>`. A fold
/// verifier that needs access to both the codeword commitment and the
/// OOD/shift-query data stored alongside it should take
/// `&impl ParsedCommitmentView<F>` rather than the concrete type, so that
/// the WHIR parsed commitment and a future WARP parsed-fold-commitment
/// can both be plugged in.
pub trait ParsedCommitmentView<F: Clone> {
    /// The commitment-root type (usually `[W; DIGEST_ELEMS]` or
    /// `p3_symmetric::Hash<F, W, N>`).
    type Root: CommitmentRoot;

    /// The evaluation statement type (usually a collection of
    /// `(MultilinearPoint, value)` pairs).
    type Statement: OodStatement<F>;

    /// The commitment root this view wraps.
    fn root(&self) -> &Self::Root;

    /// The evaluation statement derived from the commitment (OOD points,
    /// in-domain shift-query points, etc).
    fn ood_statement(&self) -> &Self::Statement;
}
