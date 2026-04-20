//! Commitment-root abstraction.

/// A commitment root: a small, publicly-checkable fingerprint of a
/// committed polynomial. Typically a Merkle-tree root (fixed-size
/// cryptographic digest) but could in principle be any succinct binding.
///
/// The trait is intentionally minimal: implementors must be cloneable,
/// comparable for equality, formattable for debugging, and safe to move
/// across threads. All concrete digest types used in the workspace —
/// `[W; DIGEST_ELEMS]` arrays and `p3_symmetric::Hash<F, W, N>` — satisfy
/// this automatically via the blanket impl below.
pub trait CommitmentRoot: Clone + Eq + core::fmt::Debug + Send + Sync {}

// ──────────────────────────────────────────────────────────────────────────
// Blanket impl for fixed-size arrays.
//
// Every Merkle digest in this workspace is stored as `[W; DIGEST_ELEMS]`
// (see e.g. `accumulation::accumulator::AccumulatorInstance.commitment_root`
// and `warp::accumulator::WarpAccumulatorInstance.commitment_root`). This
// impl lets those arrays satisfy the `CommitmentRoot` bound without any
// per-crate boilerplate.
// ──────────────────────────────────────────────────────────────────────────

impl<T, const N: usize> CommitmentRoot for [T; N]
where
    T: Clone + Eq + core::fmt::Debug + Send + Sync + 'static,
{
}

// ──────────────────────────────────────────────────────────────────────────
// Blanket impl for Plonky3's `Hash<F, W, N>` newtype.
//
// Every `ParsedCommitment` in `whir-pcs` uses `p3_symmetric::Hash<F, W, N>`
// as its root type (see `CommitmentReader::parse_commitment`). We impl
// `CommitmentRoot` here rather than in `whir-pcs` because `Hash` is a
// foreign type and so is this trait from the point of view of any
// downstream crate — only `whir-traits` can coherence-satisfy the impl.
// ──────────────────────────────────────────────────────────────────────────

impl<F, W, const N: usize> CommitmentRoot for p3_symmetric::Hash<F, W, N>
where
    F: Clone + Eq + core::fmt::Debug + Send + Sync + 'static,
    W: Clone + Eq + core::fmt::Debug + Send + Sync + 'static,
{
}
