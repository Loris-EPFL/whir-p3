//! Partial VEIL: query/proximity shielding for the terminal WHIR decider.
//!
//! **Phase 1 only. This is NOT full ZK.**
//!
//! What Phase 1 provides:
//! - ZK-code padding: each witness row polynomial is extended with k random
//!   field elements before RS encoding, hiding row openings from the verifier.
//! - Blinding row: an extra uniformly random row polynomial is added so the
//!   verifier's random linear combination hits a masked codeword.
//! - Proximity-mask infrastructure: the combined polynomial g (RLC of witness
//!   row prefixes) and its padding suffix g₁ are computed.
//!
//! What Phase 1 does NOT provide:
//! - Transcript masking: the sumcheck round polynomials and OOD answers are
//!   still sent in the clear. A motivated verifier can extract witness
//!   information from the algebraic transcript.
//! - Virtual oracle integration: the existing WHIR prover/verifier is NOT
//!   modified to query C_ρ (the masked combined oracle). The inner WHIR in
//!   VeilDecider runs on g directly via a separate commitment. Proper
//!   C_ρ-based query resolution requires changes to the WHIR query-opening
//!   layer (Phase 1.5).
//!
//! The legacy `AccumulationDecider` path is completely unaffected.
//! Enable with `--features veil`.

pub mod decider_adapter;
pub mod proximity_mask;
pub mod zk_code;

use thiserror::Error;

/// Configuration for partial VEIL (Phase 1: query + proximity shielding).
#[derive(Clone, Debug)]
pub struct VeilConfig {
    /// ZK-code padding k.
    ///
    /// Number of random field elements appended to each witness row polynomial
    /// before RS encoding. Must be >= the query complexity of the initial WHIR
    /// commitment (i.e., `round_parameters[0].num_queries`).
    ///
    /// Typical value: 128 (matches 100-bit security query count with margin).
    pub zk_padding: usize,

    /// Log stacking height p.
    ///
    /// The 2^n-evaluation polynomial is split into 2^p "row polynomials" each
    /// of length 2^(n-p). Must equal `whir_config.folding_factor.at_round(0)`
    /// to align with the WHIR commitment matrix structure.
    ///
    /// If this does not match the WHIR folding factor, the ZK-code padding
    /// does not align with the actual query structure. This is the highest-risk
    /// configuration error in Phase 1 — validate before use.
    pub log_stacking_height: usize,

    /// Log of the inverse RS code rate used for encoding each padded row.
    ///
    /// Should match `whir_config.starting_log_inv_rate` for consistency.
    pub log_inv_rate: usize,
}

impl VeilConfig {
    /// Validate that k covers the actual query complexity.
    ///
    /// `initial_num_queries` should be `whir_config.round_parameters[0].num_queries`.
    pub fn validate(&self, initial_num_queries: usize) -> Result<(), VeilError> {
        if self.zk_padding < initial_num_queries {
            return Err(VeilError::InsufficientPadding {
                required: initial_num_queries,
                provided: self.zk_padding,
            });
        }
        Ok(())
    }

    /// Total rows in the padded matrix: 2^p + 1 (witness rows + blinding row).
    pub fn num_rows(&self) -> usize {
        (1 << self.log_stacking_height) + 1
    }

    /// Expected witness row length (= 2^(n-p) where n = num_variables).
    pub fn witness_row_len(&self, num_variables: usize) -> usize {
        1 << (num_variables - self.log_stacking_height)
    }
}

#[derive(Debug, Error)]
pub enum VeilError {
    #[error("zk_padding ({provided}) < required query complexity ({required}); ZK property not guaranteed")]
    InsufficientPadding { required: usize, provided: usize },

    #[error("log_stacking_height mismatch: VeilConfig has {veil_p}, WHIR folding_factor_round0 is {whir_ff}")]
    StackingHeightMismatch { veil_p: usize, whir_ff: usize },

    #[error("num_variables ({num_variables}) must be > log_stacking_height ({p})")]
    TooFewVariables { num_variables: usize, p: usize },

    #[error("blinding coefficient is zero; abort (zk-PG must be supported on F^× in last coordinate)")]
    ZeroBlinderCoeff,

    #[error("base WHIR error: {0}")]
    BaseWhir(#[from] crate::fiat_shamir::errors::FiatShamirError),
}
