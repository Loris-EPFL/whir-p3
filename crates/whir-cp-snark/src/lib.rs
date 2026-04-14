//! CP-SNARK compiler using Symphony's commitment-based approach.

#![no_std]
extern crate alloc;

pub use accumulation;
pub use warp;
pub use whir_core::{constant, parameters, poly, utils};
pub use whir_pcs::{fiat_shamir, sumcheck, whir};
pub use whir_spartan as spartan;

mod compiler;
pub use compiler::{
    CommittedFoldTranscript, CpSnarkDeciderError, FoldTranscriptData, WarpFoldRelation,
    commit_fold_transcript_with_shift_queries, cp_snark_terminal_verify,
    cp_snark_terminal_verify_with_merkle, cp_snark_terminal_verify_with_whir,
    serialize_fold_data, verify_committed_transcripts, verify_shift_query_merkle_proofs,
};
