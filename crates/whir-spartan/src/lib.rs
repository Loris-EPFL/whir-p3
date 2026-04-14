//! Spartan R1CS Arithmetization and SPARK Integration
//!
//! Spartan's R1CS encoding and SPARK compiler for efficient polynomial
//! commitments of sparse matrices.

#![no_std]
extern crate alloc;

// Facade re-exports so `crate::poly`, `crate::parameters`, `crate::whir`,
// `crate::fiat_shamir` keep resolving inside this crate's code.
// NOTE: spartan has its own `sumcheck` submodule, so we do NOT re-export whir_pcs::sumcheck.
pub use whir_core::{constant, parameters, poly, utils};
pub use whir_pcs::{fiat_shamir, whir};

pub mod encoding;
pub mod prelude;
pub mod r1cs;
pub mod r1cs_prover;
pub mod spark;
pub mod sumcheck;

#[cfg(test)]
pub mod tests;

pub use encoding::eq_poly_at_index;
pub use r1cs::{R1CSInstance, R1CSShape, SparseMatEntry};
pub use r1cs_prover::{R1CSProof, R1CSProver, R1CSVerifier};
