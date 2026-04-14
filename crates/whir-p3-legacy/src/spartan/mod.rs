//! Spartan R1CS Arithmetization and SPARK Integration
//!
//! This module implements Spartan's R1CS encoding and SPARK compiler
//! for efficient polynomial commitments of sparse matrices.
//!
//! Based on:
//! - "Spartan: Efficient and general-purpose zkSNARKs without trusted setup"
//!   by Srinath Setty (Microsoft Research)
//! - Section 4: R1CS to degree-3 polynomial encoding
//! - Section 7: SPARK compiler for sparse multilinear polynomials

pub mod encoding;
pub mod r1cs;
pub mod r1cs_prover;
pub mod spark;
pub mod sumcheck;

#[cfg(test)]
pub mod tests;

pub use encoding::*;
pub use r1cs::*;
pub use r1cs_prover::*;
pub use spark::*;
