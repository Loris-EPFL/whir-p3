//! Incrementally Verifiable Computation (IVC) using WARP/Linearized accumulation.

#![no_std]
extern crate alloc;
extern crate self as ivc;

pub use accumulation;
pub use warp;
#[cfg(feature = "symphony")]
pub use whir_cp_snark as cp_snark;
pub use whir_circuit as circuit;
pub use whir_core::{constant, parameters, poly, utils};
pub use whir_pcs::{fiat_shamir, sumcheck, whir};
pub use whir_spartan as spartan;

pub mod eval_fold_verifier_circuit;
pub mod linearized_ivc;
pub mod prelude;
pub mod step;
pub mod verifier_circuit;
pub mod warp_fold_verifier_algebraic;
pub mod warp_fold_verifier_circuit;
pub mod warp_ivc;
