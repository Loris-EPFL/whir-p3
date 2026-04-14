//! Quasar linearized accumulation scheme.

#![no_std]
extern crate alloc;

pub use accumulation;
pub use whir_core::{constant, parameters, poly, utils};
pub use whir_pcs::{fiat_shamir, sumcheck, whir};
pub use whir_spartan as spartan;

pub mod fresh;
pub mod frontend;

pub use fresh::{FreshLinearInstance, FreshLinearInstancePublic};
pub use frontend::{QuasarFrontendOutput, QuasarFrontendProver, QuasarFrontendVerifier};
