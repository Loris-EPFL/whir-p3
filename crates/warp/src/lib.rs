//! WARP-based fixed-size accumulation scheme.

#![no_std]
extern crate alloc;

pub use accumulation;
pub use whir_core::{constant, parameters, poly, utils};
pub use whir_pcs::{fiat_shamir, sumcheck, whir};
pub use whir_spartan as spartan;

pub mod accumulator;
pub mod decider;
pub mod encoding;
pub mod eval_fold;
pub mod fold;
pub mod quasar_adapter;
pub mod quasar_multicast;
pub mod twin_constraint;
