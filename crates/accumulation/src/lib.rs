//! Shared accumulation types and algorithms.

#![no_std]
extern crate alloc;

pub use whir_core::{constant, parameters, poly, utils};
pub use whir_pcs::{fiat_shamir, sumcheck, whir};
pub use whir_spartan as spartan;

pub mod accumulator;
pub mod compact_instance;
pub mod constraint_batch;
pub mod decider;
pub mod linearized;
pub mod pipeline;
pub mod prelude;
pub mod proof;
pub mod random_lc;
pub mod scheme;
pub mod union_poly;
