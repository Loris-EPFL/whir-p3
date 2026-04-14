#![no_std]
extern crate alloc;

#[cfg(feature = "bench-timing")]
extern crate std;

// Foundation re-exports — keep `use crate::{poly, parameters, constant, utils}` working.
pub use whir_core::{constant, parameters, poly, utils};

pub mod fiat_shamir;
pub mod prelude;
pub mod sumcheck;
pub mod whir;
