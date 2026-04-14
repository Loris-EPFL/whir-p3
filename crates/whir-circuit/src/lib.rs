//! R1CS circuit builder + gadgets (Poseidon2 sponge, extension field arithmetic).

#![no_std]
extern crate alloc;

pub use whir_core::{constant, parameters, poly, utils};
pub use whir_pcs::{fiat_shamir, sumcheck, whir};
pub use whir_spartan as spartan;

pub mod bits;
pub mod builder;
pub mod prelude;
pub mod ext_field;
pub mod poseidon2;
pub mod sponge;
