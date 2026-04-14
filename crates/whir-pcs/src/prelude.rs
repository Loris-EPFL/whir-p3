//! Common re-exports for WHIR PCS users.

pub use whir_core::prelude::*;

pub use crate::{
    fiat_shamir::domain_separator::DomainSeparator,
    whir::{parameters::WhirConfig, proof::WhirProof},
};
