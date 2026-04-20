//! Microbench implementations — modular port of compare_bench.rs's
//! six specialised measurements. See crate::microbench for the trait.

pub mod circuit_size_arity;
pub mod circuit_sizes_l2;
pub mod fold_verifier;
pub mod fs_scaling;
pub mod terminal_whir;
pub mod whir_in_circuit_estimate;
