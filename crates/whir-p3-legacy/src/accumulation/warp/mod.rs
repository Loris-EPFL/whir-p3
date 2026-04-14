//! WARP-based fixed-size accumulation scheme.
//!
//! This module implements the WARP accumulation framework where the accumulator
//! size stays fixed regardless of the number of IVC steps. The key insight is
//! that the twin-constraint sumcheck *reduces* l instances to 1 (via
//! ProtoGalaxy-style folding) rather than concatenating them.
//!
//! Architecture (from WARP paper + EPFL implementation):
//!
//! ```text
//! AccumulatorInstance = (rt, alpha, mu, beta, eta)
//!   rt:    Merkle root of the codeword          [constant size]
//!   alpha: evaluation point (log_n elements)     [fixed size]
//!   mu:    evaluation claim (1 scalar)           [fixed size]
//!   beta:  PESAT constraint point (tau, x)       [fixed size]
//!   eta:   PESAT target (1 scalar)               [fixed size]
//!
//! AccumulatorWitness = (f, w)
//!   f:     codeword = encode(w)                  [fixed size n]
//!   w:     witness vector                        [fixed size k]
//! ```
//!
//! References:
//! - WARP paper: Bunz, Chiesa, Fenzi, Wang (2025) — eprint 2025/753
//! - EPFL implementation: github.com/compsec-epfl/warp
//! - ProtoGalaxy: Eagen, Gabizon (2024) — the fold primitive used inside the sumcheck

pub mod accumulator;
pub mod decider;
pub mod encoding;
pub mod eval_fold;
pub mod fold;
pub mod quasar_adapter;
pub mod twin_constraint;
