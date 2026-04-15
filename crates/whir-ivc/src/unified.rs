//! Unified IVC pipeline: compose any [`FoldingScheme`] with any compatible
//! [`TerminalScheme`] to get a complete prove/verify flow.
//!
//! This module re-exports the generic pipeline from `zkp-pipeline-traits` and
//! provides concrete type aliases for the supported combinations:
//!
//! - `WarpWhirIVC`: WARP folding + WHIR algebraic terminal
//! - `WarpCpSnarkIVC`: WARP folding + CP-SNARK terminal (requires `cp-snark` feature)
//!
//! # Example
//!
//! ```ignore
//! use whir_p3::ivc::unified::*;
//!
//! // Configure
//! let pipeline = IVCPipeline::<WarpFolding<F>, WhirTerminalWarp<F>>::new(
//!     fold_config, terminal_config,
//! );
//!
//! // Run IVC
//! let mut state = pipeline.init();
//! for instance in fresh_instances {
//!     pipeline.step(&mut state, &[instance])?;
//! }
//!
//! // Finalize
//! let proof = pipeline.finalize(&state)?;
//! let instance = WarpFolding::<F>::instance(&state.accumulator);
//! pipeline.verify(instance, &proof)?;
//! ```

// Re-export the generic pipeline types from the traits crate.
pub use zkp_pipeline_traits::{
    folding::FoldingScheme,
    pipeline::{IVCPipeline, IVCState, PipelineError},
    terminal::TerminalScheme,
};

// Re-export concrete folding schemes.
pub use warp::scheme::{WarpFolding, WarpFoldError, WarpPipelineConfig};
pub use quasar::scheme::{QuasarFolding, QuasarFoldError, QuasarPipelineConfig};

// Re-export concrete terminal schemes.
pub use warp::terminal_whir::{
    WhirTerminalWarp, WhirTerminalWarpConfig, WhirTerminalWarpProof,
};

// Re-export CP-SNARK terminal when available.
#[cfg(any(feature = "symphony", feature = "cp-snark"))]
pub use crate::cp_snark::terminal::{
    CpSnarkAccumulator, CpSnarkTerminal, CpSnarkTerminalConfig, CpSnarkTerminalProof,
};

// ── Concrete pipeline type aliases ───────────────────────────────────

use p3_field::{Field, PrimeField64, TwoAdicField};

/// WARP folding + WHIR algebraic terminal decider.
///
/// The standard pipeline: fixed-size accumulators with Merkle commitment,
/// twin-constraint sumcheck folding, and algebraic eval+PESAT terminal check.
pub type WarpWhirPipeline<F> = IVCPipeline<
    WarpFolding<F>,
    WhirTerminalWarp<F>,
>;

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::vec;

    use p3_koala_bear::KoalaBear;
    use p3_field::PrimeCharacteristicRing;

    use crate::{
        spartan::r1cs::R1CSShape,
    };
    use warp::{
        accumulator::FreshInstance,
        fold::WarpFoldConfig,
    };

    type F = KoalaBear;

    /// Build a trivial R1CS: a single constraint 0 * 0 = 0 with 2 vars, 1 input.
    fn trivial_shape() -> R1CSShape<F> {
        R1CSShape::new(1, 2, 1, vec![], vec![], vec![])
    }

    #[test]
    fn warp_whir_pipeline_init_step_finalize() {
        let shape = trivial_shape();
        let log_code_len = 2; // code_len = 4

        let fold_config = WarpPipelineConfig {
            shape: shape.clone(),
            rs_config: None,
            fold_config: WarpFoldConfig::default(),
            log_code_len,
            num_public_inputs: 1,
        };

        let terminal_config = WhirTerminalWarpConfig {
            shape: shape.clone(),
        };

        let pipeline = WarpWhirPipeline::<F>::new(fold_config, terminal_config);

        // Init
        let mut state = pipeline.init();
        assert_eq!(state.step, 0);

        // Step with a fresh instance
        let fresh = FreshInstance {
            public_input: vec![F::ZERO],
            witness: vec![F::ZERO; 2],
        };
        let result = pipeline.step(&mut state, &[fresh]);
        assert!(result.is_ok(), "fold step should succeed");
        assert_eq!(state.step, 1);

        // Finalize (algebraic decider)
        let proof = pipeline.finalize(&state);
        assert!(proof.is_ok(), "terminal proof should succeed");

        // Verify
        let instance = WarpFolding::<F>::instance(&state.accumulator);
        let result = pipeline.verify(instance, &proof.unwrap());
        assert!(result.is_ok(), "terminal verify should succeed");
    }

    #[test]
    fn warp_whir_pipeline_multi_step() {
        let shape = trivial_shape();

        let fold_config = WarpPipelineConfig {
            shape: shape.clone(),
            rs_config: None,
            fold_config: WarpFoldConfig::default(),
            log_code_len: 2,
            num_public_inputs: 1,
        };

        let terminal_config = WhirTerminalWarpConfig {
            shape: shape.clone(),
        };

        let pipeline = WarpWhirPipeline::<F>::new(fold_config, terminal_config);
        let mut state = pipeline.init();

        // Run 4 IVC steps
        for _ in 0..4 {
            let fresh = FreshInstance {
                public_input: vec![F::ZERO],
                witness: vec![F::ZERO; 2],
            };
            pipeline.step(&mut state, &[fresh]).unwrap();
        }

        assert_eq!(state.step, 4);
        assert_eq!(state.fold_proofs.len(), 4);

        // Finalize
        let proof = pipeline.finalize(&state).unwrap();
        let instance = WarpFolding::<F>::instance(&state.accumulator);
        assert!(pipeline.verify(instance, &proof).is_ok());
    }
}
