use warp::accumulator::WarpAccumulator;
use whir_ivc::warp_ivc::WarpIVCState;
use whir_pcs::whir::proof::WhirProof;

use crate::{
    axes::Axes,
    fixtures::{
        DIGEST, EF, F, make_whir_config, terminal_whir_prove_measured,
        terminal_whir_verify_bound_measured, whir_proof_field_elements,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

pub trait WarpTerminalState {
    fn accumulator(&self) -> &WarpAccumulator<F, F, F, DIGEST>;
}

impl WarpTerminalState for WarpIVCState<F> {
    fn accumulator(&self) -> &WarpAccumulator<F, F, F, DIGEST> {
        &self.accumulator
    }
}

#[cfg(feature = "symphony")]
impl WarpTerminalState for whir_ivc::warp_ivc::WarpIVCStateCp<F> {
    fn accumulator(&self) -> &WarpAccumulator<F, F, F, DIGEST> {
        &self.accumulator
    }
}

#[derive(Debug)]
pub struct TerminalWhirProof<P> {
    pub inner: P,
    terminal_whir: WhirProof<F, EF, F, DIGEST>,
    witness_num_vars: usize,
}

fn witness_num_vars(acc: &WarpAccumulator<F, F, F, DIGEST>) -> usize {
    acc.witness
        .witness
        .len()
        .next_power_of_two()
        .trailing_zeros() as usize
}

macro_rules! define_terminal_whir_scheme {
    ($name:ident, $inner:ty, $label:literal) => {
        #[derive(Debug)]
        pub struct $name {
            inner: $inner,
        }

        impl FoldingScheme for $name
        where
            $inner: FoldingScheme,
            <$inner as FoldingScheme>::Proof: WarpTerminalState,
        {
            const NAME: &'static str = $label;
            type Proof = TerminalWhirProof<<$inner as FoldingScheme>::Proof>;

            fn setup(axes: &Axes) -> Self {
                Self {
                    inner: <$inner as FoldingScheme>::setup(axes),
                }
            }

            fn prove(&self, m: &mut Metrics) -> Self::Proof {
                let inner = self.inner.prove(m);
                let acc = inner.accumulator();
                let witness_num_vars = witness_num_vars(acc);
                let whir_config = make_whir_config(witness_num_vars);
                let terminal_whir = terminal_whir_prove_measured(
                    m,
                    &whir_config,
                    &acc.witness.witness,
                    witness_num_vars,
                );
                m.count("terminal_whir_proofs", 1);
                TerminalWhirProof {
                    inner,
                    terminal_whir,
                    witness_num_vars,
                }
            }

            fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
                self.inner.verify(&proof.inner, m)?;
                let whir_config = make_whir_config(proof.witness_num_vars);
                terminal_whir_verify_bound_measured(
                    m,
                    &whir_config,
                    &proof.terminal_whir,
                    proof.witness_num_vars,
                    proof.inner.accumulator().instance.commitment_root,
                )
            }

            fn static_metrics(&self, proof: &Self::Proof) -> StaticMetrics {
                let mut metrics = self.inner.static_metrics(&proof.inner);
                metrics.proof_field_elems = metrics
                    .proof_field_elems
                    .saturating_add(whir_proof_field_elements(&proof.terminal_whir));
                metrics
            }
        }
    };
}

define_terminal_whir_scheme!(
    PureWarpSuccinct,
    crate::schemes::PureWarp,
    "pure_warp_succinct"
);
define_terminal_whir_scheme!(
    WarpStandardSuccinct,
    crate::schemes::WarpStandard,
    "warp_standard_succinct"
);
define_terminal_whir_scheme!(
    WarpUnionSuccinct,
    crate::schemes::WarpUnion,
    "warp_union_succinct"
);
define_terminal_whir_scheme!(
    WarpRecursiveStandardSuccinct,
    crate::schemes::WarpRecursiveStandard,
    "warp_recursive_standard_succinct"
);
define_terminal_whir_scheme!(
    WarpRecursiveStandardAritySuccinct,
    crate::schemes::WarpRecursiveStandardArity,
    "warp_recursive_standard_arity_succinct"
);
define_terminal_whir_scheme!(
    QuasarWarpSuccinct,
    crate::schemes::QuasarWarp,
    "quasar_warp_succinct"
);

#[cfg(feature = "symphony")]
define_terminal_whir_scheme!(
    SymphonySuccinct,
    crate::schemes::Symphony,
    "symphony_succinct"
);

#[cfg(feature = "symphony")]
define_terminal_whir_scheme!(
    SymphonyStandardAritySuccinct,
    crate::schemes::SymphonyStandardArity,
    "symphony_standard_arity_succinct"
);

#[cfg(feature = "symphony")]
define_terminal_whir_scheme!(
    QuasarSymphonySuccinct,
    crate::schemes::QuasarSymphony,
    "quasar_symphony_succinct"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_warp_succinct_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 2,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
            total_instances: Some(4),
            total_step_circuits: None,
        };
        let s = PureWarpSuccinct::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
        assert!(m.phases.contains_key("terminal_whir_prove"));
        assert!(m.phases.contains_key("terminal_whir_verify"));
        assert!(m.phases.contains_key("terminal_decider"));
    }
}
