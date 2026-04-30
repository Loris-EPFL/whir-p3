use crate::{
    axes::Axes,
    metrics::{Metrics, StaticMetrics},
};

pub trait FoldingScheme {
    const NAME: &'static str;
    type Proof;
    fn setup(axes: &Axes) -> Self
    where
        Self: Sized;
    fn prove(&self, m: &mut Metrics) -> Self::Proof;
    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()>;
    fn static_metrics(&self, proof: &Self::Proof) -> StaticMetrics;
}
