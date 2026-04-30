//! Family A (no step circuit): N × independent WHIR proofs.
//!
//! Baseline for the "prove N R1CS instances" question. No accumulation — each
//! instance gets its own succinct WHIR proof. The verifier checks N proofs.
//!
//! Total instances processed = `ivc_steps * batch` (mirrors compare_bench
//! Path 1's `N = steps × batch`).

use p3_field::{Field, PrimeCharacteristicRing};
use whir_core::poly::evals::EvaluationsList;
use whir_pcs::whir::{
    committer::{reader::CommitmentReader, writer::CommitmentWriter},
    constraints::statement::{EqStatement, InitialClaim, LinearStatement},
    parameters::WhirConfig,
    proof::WhirProof,
    prover::Prover as WhirProver,
    verifier::Verifier as WhirVerifier,
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

use crate::{
    axes::Axes,
    fixtures::{
        DIGEST, EF, F, MyChallenger, MyCompress, MyHash, make_ds, make_whir_config,
        produce_synthetic_r1cs, seed_ch, spartan_linearize_all, whir_proof_field_elements,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};

#[derive(Debug)]
pub struct IndependentWhir {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    config: WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    witness_num_vars: usize,
    total_n: usize,
}

#[derive(Debug)]
pub struct IndependentWhirProof {
    proofs: Vec<WhirProof<F, EF, F, DIGEST>>,
    linears: Vec<LinearStatement<F, EF>>,
}

impl FoldingScheme for IndependentWhir {
    const NAME: &'static str = "independent_whir";
    type Proof = IndependentWhirProof;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, _, _, _) = produce_synthetic_r1cs(axes.log_n);
        let witness_num_vars = num_witness.trailing_zeros() as usize;
        let config = make_whir_config(witness_num_vars);
        let total_n = axes
            .total_instances
            .unwrap_or_else(|| axes.ivc_steps.saturating_mul(axes.batch.max(1)))
            .max(1);
        Self {
            shape,
            instance,
            config,
            witness_num_vars,
            total_n,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();

        let (instances, spartan_us) =
            spartan_linearize_all(&self.shape, &self.instance, self.total_n);
        m.record("spartan", (spartan_us * 1000.0) as u128);

        let proofs = m.time("prove_total", || {
            let ds = make_ds(&self.config);
            let mut proofs = Vec::with_capacity(self.total_n);
            for (i, inst) in instances.iter().enumerate() {
                // Pad witness to power-of-two for WHIR.
                let mut wvec = inst.witness.as_slice().to_vec();
                wvec.resize(wvec.len().next_power_of_two(), F::ZERO);
                let wpoly = EvaluationsList::new(wvec);
                let mut stmt = self
                    .config
                    .initial_statement_with_linear(wpoly, inst.linear.clone());
                let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(&self.config);
                let mut ch = seed_ch(100 + i as u64, &ds);
                let comm = CommitmentWriter::new(&self.config)
                    .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                        &dft, &mut proof, &mut ch, &mut stmt,
                    )
                    .unwrap();
                WhirProver(&self.config)
                    .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                        &dft, &mut proof, &mut ch, &stmt, comm,
                    )
                    .unwrap();
                proofs.push(proof);
            }
            proofs
        });

        m.count("total_instances", self.total_n as u64);
        m.count("target_total_instances", self.total_n as u64);
        m.count("family_a", 1);

        let linears = instances.into_iter().map(|li| li.linear).collect();
        IndependentWhirProof { proofs, linears }
    }

    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        m.time("verify_total", || {
            let ds = make_ds(&self.config);
            for (i, (p, lin)) in proof.proofs.iter().zip(proof.linears.iter()).enumerate() {
                let initial_claim = InitialClaim {
                    eq_statement: EqStatement::initialize(self.witness_num_vars),
                    linear_statement: lin.clone(),
                };
                let mut ch = seed_ch(100 + i as u64, &ds);
                let parsed = CommitmentReader::new(&self.config)
                    .parse_commitment::<F, DIGEST>(p, &mut ch);
                WhirVerifier::new(&self.config)
                    .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                        p, &mut ch, &parsed, initial_claim,
                    )
                    .map_err(|e| anyhow::anyhow!("proof {i} verify failed: {e:?}"))?;
            }
            Ok::<(), anyhow::Error>(())
        })
    }

    fn static_metrics(&self, proof: &Self::Proof) -> StaticMetrics {
        let per = proof.proofs.first().map_or(0, whir_proof_field_elements);
        StaticMetrics {
            proof_field_elems: per * self.total_n as u64,
            circuit_constraints: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_whir_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 2,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
            total_instances: None,
            total_step_circuits: None,
        };
        let s = IndependentWhir::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        let r = s.verify(&p, &mut m);
        assert!(r.is_ok(), "verify failed: {r:?}");
    }
}
