use p3_field::Field;

use crate::{
    axes::Axes,
    fixtures::{
        make_ds, make_whir_config, produce_synthetic_r1cs, seed_ch, spartan_linearize_all,
        LinearizedInstance, EF, F, DIGEST,
        MyHash, MyCompress, MyChallenger,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};
use whir_pcs::whir::{
    committer::{reader::CommitmentReader, writer::CommitmentWriter},
    constraints::statement::{EqStatement, InitialClaim},
    parameters::WhirConfig,
    proof::WhirProof,
    prover::Prover as WhirProver,
    verifier::Verifier as WhirVerifier,
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

#[derive(Debug)]
pub struct PlainWhir {
    config: WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    instances: Vec<LinearizedInstance>,
    witness_num_vars: usize,
    #[allow(dead_code)]
    shape: R1CSShape<F>,
    #[allow(dead_code)]
    instance: R1CSInstance<F>,
}

impl FoldingScheme for PlainWhir {
    const NAME: &'static str = "plain_whir";
    type Proof = Vec<WhirProof<F, EF, F, DIGEST>>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, _num_inputs, _log_code, _log_m) =
            produce_synthetic_r1cs(axes.log_n);
        let witness_num_vars = num_witness.trailing_zeros() as usize;
        let config = make_whir_config(witness_num_vars);
        let total_n = axes.ivc_steps * axes.batch;
        let (instances, _us) = spartan_linearize_all(&shape, &instance, total_n);
        Self {
            config,
            instances,
            witness_num_vars,
            shape,
            instance,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = crate::fixtures::make_dft();
        let ds = make_ds(&self.config);
        m.time("prove_total", || {
            self.instances
                .iter()
                .enumerate()
                .map(|(i, inst)| {
                    let mut stmt = self.config.initial_statement_with_linear(
                        inst.witness.clone(),
                        inst.linear.clone(),
                    );
                    let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(&self.config);
                    let mut ch = seed_ch(100 + i as u64, &ds);
                    let comm = CommitmentWriter::new(&self.config)
                        .commit::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                            &dft,
                            &mut proof,
                            &mut ch,
                            &mut stmt,
                        )
                        .unwrap();
                    WhirProver(&self.config)
                        .prove::<_, <F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                            &dft,
                            &mut proof,
                            &mut ch,
                            &stmt,
                            comm,
                        )
                        .unwrap();
                    proof
                })
                .collect()
        })
    }

    fn verify(&self, proofs: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        let ds = make_ds(&self.config);
        m.time("verify_total", || {
            for (i, proof) in proofs.iter().enumerate() {
                let initial_claim = InitialClaim {
                    eq_statement: EqStatement::initialize(self.witness_num_vars),
                    linear_statement: self.instances[i].linear.clone(),
                };
                let mut ch = seed_ch(100 + i as u64, &ds);
                let parsed = CommitmentReader::new(&self.config)
                    .parse_commitment::<F, DIGEST>(proof, &mut ch);
                WhirVerifier::new(&self.config)
                    .verify_with_initial_claim::<
                        <F as Field>::Packing,
                        F,
                        <F as Field>::Packing,
                        DIGEST,
                    >(proof, &mut ch, &parsed, initial_claim)
                    .unwrap();
            }
        });
        Ok(())
    }

    fn static_metrics(&self, proofs: &Self::Proof) -> StaticMetrics {
        let total_fe: u64 = proofs
            .iter()
            .map(|p| whir_proof_field_elements(p) as u64)
            .sum();
        StaticMetrics {
            proof_field_elems: total_fe,
            circuit_constraints: None,
        }
    }
}

pub(crate) fn whir_proof_field_elements_pub(proof: &WhirProof<F, EF, F, DIGEST>) -> usize {
    whir_proof_field_elements(proof)
}

fn whir_proof_field_elements(proof: &WhirProof<F, EF, F, DIGEST>) -> usize {
    let mut count = 0usize;
    count += DIGEST;
    count += proof.initial_ood_answers.len() * 4;
    count += proof.initial_sumcheck.polynomial_evaluations.len() * 2 * 4;
    count += proof.initial_sumcheck.pow_witnesses.len();
    for round in &proof.rounds {
        count += DIGEST;
        count += round.ood_answers.len() * 4;
        count += 1;
        for q in &round.queries {
            match q {
                whir_pcs::whir::proof::QueryOpening::Base { values, proof: p } => {
                    count += values.len();
                    count += p.len() * DIGEST;
                }
                whir_pcs::whir::proof::QueryOpening::Extension { values, proof: p } => {
                    count += values.len() * 4;
                    count += p.len() * DIGEST;
                }
            }
        }
        count += round.sumcheck.polynomial_evaluations.len() * 2 * 4;
        count += round.sumcheck.pow_witnesses.len();
    }
    if let Some(ref fp) = proof.final_poly {
        count += fp.num_evals() * 4;
    }
    count += 1;
    for q in &proof.final_queries {
        match q {
            whir_pcs::whir::proof::QueryOpening::Base { values, proof: p } => {
                count += values.len();
                count += p.len() * DIGEST;
            }
            whir_pcs::whir::proof::QueryOpening::Extension { values, proof: p } => {
                count += values.len() * 4;
                count += p.len() * DIGEST;
            }
        }
    }
    if let Some(ref fs) = proof.final_sumcheck {
        count += fs.polynomial_evaluations.len() * 2 * 4;
        count += fs.pow_witnesses.len();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_whir_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 1,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
        };
        let s = PlainWhir::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
