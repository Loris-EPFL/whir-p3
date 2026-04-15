use p3_field::{Field, PrimeCharacteristicRing};

use crate::{
    axes::Axes,
    fixtures::{
        make_hc, make_whir_config, make_zero_acc, produce_synthetic_r1cs, rebuild_acc,
        spartan_linearize_all, make_dft, make_ds, seed_ch,
        LinearizedInstance, EF, F, DIGEST, MyHash, MyCompress, MyChallenger, RS_LOG_INV_RATE,
    },
    metrics::{Metrics, StaticMetrics},
    scheme::FoldingScheme,
};
use warp::{
    accumulator::FreshInstance,
    encoding::merkle_commit_codeword,
    fold::{warp_fold_prove_rs_committed, RSEncodingConfig},
};
use whir_pcs::whir::{
    committer::{reader::CommitmentReader, writer::CommitmentWriter},
    constraints::statement::{EqStatement, InitialClaim, LinearStatement},
    parameters::WhirConfig,
    proof::WhirProof,
    prover::Prover as WhirProver,
    verifier::Verifier as WhirVerifier,
};
use whir_spartan::r1cs::{R1CSInstance, R1CSShape};

#[derive(Debug)]
pub struct WarpDirect {
    config: WhirConfig<EF, F, MyHash, MyCompress, MyChallenger>,
    instances: Vec<LinearizedInstance>,
    shape: R1CSShape<F>,
    #[allow(dead_code)]
    instance: R1CSInstance<F>,
    num_witness: usize,
    num_inputs: usize,
    log_code: usize,
    log_m: usize,
    witness_num_vars: usize,
    batch: usize,
    ivc_steps: usize,
}

impl FoldingScheme for WarpDirect {
    const NAME: &'static str = "warp_direct";
    type Proof = WhirProof<F, EF, F, DIGEST>;

    fn setup(axes: &Axes) -> Self {
        let (shape, instance, num_witness, num_inputs, log_code, log_m) =
            produce_synthetic_r1cs(axes.log_n);
        let witness_num_vars = num_witness.trailing_zeros() as usize;
        let config = make_whir_config(witness_num_vars);
        let total_n = axes.ivc_steps * axes.batch;
        let (instances, _us) = spartan_linearize_all(&shape, &instance, total_n);
        Self {
            config,
            instances,
            shape,
            instance,
            num_witness,
            num_inputs,
            log_code,
            log_m,
            witness_num_vars,
            batch: axes.batch,
            ivc_steps: axes.ivc_steps,
        }
    }

    fn prove(&self, m: &mut Metrics) -> Self::Proof {
        let dft = make_dft();
        let (mh, mc) = make_hc();
        let rs_config = RSEncodingConfig::new(2, RS_LOG_INV_RATE);
        let ds = make_ds(&self.config);

        let fresh_instances: Vec<FreshInstance<F>> = self
            .instances
            .iter()
            .map(|inst| {
                let z = inst.witness.as_slice();
                let pi = z[..self.num_inputs].to_vec();
                let mut w = z[self.num_inputs..].to_vec();
                w.resize(self.num_witness, F::ZERO);
                FreshInstance {
                    public_input: pi,
                    witness: w,
                }
            })
            .collect();

        let acc = m.time("prove_total", || {
            let mut acc = make_zero_acc(self.num_witness, self.log_code, self.log_m, self.num_inputs);
            for step in 0..self.ivc_steps {
                let idx = step * self.batch;
                let step_fresh: Vec<FreshInstance<F>> =
                    fresh_instances[idx..idx + self.batch].to_vec();
                let l = (1 + self.batch).next_power_of_two();
                let log_l = l.trailing_zeros() as usize;
                let tau: Vec<F> = (0..log_l)
                    .map(|i| F::from_u64(step as u64 * 10 + i as u64 + 42))
                    .collect();
                let mh2 = mh.clone();
                let mc2 = mc.clone();
                let mut ctr = step as u64 * 1000;
                let r = warp_fold_prove_rs_committed(
                    &self.shape,
                    &step_fresh,
                    &acc,
                    F::from_u64(7),
                    &tau,
                    &[],
                    &rs_config,
                    &dft,
                    |_| {
                        ctr += 1;
                        F::from_u64(ctr + 500)
                    },
                    |cw, ff| {
                        let (r, _) = merkle_commit_codeword::<
                            F,
                            F,
                            <F as Field>::Packing,
                            <F as Field>::Packing,
                            MyHash,
                            MyCompress,
                            DIGEST,
                        >(cw, ff, mh2.clone(), mc2.clone());
                        r
                    },
                );
                acc = rebuild_acc(&r);
            }
            acc
        });

        m.time("terminal_whir_prove", || {
            let mut wvec = acc.witness.witness.to_vec();
            wvec.resize(wvec.len().next_power_of_two(), F::ZERO);
            let wpoly = whir_core::poly::evals::EvaluationsList::new(wvec);
            let lc = LinearStatement::<F, EF>::initialize(self.witness_num_vars);
            let mut stmt = self.config.initial_statement_with_linear(wpoly, lc);
            let mut proof = WhirProof::<F, EF, F, DIGEST>::from_whir_config(&self.config);
            let mut ch = seed_ch(999, &ds);
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
            proof
        })
    }

    fn verify(&self, proof: &Self::Proof, m: &mut Metrics) -> anyhow::Result<()> {
        let ds = make_ds(&self.config);
        m.time("verify_total", || {
            let initial_claim = InitialClaim {
                eq_statement: EqStatement::initialize(self.witness_num_vars),
                linear_statement: LinearStatement::<F, EF>::initialize(self.witness_num_vars),
            };
            let mut ch = seed_ch(999, &ds);
            let parsed = CommitmentReader::new(&self.config)
                .parse_commitment::<F, DIGEST>(proof, &mut ch);
            WhirVerifier::new(&self.config)
                .verify_with_initial_claim::<<F as Field>::Packing, F, <F as Field>::Packing, DIGEST>(
                    proof, &mut ch, &parsed, initial_claim,
                )
                .unwrap();
        });
        Ok(())
    }

    fn static_metrics(&self, proof: &Self::Proof) -> StaticMetrics {
        StaticMetrics {
            proof_field_elems: super::plain_whir::whir_proof_field_elements_pub(proof) as u64,
            circuit_constraints: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warp_direct_prove_verify() {
        let axes = Axes {
            log_n: 10,
            arity: 2,
            batch: 1,
            ivc_steps: 2,
            step_muls: 100,
            seed: 42,
        };
        let s = WarpDirect::setup(&axes);
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        assert!(s.verify(&p, &mut m).is_ok());
    }
}
