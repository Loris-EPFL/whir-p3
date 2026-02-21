use std::collections::BTreeSet;
use std::fs::{create_dir_all, File};
use std::hint::black_box;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use p3_challenger::DuplexChallenger;
use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
use rand::SeedableRng;
use whir_p3::spartan::{R1CSInstance, R1CSProver, R1CSShape, R1CSVerifier, SparseMatEntry};

const TRANSCRIPT_BASE_BYTES: usize = 128;
const PER_QUERY_TRANSCRIPT_BYTES: usize = 16;

#[derive(Clone, Copy)]
enum ShapeKind {
    Square,
    Tall,
    Wide,
}

impl ShapeKind {
    fn all() -> [Self; 3] {
        [Self::Square, Self::Tall, Self::Wide]
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Square => "square",
            Self::Tall => "tall",
            Self::Wide => "wide",
        }
    }

    fn num_vars(self, num_cons: usize) -> usize {
        match self {
            Self::Square => num_cons,
            Self::Tall => (num_cons / 2).max(2),
            Self::Wide => num_cons * 2,
        }
    }
}

#[derive(Clone)]
struct Scenario {
    shape: ShapeKind,
    log_m: usize,
    nnz_per_row: usize,
}

#[derive(Clone)]
struct ScenarioMaterial<F: Field> {
    shape: R1CSShape<F>,
    instance: R1CSInstance<F>,
    a_entries: Vec<SparseMatEntry<F>>,
    b_entries: Vec<SparseMatEntry<F>>,
    c_entries: Vec<SparseMatEntry<F>>,
}

fn build_scenario<F: Field>(s: &Scenario) -> ScenarioMaterial<F> {
    let num_cons = 1usize << s.log_m;
    let num_vars = s.shape.num_vars(num_cons);
    let num_inputs = 1usize;

    let positions = make_positions(num_cons, num_vars, s.nnz_per_row);
    let a_entries = materialize_entries::<F>(&positions, 3);
    let b_entries = materialize_entries::<F>(&positions, 11);
    let c_entries = materialize_entries::<F>(&positions, 29);

    let shape = R1CSShape::new(
        num_cons,
        num_vars,
        num_inputs,
        a_entries.clone(),
        b_entries.clone(),
        c_entries.clone(),
    );
    let witness = vec![F::ZERO; num_vars];
    let input = vec![F::ZERO; num_inputs];
    let instance = R1CSInstance::new(shape.clone(), input, witness);

    ScenarioMaterial {
        shape,
        instance,
        a_entries,
        b_entries,
        c_entries,
    }
}

fn make_positions(num_cons: usize, num_vars: usize, nnz_per_row: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(nnz_per_row * num_cons);
    for row in 0..num_cons {
        let stride = if num_vars <= 1 {
            1
        } else {
            ((2 * row + 1) % num_vars).max(1) | 1
        };
        let offset = if num_vars == 0 {
            0
        } else {
            (row * 17) % num_vars
        };
        for j in 0..nnz_per_row {
            let col = if num_vars == 0 {
                0
            } else {
                (offset + j * stride) % num_vars
            };
            out.push((row, col));
        }
    }
    out
}

fn materialize_entries<F: Field>(
    positions: &[(usize, usize)],
    salt: u64,
) -> Vec<SparseMatEntry<F>> {
    positions
        .iter()
        .enumerate()
        .map(|(k, (row, col))| {
            let val = F::from_u64(((k as u64).wrapping_mul(37).wrapping_add(salt) % 97) + 1);
            SparseMatEntry::new(*row, *col, val)
        })
        .collect()
}

fn deterministic_point<F: Field>(dim: usize, seed: u64) -> Vec<F> {
    (0..dim)
        .map(|i| {
            let v = (seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(i as u64 * 1_442_695_040_888_963_407)
                % 10_000)
                + 3;
            F::from_u64(v)
        })
        .collect()
}

fn eval_unbatched<F: Field>(
    a_entries: &[SparseMatEntry<F>],
    b_entries: &[SparseMatEntry<F>],
    c_entries: &[SparseMatEntry<F>],
    rx: &[F],
    ry: &[F],
) -> (F, F, F) {
    (
        eval_sparse(a_entries, rx, ry),
        eval_sparse(b_entries, rx, ry),
        eval_sparse(c_entries, rx, ry),
    )
}

fn eval_batched_aligned<F: Field>(
    a_entries: &[SparseMatEntry<F>],
    b_entries: &[SparseMatEntry<F>],
    c_entries: &[SparseMatEntry<F>],
    rx: &[F],
    ry: &[F],
    eta: F,
) -> F {
    let eta2 = eta.square();
    let mut acc = F::ZERO;
    for ((a, b), c) in a_entries.iter().zip(b_entries.iter()).zip(c_entries.iter()) {
        let eq_row = eq_index(a.row, rx);
        let eq_col = eq_index(a.col, ry);
        let combined = a.val + eta * b.val + eta2 * c.val;
        acc += combined * eq_row * eq_col;
    }
    acc
}

fn eval_sparse<F: Field>(entries: &[SparseMatEntry<F>], rx: &[F], ry: &[F]) -> F {
    let mut acc = F::ZERO;
    for e in entries {
        let eq_row = eq_index(e.row, rx);
        let eq_col = eq_index(e.col, ry);
        acc += e.val * eq_row * eq_col;
    }
    acc
}

fn eq_index<F: Field>(idx: usize, r: &[F]) -> F {
    let mut res = F::ONE;
    for (i, r_i) in r.iter().enumerate() {
        let bit = (idx >> i) & 1;
        res *= if bit == 1 { *r_i } else { F::ONE - *r_i };
    }
    res
}

fn modeled_full_proof_bytes(
    log_m: usize,
    num_vars: usize,
    queries: usize,
    unbatched_serialized_fields: usize,
    batched_serialized_fields: usize,
    field_bytes: usize,
    hash_bytes: usize,
) -> (usize, usize) {
    let num_poly_vars_y = (2 * num_vars).trailing_zeros() as usize;

    // Spartan core (phase-1 + phase-2 sumcheck payload, eval claims, SPARK metadata, transcript)
    let spartan_field_elems =
        (4 * log_m) + (3 * num_poly_vars_y) + 3 + 9 + log_m + num_poly_vars_y + 3 + 4 + 6;
    let spartan_core_bytes = spartan_field_elems * field_bytes + TRANSCRIPT_BASE_BYTES;

    // Query proof material: evaluations + Merkle auth paths/hashes + per-query transcript overhead.
    let path_bytes_per_opening = log_m * hash_bytes;
    let unbatched_query_bytes =
        unbatched_serialized_fields * field_bytes + (3 * queries * path_bytes_per_opening);
    let batched_query_bytes =
        batched_serialized_fields * field_bytes + (queries * path_bytes_per_opening);
    let transcript_query_bytes = queries * PER_QUERY_TRANSCRIPT_BYTES;

    (
        spartan_core_bytes + unbatched_query_bytes + transcript_query_bytes,
        spartan_core_bytes + batched_query_bytes + transcript_query_bytes,
    )
}

macro_rules! bench_field_impl {
    ($mod_name:ident, $field_name:expr, $F:ty, $EF:ty, $Perm:ty, $Challenger:ty, $field_bytes:expr, $hash_bytes:expr) => {
        mod $mod_name {
            use super::*;

            pub(crate) fn bench_prover_verifier(
                material: &ScenarioMaterial<$F>,
                repeats: usize,
            ) -> (f64, f64) {
                let prover = R1CSProver::<$F>::new();
                let verifier = R1CSVerifier::<$F>::new();

                let mut prover_ms = 0.0;
                let mut verifier_ms = 0.0;

                for i in 0..repeats {
                    let seed = 0x5eed_u64 + i as u64;
                    let perm =
                        <$Perm>::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(seed));
                    let mut prover_challenger = <$Challenger>::new(perm.clone());

                    let t0 = Instant::now();
                    let proof = prover.prove::<$EF, _>(&material.instance, &mut prover_challenger);
                    prover_ms += t0.elapsed().as_secs_f64() * 1_000.0;

                    let mut verifier_challenger = <$Challenger>::new(perm);
                    let t1 = Instant::now();
                    verifier
                        .verify::<$EF, _>(
                            &material.shape,
                            material.instance.input(),
                            &proof,
                            &mut verifier_challenger,
                        )
                        .expect("verifier should accept benchmark proof");
                    verifier_ms += t1.elapsed().as_secs_f64() * 1_000.0;
                }

                (prover_ms / repeats as f64, verifier_ms / repeats as f64)
            }

            fn bench_opening_pair(
                material: &ScenarioMaterial<$F>,
                queries: usize,
                repeats: usize,
            ) -> (f64, f64) {
                let num_vars_y = material.shape.num_poly_vars_y();
                let eta = <$F>::from_u64(17);

                let points: Vec<(Vec<$F>, Vec<$F>)> = (0..queries)
                    .map(|q| {
                        (
                            deterministic_point::<$F>(
                                material.shape.num_poly_vars_x(),
                                q as u64 + 11,
                            ),
                            deterministic_point::<$F>(num_vars_y, q as u64 + 97),
                        )
                    })
                    .collect();

                let sanity = points
                    .iter()
                    .map(|(rx, ry)| {
                        let (a_eval, b_eval, c_eval) = eval_unbatched::<$F>(
                            &material.a_entries,
                            &material.b_entries,
                            &material.c_entries,
                            rx,
                            ry,
                        );
                        let batched_eval = eval_batched_aligned::<$F>(
                            &material.a_entries,
                            &material.b_entries,
                            &material.c_entries,
                            rx,
                            ry,
                            eta,
                        );
                        a_eval + eta * b_eval + eta.square() * c_eval == batched_eval
                    })
                    .all(|x| x);
                assert!(
                    sanity,
                    "batched sparse opening must match unbatched combination"
                );

                let mut unbatched_us = 0.0;
                let mut batched_us = 0.0;

                for _ in 0..repeats {
                    let t0 = Instant::now();
                    let mut acc = <$F>::ZERO;
                    for (rx, ry) in &points {
                        let (a_eval, b_eval, c_eval) = eval_unbatched::<$F>(
                            &material.a_entries,
                            &material.b_entries,
                            &material.c_entries,
                            rx,
                            ry,
                        );
                        acc += a_eval + b_eval + c_eval;
                    }
                    let _ = black_box(acc);
                    unbatched_us += t0.elapsed().as_secs_f64() * 1_000_000.0;

                    let t1 = Instant::now();
                    let mut acc_b = <$F>::ZERO;
                    for (rx, ry) in &points {
                        let batch = eval_batched_aligned::<$F>(
                            &material.a_entries,
                            &material.b_entries,
                            &material.c_entries,
                            rx,
                            ry,
                            eta,
                        );
                        acc_b += batch;
                    }
                    let _ = black_box(acc_b);
                    batched_us += t1.elapsed().as_secs_f64() * 1_000_000.0;
                }

                (unbatched_us / repeats as f64, batched_us / repeats as f64)
            }

            fn bench_verifier_queries(
                material: &ScenarioMaterial<$F>,
                queries: usize,
                repeats: usize,
            ) -> (f64, f64) {
                let num_vars_y = material.shape.num_poly_vars_y();
                let eta = <$F>::from_u64(17);

                let points: Vec<(Vec<$F>, Vec<$F>)> = (0..queries)
                    .map(|q| {
                        (
                            deterministic_point::<$F>(
                                material.shape.num_poly_vars_x(),
                                q as u64 + 211,
                            ),
                            deterministic_point::<$F>(num_vars_y, q as u64 + 307),
                        )
                    })
                    .collect();

                let claims: Vec<($F, $F, $F, $F)> = points
                    .iter()
                    .map(|(rx, ry)| {
                        let (a_eval, b_eval, c_eval) = eval_unbatched::<$F>(
                            &material.a_entries,
                            &material.b_entries,
                            &material.c_entries,
                            rx,
                            ry,
                        );
                        let batched_eval = a_eval + eta * b_eval + eta.square() * c_eval;
                        (a_eval, b_eval, c_eval, batched_eval)
                    })
                    .collect();

                let mut unbatched_us = 0.0;
                let mut batched_us = 0.0;

                for _ in 0..repeats {
                    let t0 = Instant::now();
                    let mut ok_count = 0usize;
                    for ((rx, ry), (ca, cb, cc, _)) in points.iter().zip(claims.iter()) {
                        let (a_eval, b_eval, c_eval) = eval_unbatched::<$F>(
                            &material.a_entries,
                            &material.b_entries,
                            &material.c_entries,
                            rx,
                            ry,
                        );
                        if a_eval == *ca && b_eval == *cb && c_eval == *cc {
                            ok_count += 1;
                        }
                    }
                    let _ = black_box(ok_count);
                    unbatched_us += t0.elapsed().as_secs_f64() * 1_000_000.0;

                    let t1 = Instant::now();
                    let mut ok_count_b = 0usize;
                    for ((rx, ry), (_, _, _, c_batch)) in points.iter().zip(claims.iter()) {
                        let batch_eval = eval_batched_aligned::<$F>(
                            &material.a_entries,
                            &material.b_entries,
                            &material.c_entries,
                            rx,
                            ry,
                            eta,
                        );
                        if batch_eval == *c_batch {
                            ok_count_b += 1;
                        }
                    }
                    let _ = black_box(ok_count_b);
                    batched_us += t1.elapsed().as_secs_f64() * 1_000_000.0;
                }

                (unbatched_us / repeats as f64, batched_us / repeats as f64)
            }

            pub(crate) fn run(
                quick: bool,
                repeats: usize,
                metrics: &mut std::fs::File,
                opening: &mut std::fs::File,
                verifier_queries: &mut std::fs::File,
            ) {
                let log_ms: Vec<usize> = if quick {
                    vec![4, 6]
                } else {
                    vec![4, 5, 6, 7, 8]
                };
                let nnz_per_row_grid: Vec<usize> = if quick {
                    vec![1, 4]
                } else {
                    vec![1, 2, 4, 8, 16, 32]
                };

                for shape in ShapeKind::all() {
                    for &log_m in &log_ms {
                        let num_cons = 1usize << log_m;
                        let num_vars = shape.num_vars(num_cons);
                        let max_nnz_per_row = num_vars.max(1);
                        let mut nnz_per_row_values = BTreeSet::new();
                        for &candidate in &nnz_per_row_grid {
                            nnz_per_row_values.insert(candidate.min(max_nnz_per_row));
                        }

                        for nnz_per_row in nnz_per_row_values {
                            let scenario = Scenario {
                                shape,
                                log_m,
                                nnz_per_row,
                            };
                            let material = build_scenario::<$F>(&scenario);
                            let nnz_per_matrix_global = nnz_per_row * num_cons;
                            let total_nnz_global = 3 * nnz_per_matrix_global;

                            let (prover_ms, verifier_ms) =
                                bench_prover_verifier(&material, repeats);
                            let (opening_unbatched_us, opening_batched_us) =
                                bench_opening_pair(&material, 1, repeats * 3);

                            writeln!(
                                metrics,
                                "{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6}",
                                $field_name,
                                shape.as_str(),
                                log_m,
                                num_cons,
                                num_vars,
                                nnz_per_row,
                                nnz_per_matrix_global,
                                total_nnz_global,
                                prover_ms,
                                verifier_ms,
                                opening_unbatched_us,
                                opening_batched_us
                            )
                            .unwrap();

                            let query_grid: Vec<usize> = if quick {
                                vec![1, 4, 16]
                            } else {
                                vec![1, 2, 4, 8, 16, 32, 64]
                            };
                            for queries in query_grid {
                                let (unbatched_us, batched_us) =
                                    bench_opening_pair(&material, queries, repeats * 2);
                                let (verifier_unbatched_us, verifier_batched_us) =
                                    bench_verifier_queries(&material, queries, repeats * 2);

                                let unbatched_field_ops = 3usize * queries * nnz_per_matrix_global;
                                let batched_field_ops =
                                    queries * nnz_per_matrix_global + 2 * queries;
                                let unbatched_serialized_fields = 3usize * queries;
                                let batched_serialized_fields = queries + 2;

                                let (unbatched_full_proof_bytes, batched_full_proof_bytes) =
                                    modeled_full_proof_bytes(
                                        log_m,
                                        num_vars,
                                        queries,
                                        unbatched_serialized_fields,
                                        batched_serialized_fields,
                                        $field_bytes,
                                        $hash_bytes,
                                    );

                                writeln!(
                                    opening,
                                    "{},{},{},{},{},{},{},{},{:.6},{:.6},{},{},{},{},{},{}",
                                    $field_name,
                                    shape.as_str(),
                                    log_m,
                                    num_cons,
                                    num_vars,
                                    nnz_per_row,
                                    nnz_per_matrix_global,
                                    queries,
                                    unbatched_us,
                                    batched_us,
                                    unbatched_field_ops,
                                    batched_field_ops,
                                    unbatched_serialized_fields,
                                    batched_serialized_fields,
                                    unbatched_full_proof_bytes,
                                    batched_full_proof_bytes
                                )
                                .unwrap();

                                writeln!(
                                    verifier_queries,
                                    "{},{},{},{},{},{},{},{},{:.6},{:.6}",
                                    $field_name,
                                    shape.as_str(),
                                    log_m,
                                    num_cons,
                                    num_vars,
                                    nnz_per_row,
                                    nnz_per_matrix_global,
                                    queries,
                                    verifier_unbatched_us,
                                    verifier_batched_us
                                )
                                .unwrap();
                            }
                        }
                    }
                }
            }
        }
    };
}

bench_field_impl!(
    bench_babybear,
    "BabyBear",
    p3_baby_bear::BabyBear,
    BinomialExtensionField<p3_baby_bear::BabyBear, 4>,
    p3_baby_bear::Poseidon2BabyBear<16>,
    DuplexChallenger<p3_baby_bear::BabyBear, p3_baby_bear::Poseidon2BabyBear<16>, 16, 8>,
    4,
    32
);

bench_field_impl!(
    bench_m31,
    "M31",
    p3_mersenne_31::Mersenne31,
    BinomialExtensionField<p3_mersenne_31::Mersenne31, 3>,
    p3_mersenne_31::Poseidon2Mersenne31<16>,
    DuplexChallenger<p3_mersenne_31::Mersenne31, p3_mersenne_31::Poseidon2Mersenne31<16>, 16, 8>,
    4,
    32
);

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let repeats = if quick { 2 } else { 6 };

    let out_dir = Path::new("output/benchmarks/spartan_spark");
    create_dir_all(out_dir).expect("create benchmark output directory");

    let mut metrics = File::create(out_dir.join("metrics.csv")).expect("create metrics.csv");
    writeln!(
        metrics,
        "field,shape,log_m,num_cons,num_vars,nnz_per_row,nnz_per_matrix_global,total_nnz_global,prover_ms,verifier_ms,opening_unbatched_us,opening_batched_us"
    )
    .unwrap();

    let mut opening =
        File::create(out_dir.join("opening_batch_compare.csv")).expect("create opening csv");
    writeln!(
        opening,
        "field,shape,log_m,num_cons,num_vars,nnz_per_row,nnz_per_matrix_global,queries,unbatched_us,batched_us,unbatched_field_ops,batched_field_ops,unbatched_serialized_fields,batched_serialized_fields,unbatched_full_proof_bytes,batched_full_proof_bytes"
    )
    .unwrap();

    let mut verifier_queries =
        File::create(out_dir.join("verifier_query_compare.csv")).expect("create verifier csv");
    writeln!(
        verifier_queries,
        "field,shape,log_m,num_cons,num_vars,nnz_per_row,nnz_per_matrix_global,queries,verifier_unbatched_us,verifier_batched_us"
    )
    .unwrap();

    println!("Running BabyBear benchmark...");
    bench_babybear::run(
        quick,
        repeats,
        &mut metrics,
        &mut opening,
        &mut verifier_queries,
    );

    println!("Running M31 benchmark...");
    bench_m31::run(
        quick,
        repeats,
        &mut metrics,
        &mut opening,
        &mut verifier_queries,
    );

    println!("Wrote benchmark data to {}", out_dir.to_string_lossy());
}
