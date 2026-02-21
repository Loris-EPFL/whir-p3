# Spartan+WHIR SPARK Benchmark Report

## Inputs
- Cost sweep dimensions: `nnz_per_row`, `nnz_per_matrix_global`, `total_nnz_global`, `log m`, and shape (`square|tall|wide`).
- Runtime comparison includes unbatched vs batched sparse opening evaluation.
- Full proof-size model includes sum-check payload, transcript overhead, and Merkle authentication-path hashes.

## Prover/Verifier Cost Table
| field | shape | log_m | num_cons | num_vars | nnz_per_row | nnz_per_matrix_global | total_nnz_global | prover_ms | verifier_ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| BabyBear | square | 4 | 16 | 16 | 1 | 16 | 48 | 1.6286 | 0.3001 |
| BabyBear | square | 4 | 16 | 16 | 4 | 64 | 192 | 4.5700 | 0.3955 |
| BabyBear | square | 6 | 64 | 64 | 1 | 64 | 192 | 26.1099 | 0.4822 |
| BabyBear | square | 6 | 64 | 64 | 4 | 256 | 768 | 83.6727 | 0.8828 |
| BabyBear | tall | 4 | 16 | 8 | 1 | 16 | 48 | 0.8284 | 0.2389 |
| BabyBear | tall | 4 | 16 | 8 | 4 | 64 | 192 | 2.2692 | 0.3146 |
| BabyBear | tall | 6 | 64 | 32 | 1 | 64 | 192 | 12.7076 | 0.4461 |
| BabyBear | tall | 6 | 64 | 32 | 4 | 256 | 768 | 45.5135 | 0.7669 |
| BabyBear | wide | 4 | 16 | 32 | 1 | 16 | 48 | 3.2688 | 0.2948 |
| BabyBear | wide | 4 | 16 | 32 | 4 | 64 | 192 | 7.9463 | 0.3709 |
| BabyBear | wide | 6 | 64 | 128 | 1 | 64 | 192 | 61.7018 | 0.5413 |
| BabyBear | wide | 6 | 64 | 128 | 4 | 256 | 768 | 170.2382 | 1.0793 |
| M31 | square | 4 | 16 | 16 | 1 | 16 | 48 | 2.4593 | 0.3241 |
| M31 | square | 4 | 16 | 16 | 4 | 64 | 192 | 7.9460 | 0.5901 |
| M31 | square | 6 | 64 | 64 | 1 | 64 | 192 | 48.8056 | 0.6819 |
| M31 | square | 6 | 64 | 64 | 4 | 256 | 768 | 153.5558 | 1.2669 |
| M31 | tall | 4 | 16 | 8 | 1 | 16 | 48 | 1.3735 | 0.3025 |
| M31 | tall | 4 | 16 | 8 | 4 | 64 | 192 | 4.2028 | 0.4273 |
| M31 | tall | 6 | 64 | 32 | 1 | 64 | 192 | 24.0575 | 0.5937 |
| M31 | tall | 6 | 64 | 32 | 4 | 256 | 768 | 87.6240 | 1.2295 |
| M31 | wide | 4 | 16 | 32 | 1 | 16 | 48 | 5.5446 | 0.3618 |
| M31 | wide | 4 | 16 | 32 | 4 | 64 | 192 | 14.8358 | 0.5015 |
| M31 | wide | 6 | 64 | 128 | 1 | 64 | 192 | 109.2758 | 0.7316 |
| M31 | wide | 6 | 64 | 128 | 4 | 256 | 768 | 300.8632 | 1.5328 |

## Crossover Thresholds
| field | shape | log_m | runtime crossover queries | payload-fields crossover queries | full-proof-bytes crossover queries |
|---|---|---:|---:|---:|---:|
| BabyBear | square | 4 | 1 | 1 | 1 |
| BabyBear | square | 6 | 1 | 1 | 1 |
| BabyBear | tall | 4 | 1 | 1 | 1 |
| BabyBear | tall | 6 | 1 | 1 | 1 |
| BabyBear | wide | 4 | 1 | 1 | 1 |
| BabyBear | wide | 6 | 1 | 1 | 1 |
| M31 | square | 4 | 1 | 1 | 1 |
| M31 | square | 6 | 1 | 1 | 1 |
| M31 | tall | 4 | 1 | 1 | 1 |
| M31 | tall | 6 | 1 | 1 | 1 |
| M31 | wide | 4 | 1 | 1 | 1 |
| M31 | wide | 6 | 1 | 1 | 1 |

## Verifier Query Sweep
- Per-`log_m` plots are generated to show verifier-time scaling with query count.

## Plots
- `prover_verifier_vs_total_nnz_global.svg` (cost vs true global nnz)
- `opening_runtime_vs_queries.svg` (batched vs unbatched runtime)
- `opening_payload_vs_queries.svg` (batched vs unbatched serialized field elements)
- `full_proof_bytes_vs_queries.svg` (batched vs unbatched full proof size in bytes)
- `verifier_vs_queries_logm4.svg` (verifier time vs queries at fixed log_m)
- `verifier_vs_queries_logm6.svg` (verifier time vs queries at fixed log_m)
