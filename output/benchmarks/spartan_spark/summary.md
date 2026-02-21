# Spartan+WHIR SPARK Benchmark Report

## Inputs
- Cost sweep dimensions: `nnz_per_row`, `nnz_per_matrix_global`, `total_nnz_global`, `log m`, and shape (`square|tall|wide`).
- Runtime comparison includes unbatched vs batched sparse opening evaluation.
- Full proof-size model includes sum-check payload, transcript overhead, and Merkle authentication-path hashes.

## Prover/Verifier Cost Table
| field | shape | log_m | num_cons | num_vars | nnz_per_row | nnz_per_matrix_global | total_nnz_global | prover_ms | verifier_ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| BabyBear | square | 4 | 16 | 16 | 1 | 16 | 48 | 0.1579 | 0.0169 |
| BabyBear | square | 4 | 16 | 16 | 4 | 64 | 192 | 0.4516 | 0.0228 |
| BabyBear | square | 6 | 64 | 64 | 1 | 64 | 192 | 3.1945 | 0.0318 |
| BabyBear | square | 6 | 64 | 64 | 4 | 256 | 768 | 13.9330 | 0.0913 |
| BabyBear | tall | 4 | 16 | 8 | 1 | 16 | 48 | 0.0799 | 0.0132 |
| BabyBear | tall | 4 | 16 | 8 | 4 | 64 | 192 | 0.2296 | 0.0190 |
| BabyBear | tall | 6 | 64 | 32 | 1 | 64 | 192 | 1.4233 | 0.0272 |
| BabyBear | tall | 6 | 64 | 32 | 4 | 256 | 768 | 5.3737 | 0.0615 |
| BabyBear | wide | 4 | 16 | 32 | 1 | 16 | 48 | 0.2981 | 0.0147 |
| BabyBear | wide | 4 | 16 | 32 | 4 | 64 | 192 | 0.8196 | 0.0220 |
| BabyBear | wide | 6 | 64 | 128 | 1 | 64 | 192 | 9.3634 | 0.0372 |
| BabyBear | wide | 6 | 64 | 128 | 4 | 256 | 768 | 18.2681 | 0.0615 |
| Goldilocks | square | 4 | 16 | 16 | 1 | 16 | 48 | 0.3214 | 0.0398 |
| Goldilocks | square | 4 | 16 | 16 | 4 | 64 | 192 | 0.4166 | 0.0357 |
| Goldilocks | square | 6 | 64 | 64 | 1 | 64 | 192 | 2.0632 | 0.0470 |
| Goldilocks | square | 6 | 64 | 64 | 4 | 256 | 768 | 8.4597 | 0.1224 |
| Goldilocks | tall | 4 | 16 | 8 | 1 | 16 | 48 | 0.0771 | 0.0230 |
| Goldilocks | tall | 4 | 16 | 8 | 4 | 64 | 192 | 0.2101 | 0.0293 |
| Goldilocks | tall | 6 | 64 | 32 | 1 | 64 | 192 | 1.4169 | 0.0758 |
| Goldilocks | tall | 6 | 64 | 32 | 4 | 256 | 768 | 4.1612 | 0.0855 |
| Goldilocks | wide | 4 | 16 | 32 | 1 | 16 | 48 | 0.2767 | 0.0299 |
| Goldilocks | wide | 4 | 16 | 32 | 4 | 64 | 192 | 0.7007 | 0.0366 |
| Goldilocks | wide | 6 | 64 | 128 | 1 | 64 | 192 | 5.7409 | 0.0567 |
| Goldilocks | wide | 6 | 64 | 128 | 4 | 256 | 768 | 19.0184 | 0.0965 |
| KoalaBear | square | 4 | 16 | 16 | 1 | 16 | 48 | 0.3160 | 0.0269 |
| KoalaBear | square | 4 | 16 | 16 | 4 | 64 | 192 | 0.7807 | 0.0205 |
| KoalaBear | square | 6 | 64 | 64 | 1 | 64 | 192 | 2.6789 | 0.0266 |
| KoalaBear | square | 6 | 64 | 64 | 4 | 256 | 768 | 9.3756 | 0.0575 |
| KoalaBear | tall | 4 | 16 | 8 | 1 | 16 | 48 | 0.0739 | 0.0121 |
| KoalaBear | tall | 4 | 16 | 8 | 4 | 64 | 192 | 0.2334 | 0.0197 |
| KoalaBear | tall | 6 | 64 | 32 | 1 | 64 | 192 | 1.4438 | 0.0245 |
| KoalaBear | tall | 6 | 64 | 32 | 4 | 256 | 768 | 5.3574 | 0.0544 |
| KoalaBear | wide | 4 | 16 | 32 | 1 | 16 | 48 | 0.3008 | 0.0163 |
| KoalaBear | wide | 4 | 16 | 32 | 4 | 64 | 192 | 0.8133 | 0.0215 |
| KoalaBear | wide | 6 | 64 | 128 | 1 | 64 | 192 | 6.4541 | 0.0289 |
| KoalaBear | wide | 6 | 64 | 128 | 4 | 256 | 768 | 18.1055 | 0.0597 |
| M31 | square | 4 | 16 | 16 | 1 | 16 | 48 | 0.1447 | 0.0189 |
| M31 | square | 4 | 16 | 16 | 4 | 64 | 192 | 0.3014 | 0.0164 |
| M31 | square | 6 | 64 | 64 | 1 | 64 | 192 | 1.7830 | 0.0215 |
| M31 | square | 6 | 64 | 64 | 4 | 256 | 768 | 6.7637 | 0.0643 |
| M31 | tall | 4 | 16 | 8 | 1 | 16 | 48 | 0.4240 | 0.0112 |
| M31 | tall | 4 | 16 | 8 | 4 | 64 | 192 | 0.2175 | 0.0158 |
| M31 | tall | 6 | 64 | 32 | 1 | 64 | 192 | 0.9230 | 0.0203 |
| M31 | tall | 6 | 64 | 32 | 4 | 256 | 768 | 3.4953 | 0.0413 |
| M31 | wide | 4 | 16 | 32 | 1 | 16 | 48 | 0.2339 | 0.0131 |
| M31 | wide | 4 | 16 | 32 | 4 | 64 | 192 | 0.5613 | 0.0176 |
| M31 | wide | 6 | 64 | 128 | 1 | 64 | 192 | 5.4523 | 0.0252 |
| M31 | wide | 6 | 64 | 128 | 4 | 256 | 768 | 12.2079 | 0.0532 |

## Crossover Thresholds
| field | shape | log_m | runtime crossover queries | payload-fields crossover queries | full-proof-bytes crossover queries |
|---|---|---:|---:|---:|---:|
| BabyBear | square | 4 | 1 | 1 | 1 |
| BabyBear | square | 6 | 1 | 1 | 1 |
| BabyBear | tall | 4 | 1 | 1 | 1 |
| BabyBear | tall | 6 | 1 | 1 | 1 |
| BabyBear | wide | 4 | 1 | 1 | 1 |
| BabyBear | wide | 6 | 1 | 1 | 1 |
| Goldilocks | square | 4 | 1 | 1 | 1 |
| Goldilocks | square | 6 | 1 | 1 | 1 |
| Goldilocks | tall | 4 | 1 | 1 | 1 |
| Goldilocks | tall | 6 | 1 | 1 | 1 |
| Goldilocks | wide | 4 | 1 | 1 | 1 |
| Goldilocks | wide | 6 | 1 | 1 | 1 |
| KoalaBear | square | 4 | 1 | 1 | 1 |
| KoalaBear | square | 6 | 1 | 1 | 1 |
| KoalaBear | tall | 4 | 1 | 1 | 1 |
| KoalaBear | tall | 6 | 1 | 1 | 1 |
| KoalaBear | wide | 4 | 1 | 1 | 1 |
| KoalaBear | wide | 6 | 1 | 1 | 1 |
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
