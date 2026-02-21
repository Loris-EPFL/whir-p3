# Spartan+WHIR SPARK Benchmark Report

## Inputs
- Cost sweep dimensions: `nnz_per_row`, `nnz_per_matrix_global`, `total_nnz_global`, `log m`, and shape (`square|tall|wide`).
- Runtime comparison includes unbatched vs batched sparse opening evaluation.
- Full proof-size model includes sum-check payload, transcript overhead, and Merkle authentication-path hashes.

## Prover/Verifier Cost Table
| shape | log_m | num_cons | num_vars | nnz_per_row | nnz_per_matrix_global | total_nnz_global | prover_ms | verifier_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| square | 4 | 16 | 16 | 1 | 16 | 48 | 1.8835 | 0.3011 |
| square | 4 | 16 | 16 | 4 | 64 | 192 | 5.3298 | 0.4144 |
| square | 6 | 64 | 64 | 1 | 64 | 192 | 33.2663 | 0.5447 |
| square | 6 | 64 | 64 | 4 | 256 | 768 | 107.7555 | 0.9758 |
| tall | 4 | 16 | 8 | 1 | 16 | 48 | 1.1043 | 0.2754 |
| tall | 4 | 16 | 8 | 4 | 64 | 192 | 3.1854 | 0.3792 |
| tall | 6 | 64 | 32 | 1 | 64 | 192 | 17.8275 | 0.5138 |
| tall | 6 | 64 | 32 | 4 | 256 | 768 | 62.7908 | 1.0001 |
| wide | 4 | 16 | 32 | 1 | 16 | 48 | 4.9283 | 0.3478 |
| wide | 4 | 16 | 32 | 4 | 64 | 192 | 10.7425 | 0.4672 |
| wide | 6 | 64 | 128 | 1 | 64 | 192 | 85.2003 | 0.6517 |
| wide | 6 | 64 | 128 | 4 | 256 | 768 | 215.9326 | 1.0197 |

## Crossover Thresholds
| shape | log_m | runtime crossover queries | payload-fields crossover queries | full-proof-bytes crossover queries |
|---|---:|---:|---:|---:|
| square | 4 | 1 | 1 | 1 |
| square | 6 | 1 | 1 | 1 |
| tall | 4 | 1 | 1 | 1 |
| tall | 6 | 1 | 1 | 1 |
| wide | 4 | 1 | 1 | 1 |
| wide | 6 | 1 | 1 | 1 |

## Verifier Query Sweep
- Per-`log_m` plots are generated to show verifier-time scaling with query count.

## Plots
- `prover_verifier_vs_total_nnz_global.svg` (cost vs true global nnz)
- `opening_runtime_vs_queries.svg` (batched vs unbatched runtime)
- `opening_payload_vs_queries.svg` (batched vs unbatched serialized field elements)
- `full_proof_bytes_vs_queries.svg` (batched vs unbatched full proof size in bytes)
- `verifier_vs_queries_logm4.svg` (verifier time vs queries at fixed log_m)
- `verifier_vs_queries_logm6.svg` (verifier time vs queries at fixed log_m)
