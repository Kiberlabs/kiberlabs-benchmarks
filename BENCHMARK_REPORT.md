# KiberLabs Reproducible Benchmark & Red-Team Report

- **Generated (UTC):** `2026-11-22T11:53:59Z`
- **Suite Version:** `v0.1.0`
- **Runtime:** Python `3.15.2` on `Windows 11 (AMD64)` (`12` CPUs)

## 1. Performance & Zero-Lock Concurrency Benchmarks

| Workload | Ops | Throughput | p50 (ms) | p95 (ms) | p99 (ms) | Wall (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Margin Sieve (3-Stage Deterministic Filter) | 10,000 | **38,535.9 SKUs/sec** | 0.0224 | 0.0376 | 0.0511 | 259.50 |
| Lead Bot Bilingual NLU + WAL Dedup | 2,000 | **73,912.8 msgs/sec** | 0.0116 | 0.0176 | 0.0928 | 27.06 |
| Grounded RAG SQLite FTS5 BM25 | 1,000 | **6,671.6 queries/sec** | 0.1577 | 0.2396 | 0.2687 | 149.89 |
| FastAPI Gateway HMAC Auth + Rate Limit | 2,000 | **763,883.6 reqs/sec** | 0.0007 | 0.0010 | 0.0014 | 2.62 |
| SQLite WAL 50-Thread Concurrency | 2,000 | **299.2 ops/sec** | 0.0619 | 0.2541 | 3222.1865 | 6685.00 |

**SQLite WAL Verification:** `50` concurrent threads, `1,000` writes + `1,000` reads, `1,000` persisted rows, journal mode `WAL`, **`0` `database is locked` errors**.

## 2. Adversarial Red-Team Security Suite

**Overall Block Rate:** **112 / 112 (100.00%)** blocked in `712.84 ms` (`0` bypassed).

| Attack Category | Payloads | Blocked | Bypassed | Block Rate | Time (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| SSRF & Cloud Metadata | 27 | 27 | 0 | **100.00%** | 0.944 |
| Path Traversal & Shell Injection | 22 | 22 | 0 | **100.00%** | 1.474 |
| FTS5 & SQL Injection | 22 | 22 | 0 | **100.00%** | 0.029 |
| Webhook Replay & HMAC Storms | 21 | 21 | 0 | **100.00%** | 710.250 |
| Invalid & Malformed Boundary Inputs | 20 | 20 | 0 | **100.00%** | 0.103 |

---
*Reproduce locally with zero external dependencies:* `pip install -e . && kiberlabs-bench`
