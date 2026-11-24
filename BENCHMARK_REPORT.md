# KiberLabs Reproducible Benchmark & Red-Team Report

- **Generated (UTC):** `2026-11-23T23:36:28Z`
- **Suite Version:** `v0.1.0`
- **Runtime:** Python `3.15.2` on `Windows 11 (AMD64)` (`12` CPUs)

## 1. Performance & Zero-Lock Concurrency Benchmarks

| Workload | Ops | Throughput | p50 (ms) | p95 (ms) | p99 (ms) | Wall (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Margin Sieve (3-Stage Deterministic Filter) | 10,000 | **35,051.3 SKUs/sec** | 0.0263 | 0.0423 | 0.0551 | 285.30 |
| Lead Bot Bilingual NLU + WAL Dedup | 2,000 | **65,405.0 msgs/sec** | 0.0117 | 0.0253 | 0.0799 | 30.58 |
| Grounded RAG SQLite FTS5 BM25 | 1,000 | **6,533.0 queries/sec** | 0.1494 | 0.2682 | 0.4175 | 153.07 |
| FastAPI Gateway HMAC Auth + Rate Limit | 2,000 | **919,286.6 reqs/sec** | 0.0006 | 0.0009 | 0.0018 | 2.18 |
| SQLite WAL 50-Thread Concurrency | 2,000 | **186.3 ops/sec** | 0.0467 | 0.1915 | 4789.8968 | 10732.58 |

**SQLite WAL Verification:** `50` concurrent threads, `1,000` writes + `1,000` reads, `1,000` persisted rows, journal mode `WAL`, **`0` `database is locked` errors**.

## 2. Adversarial Red-Team Security Suite

**Overall Block Rate:** **112 / 112 (100.00%)** blocked in `2167.68 ms` (`0` bypassed).

| Attack Category | Payloads | Blocked | Bypassed | Block Rate | Time (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| SSRF & Cloud Metadata | 27 | 27 | 0 | **100.00%** | 1.032 |
| Path Traversal & Shell Injection | 22 | 22 | 0 | **100.00%** | 1.242 |
| FTS5 & SQL Injection | 22 | 22 | 0 | **100.00%** | 0.030 |
| Webhook Replay & HMAC Storms | 21 | 21 | 0 | **100.00%** | 2165.198 |
| Invalid & Malformed Boundary Inputs | 20 | 20 | 0 | **100.00%** | 0.138 |

---
*Reproduce locally with zero external dependencies:* `pip install -e . && kiberlabs-bench`
