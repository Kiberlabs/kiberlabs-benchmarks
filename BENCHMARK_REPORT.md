# KiberLabs Reproducible Benchmark & Red-Team Report

- **Generated (UTC):** `2026-11-25T23:54:21Z`
- **Suite Version:** `v0.1.0`
- **Runtime:** Python `3.15.2` on `Windows 11 (AMD64)` (`12` CPUs)

## 1. Performance & Zero-Lock Concurrency Benchmarks

| Workload | Ops | Throughput | p50 (ms) | p95 (ms) | p99 (ms) | Wall (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Margin Sieve (3-Stage Deterministic Filter) | 10,000 | **36,819.9 SKUs/sec** | 0.0258 | 0.0316 | 0.0472 | 271.59 |
| Lead Bot Bilingual NLU + WAL Dedup | 2,000 | **73,419.6 msgs/sec** | 0.0118 | 0.0179 | 0.0807 | 27.24 |
| Grounded RAG SQLite FTS5 BM25 | 1,000 | **7,196.6 queries/sec** | 0.1546 | 0.1716 | 0.2756 | 138.95 |
| FastAPI Gateway HMAC Auth + Rate Limit | 2,000 | **1,026,430.6 reqs/sec** | 0.0006 | 0.0006 | 0.0008 | 1.95 |
| SQLite WAL 50-Thread Concurrency | 2,000 | **133.1 ops/sec** | 0.0464 | 0.2273 | 7861.8501 | 15027.40 |
| Telegram Maintenance Manual FTS5 RAG | 1,000 | **2,738.8 queries/sec** | 0.3799 | 0.5189 | 0.7319 | 365.13 |
| Telegram 64-bit update_id 16-Thread WAL | 640 | **189.5 ops/sec** | 0.0330 | 0.1422 | 1630.3953 | 3377.04 |

**SQLite WAL Verification:** `50` concurrent threads, `1,000` writes + `1,000` reads, `1,000` persisted rows, journal mode `WAL`, **`0` `database is locked` errors**.

**Maintenance 64-bit `update_id` WAL Verification:** `16` concurrent threads, `490` unique inserts + `150` duplicate replays blocked, `490` persisted rows, journal mode `WAL`, **`0` `database is locked` errors**.

## 2. Adversarial Red-Team Security Suite

**Overall Block Rate:** **122 / 122 (100.00%)** blocked in `3945.90 ms` (`0` bypassed).

| Attack Category | Payloads | Blocked | Bypassed | Block Rate | Time (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| SSRF & Cloud Metadata | 27 | 27 | 0 | **100.00%** | 1.001 |
| Path Traversal & Shell Injection | 22 | 22 | 0 | **100.00%** | 1.434 |
| FTS5 & SQL Injection | 32 | 32 | 0 | **100.00%** | 0.204 |
| Webhook Replay & HMAC Storms | 21 | 21 | 0 | **100.00%** | 3943.062 |
| Invalid & Malformed Boundary Inputs | 20 | 20 | 0 | **100.00%** | 0.152 |

---
*Reproduce locally with zero external dependencies:* `pip install -e . && kiberlabs-bench`
