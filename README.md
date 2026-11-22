# kiberlabs-benchmarks

[![CI](https://github.com/Kiberlabs/kiberlabs-benchmarks/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiberlabs/kiberlabs-benchmarks/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/downloads/)
[![Zero Runtime Deps](https://img.shields.io/badge/runtime%20deps-0%20(stdlib)-10b981.svg)](pyproject.toml)

Reproducible performance, **50-thread SQLite WAL zero-lock concurrency**, and **112-payload Adversarial Red-Team Security** benchmark harness for [KiberLabs](https://kiberlabs.github.io) B2B automation engines.

- **Live Visual Dashboard:** [kiberlabs.github.io/benchmarks.html](https://kiberlabs.github.io/benchmarks.html)
- **Trust & Architecture Decisions (ADRs):** [kiberlabs.github.io/trust.html](https://kiberlabs.github.io/trust.html)
- **Interactive Fixed-Price SOW PDF Generator:** [kiberlabs.github.io/sow.html](https://kiberlabs.github.io/sow.html)

---

## Measured Reference Results (`v0.1.0`)

Generated directly by `runner.py` (`2026-11-22T11:53:59Z`, Python `3.15.2`, Windows 11 AMD64, 12 CPUs — full raw data in [`results/benchmark_report.json`](results/benchmark_report.json) and [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)):

| Workload | Ops | Measured Throughput | p50 (ms) | p95 (ms) | p99 (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **Margin Sieve** (3-Stage Deterministic Filter) | 10,000 | **38,535.9 SKUs/sec** | 0.0224 | 0.0376 | 0.0511 |
| **Lead Bot** Bilingual EN/ES NLU + WAL Dedup | 2,000 | **73,912.8 msgs/sec** | 0.0116 | 0.0176 | 0.0928 |
| **Grounded RAG** SQLite FTS5 BM25 | 1,000 | **6,671.6 queries/sec** | 0.1577 | 0.2396 | 0.2687 |
| **FastAPI Gateway** HMAC Auth + Sliding Rate Limit | 2,000 | **763,883.6 reqs/sec** | 0.0007 | 0.0010 | 0.0014 |
| **SQLite WAL 50-Thread Concurrency** | 2,000 | **299.2 ops/sec** | 0.0619 | 0.2541 | 3222.1865 |

- **SQLite WAL Zero-Lock Guarantee:** 50 concurrent threads (`1,000` writes + `1,000` reads) -> **`1,000` persisted rows, `0` `database is locked` errors**.
- **Adversarial Red-Team Suite:** **112 / 112 (100.00%)** attack payloads deterministically blocked across 5 categories (`SSRF & Cloud Metadata`, `Path Traversal & Shell Injection`, `FTS5 & SQL Injection`, `Webhook Replay & HMAC Storms`, `Invalid & Malformed Boundary Inputs`) with **0 bypasses**.

---

## Reproduce Locally (Zero External Runtime Dependencies)

```bash
git clone https://github.com/Kiberlabs/kiberlabs-benchmarks.git
cd kiberlabs-benchmarks
python -m pip install -e ".[dev]"

# 1. Run full pytest verification suite (including benign false-positive controls)
pytest -v

# 2. Generate fresh JSON + Markdown benchmark reports on your own hardware
kiberlabs-bench --json-out results/benchmark_report.json --md-out BENCHMARK_REPORT.md
```

---

## Architecture

- `src/kiberlabs_bench/guards.py`: Shared boundary guards (`validate_outbound_url`, `validate_safe_path`, `sanitize_fts5_query`, `ReplayGuard`, `validate_sku_payload`).
- `src/kiberlabs_bench/security_redteam.py`: 112-payload adversarial attack generator and evaluator across 5 threat classes.
- `src/kiberlabs_bench/runner.py`: High-resolution (`time.perf_counter_ns`) benchmark harness with exact percentile calculation, 50-thread SQLite WAL stress test, and JSON/Markdown report serialization.
- `.github/workflows/ci.yml`: Automated CI running on every `push`, `pull_request`, and weekly Monday schedule (`0 6 * * 1`) across Python `3.11` and `3.12`.
