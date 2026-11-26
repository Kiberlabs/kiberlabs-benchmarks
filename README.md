# kiberlabs-benchmarks

[![CI](https://github.com/Kiberlabs/kiberlabs-benchmarks/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiberlabs/kiberlabs-benchmarks/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/downloads/)
[![Zero Runtime Deps](https://img.shields.io/badge/runtime%20deps-0%20(stdlib)-10b981.svg)](pyproject.toml)

Reproducible performance, **50-thread & 16-thread SQLite WAL zero-lock concurrency**, and **122-payload Adversarial Red-Team Security** benchmark harness for [KiberLabs](https://kiberlabs.github.io) B2B automation engines.

- **Live Visual Dashboard:** [kiberlabs.github.io/benchmarks.html](https://kiberlabs.github.io/benchmarks.html)
- **Trust & Architecture Decisions (ADRs):** [kiberlabs.github.io/trust.html](https://kiberlabs.github.io/trust.html)
- **Interactive Fixed-Price SOW PDF Generator:** [kiberlabs.github.io/sow.html](https://kiberlabs.github.io/sow.html)


> **Public Evaluation Sandbox & Scope Note:** This repository contains the open reference core and deterministic `pytest` harness operating on synthetic fixtures (`data/sample_*`) under the [MIT License](LICENSE). Production connectors (live anti-bot scrapers, WhatsApp/Telegram cloud webhooks, ERP/SAP & VIES adapters, and multi-tenant deployment manifests) are maintained in **KiberLabs Private Enterprise Repositories** and delivered under client SOW.
---

## Measured Reference Results (`v0.1.0`)

Generated directly by `runner.py` (`2026-11-25T23:54:21Z`, Python `3.15.2`, Windows 11 AMD64, 12 CPUs — full raw data in [`results/benchmark_report.json`](results/benchmark_report.json) and [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)):

| Workload | Ops | Measured Throughput | p50 (ms) | p95 (ms) | p99 (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **Margin Sieve** (3-Stage Deterministic Filter) | 10,000 | **36,819.9 SKUs/sec** | 0.0258 | 0.0316 | 0.0472 |
| **Lead Bot** Bilingual EN/ES NLU + WAL Dedup | 2,000 | **73,419.6 msgs/sec** | 0.0118 | 0.0179 | 0.0807 |
| **Grounded RAG** SQLite FTS5 BM25 | 1,000 | **7,196.6 queries/sec** | 0.1546 | 0.1716 | 0.2756 |
| **FastAPI Gateway** HMAC Auth + Rate Limit | 2,000 | **1,026,430.6 reqs/sec** | 0.0006 | 0.0006 | 0.0008 |
| **SQLite WAL 50-Thread Concurrency** | 2,000 | **133.1 ops/sec** | 0.0464 | 0.2273 | 7861.8501 |
| **Telegram Maintenance Manual FTS5 RAG** | 1,000 | **2,738.8 queries/sec** | 0.3799 | 0.5189 | 0.7319 |
| **Telegram 64-bit `update_id` 16-Thread WAL** | 640 | **189.5 ops/sec** | 0.0330 | 0.1422 | 1630.3953 |

- **SQLite WAL Zero-Lock Guarantee:** 50 concurrent threads (`1,000` writes + `1,000` reads -> `1,000` persisted rows, `0` `database is locked` errors) plus 16-thread 64-bit `update_id` WAL (`490` unique inserts + `150` duplicate replays blocked, `0` lock errors).
- **Adversarial Red-Team Suite:** **122 / 122 (100.00%)** attack payloads deterministically blocked across 5 categories (`SSRF & Cloud Metadata`, `Path Traversal & Shell Injection`, `FTS5 & SQL Injection`, `Webhook Replay & HMAC Storms`, `Invalid & Malformed Boundary Inputs`) with **0 bypasses**.

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
- `src/kiberlabs_bench/security_redteam.py`: 122-payload adversarial attack generator and evaluator across 5 threat classes.
- `src/kiberlabs_bench/runner.py`: High-resolution (`time.perf_counter_ns`) benchmark harness with exact percentile calculation, 50-thread SQLite WAL stress test, and JSON/Markdown report serialization.
- `.github/workflows/ci.yml`: Automated CI running on every `push`, `pull_request`, and weekly Monday schedule (`0 6 * * 1`) across Python `3.11` and `3.12`.

---

## License

[MIT](LICENSE) — Built by **KiberLabs Engineering** (*AI & Python Automation Studio*).
