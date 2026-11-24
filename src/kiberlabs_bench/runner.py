"""Reproducible performance, SQLite WAL concurrency, and Red-Team benchmark harness."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import sqlite3
import tempfile
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kiberlabs_bench import __version__
from kiberlabs_bench.guards import sanitize_fts5_query, validate_sku_payload
from kiberlabs_bench.security_redteam import run_redteam_suite

_SPAM_RE = re.compile(r"\b(crypto|airdrop|casino|betting|forex|viagra|free money)\b", re.IGNORECASE)
_BUDGET_RE = re.compile(r"(?:€|\$|eur|usd)?\s*(\d{3,5})\s*(?:€|\$|eur|usd)?", re.IGNORECASE)
_EN_NEED_RE = re.compile(r"\b(scraper|bot|rag|api|invoice|automation|python)\b", re.IGNORECASE)
_ES_NEED_RE = re.compile(r"\b(scraping|bot|facturas|automatizacion|precios|whatsapp|consulta)\b", re.IGNORECASE)


def compute_latency_stats(samples_ns: list[int], total_wall_ns: int) -> dict[str, float | int]:
    """Flow: sort nanosecond latency samples and compute exact min/p50/p95/p99/max (ms) and ops/sec."""
    if not samples_ns:
        raise ValueError("Latency sample list cannot be empty")
    ordered = sorted(samples_ns)
    n = len(ordered)

    def pct(p: float) -> float:
        idx = min(n - 1, max(0, int((p / 100.0) * (n - 1))))
        return round(ordered[idx] / 1e6, 4)

    wall_sec = max(total_wall_ns / 1e9, 1e-9)
    return {
        "operations": n,
        "wall_ms": round(total_wall_ns / 1e6, 2),
        "ops_per_sec": round(n / wall_sec, 1),
        "min_ms": round(ordered[0] / 1e6, 4),
        "p50_ms": pct(50.0),
        "p95_ms": pct(95.0),
        "p99_ms": pct(99.0),
        "max_ms": round(ordered[-1] / 1e6, 4),
    }


def bench_margin_sieve(count: int = 10_000) -> dict[str, Any]:
    """Flow: run deterministic 3-stage Margin Sieve + boundary/SSRF validation across `count` synthetic B2B SKUs."""
    payloads = [
        {
            "sku_id": f"SKU-{i:05d}",
            "supplier_price": 25.0 + (i % 90),
            "resale_price": 65.0 + (i % 150),
            "shipping_cost": 4.5 + (i % 5),
            "fee_pct": 12.0,
            "delivery_days": 1 + (i % 6),
            "rating": 3.8 + ((i % 12) * 0.1),
            "source_url": f"https://catalog.supplier-eu.example/sku/{i}",
            "in_stock": (i % 10) != 0,
            "eu_dispatch": (i % 7) != 0,
        }
        for i in range(count)
    ]

    approved = 0
    rejected = 0
    samples_ns: list[int] = []
    t_wall0 = time.perf_counter_ns()
    for raw in payloads:
        t0 = time.perf_counter_ns()
        sku = validate_sku_payload(raw)
        # Stage 1: hard operational gates
        if not sku["in_stock"] or not sku["eu_dispatch"] or sku["delivery_days"] > 5 or sku["rating"] < 4.2:
            rejected += 1
        else:
            # Stage 2: deterministic net-margin calculation
            fee_eur = sku["resale_price"] * (sku["fee_pct"] / 100.0)
            return_reserve = sku["resale_price"] * 0.04
            net_profit = sku["resale_price"] - sku["supplier_price"] - sku["shipping_cost"] - fee_eur - return_reserve
            net_margin_pct = (net_profit / sku["resale_price"]) * 100.0
            if net_margin_pct >= 20.0 and net_profit >= 15.0:
                approved += 1
            else:
                rejected += 1
        samples_ns.append(time.perf_counter_ns() - t0)
    wall_ns = time.perf_counter_ns() - t_wall0

    stats = compute_latency_stats(samples_ns, wall_ns)
    return {
        "id": "margin_sieve",
        "name": "Margin Sieve (3-Stage Deterministic Filter)",
        "unit": "SKUs/sec",
        **stats,
        "details": {"approved": approved, "rejected": rejected, "llm_tokens_used": 0},
    }


def bench_lead_bot_nlu(count: int = 2_000) -> dict[str, Any]:
    """Flow: execute bilingual EN/ES zero-token NLU + spam blocking + SQLite WAL webhook dedup across `count` turns."""
    messages = (
        "Hi we need a Python scraper with $900 budget asap",
        "Hola buscamos automatizacion de facturas presupuesto 1200 EUR",
        "Free crypto airdrop bonus click now!",
        "Need a FastAPI RAG bot for 1500 USD",
        "Necesitamos bot whatsapp para cualificar leads 800 eur",
    )
    qualified = 0
    spam_blocked = 0
    samples_ns: list[int] = []

    with tempfile.TemporaryDirectory(prefix="kl_bench_bot_") as tmp:
        conn = sqlite3.connect(str(Path(tmp) / "bot.db"), timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("CREATE TABLE webhook_dedup (msg_id TEXT PRIMARY KEY, state TEXT NOT NULL)")
        conn.commit()
        try:
            t_wall0 = time.perf_counter_ns()
            for i in range(count):
                msg = messages[i % len(messages)]
                msg_id = f"wh_{i:06d}"
                t0 = time.perf_counter_ns()
                if _SPAM_RE.search(msg):
                    state = "spam_blocked"
                    spam_blocked += 1
                else:
                    need = _EN_NEED_RE.search(msg) or _ES_NEED_RE.search(msg)
                    budget_m = _BUDGET_RE.search(msg)
                    budget = int(budget_m.group(1)) if budget_m else 0
                    if need and budget >= 400:
                        state = "handoff_ready"
                        qualified += 1
                    else:
                        state = "qualifying"
                conn.execute("INSERT INTO webhook_dedup (msg_id, state) VALUES (?, ?)", (msg_id, state))
                if (i + 1) % 100 == 0:
                    conn.commit()
                samples_ns.append(time.perf_counter_ns() - t0)
            conn.commit()
            wall_ns = time.perf_counter_ns() - t_wall0
        finally:
            conn.close()

    stats = compute_latency_stats(samples_ns, wall_ns)
    return {
        "id": "lead_bot_nlu",
        "name": "Lead Bot Bilingual NLU + WAL Dedup",
        "unit": "msgs/sec",
        **stats,
        "details": {"qualified": qualified, "spam_blocked": spam_blocked, "llm_tokens_used": 0},
    }


def bench_rag_fts5_bm25(doc_count: int = 200, query_count: int = 1_000) -> dict[str, Any]:
    """Flow: populate SQLite FTS5 BM25 corpus of `doc_count` policy articles and run `query_count` grounded queries."""
    queries = (
        "personal data breach notification 72 hours",
        "conservacion facturas electronicas plazo legal",
        "SQLite WAL busy timeout lock contention",
        "HMAC API key constant time verification",
        "sourdough pizza oven temperature",  # deliberate abstention control
    )
    grounded = 0
    abstained = 0
    samples_ns: list[int] = []

    with tempfile.TemporaryDirectory(prefix="kl_bench_rag_") as tmp:
        conn = sqlite3.connect(str(Path(tmp) / "rag.db"), timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(doc_id UNINDEXED, article, body, sha256 UNINDEXED)")

        seed_articles = (
            ("REG-GDPR-ART33", "Article 33", "Personal data breach notification to supervisory authority within 72 hours."),
            ("NORM-ES-FACTURA", "Articulo 29", "Conservacion obligatoria de facturas electronicas durante plazo legal de 6 años."),
            ("ADR-001-WAL", "Section 1", "SQLite WAL journal mode with busy timeout 5000 eliminates concurrent read write lock contention."),
            ("ADR-003-HMAC", "Section 3", "FastAPI gateway enforces HMAC API key constant time verification and rate limiting."),
        )
        rows = []
        for idx in range(doc_count):
            doc_id, article, body = seed_articles[idx % len(seed_articles)]
            full_body = f"{body} Clause revision {idx}."
            digest = hashlib.sha256(full_body.encode("utf-8")).hexdigest()[:16]
            rows.append((f"{doc_id}-{idx:03d}", article, full_body, digest))
        conn.executemany("INSERT INTO docs_fts (doc_id, article, body, sha256) VALUES (?, ?, ?, ?)", rows)
        conn.commit()

        try:
            t_wall0 = time.perf_counter_ns()
            for i in range(query_count):
                raw_q = queries[i % len(queries)]
                t0 = time.perf_counter_ns()
                safe_q = sanitize_fts5_query(raw_q)
                hits = conn.execute(
                    "SELECT doc_id, sha256, bm25(docs_fts) AS rank FROM docs_fts WHERE docs_fts MATCH ? ORDER BY rank LIMIT 3",
                    (safe_q,),
                ).fetchall()
                if hits:
                    grounded += 1
                else:
                    abstained += 1
                samples_ns.append(time.perf_counter_ns() - t0)
            wall_ns = time.perf_counter_ns() - t_wall0
        finally:
            conn.close()

    stats = compute_latency_stats(samples_ns, wall_ns)
    return {
        "id": "rag_fts5_bm25",
        "name": "Grounded RAG SQLite FTS5 BM25",
        "unit": "queries/sec",
        **stats,
        "details": {"corpus_articles": doc_count, "grounded": grounded, "abstained": abstained},
    }


def bench_gateway_auth_ratelimit(count: int = 2_000) -> dict[str, Any]:
    """Flow: benchmark FastAPI Gateway HMAC X-API-Key constant-time auth + sliding-window rate limiter across `count` requests."""
    secret = b"kiberlabs-gateway-master-key"
    expected_token = hmac.new(secret, b"tenant-alpha", hashlib.sha256).hexdigest()
    bad_token = hmac.new(secret, b"tenant-invalid", hashlib.sha256).hexdigest()
    limit_per_window = 60
    window_sec = 60.0
    buckets: dict[str, deque[float]] = {}

    allowed = 0
    throttled = 0
    unauthorized = 0
    samples_ns: list[int] = []

    t_wall0 = time.perf_counter_ns()
    base_ts = 1_763_800_000.0
    for i in range(count):
        tenant = f"tenant-{i % 25}"
        token = bad_token if (i % 20 == 0) else expected_token
        now_ts = base_ts + (i * 0.02)
        t0 = time.perf_counter_ns()

        if not hmac.compare_digest(token, expected_token):
            unauthorized += 1
        else:
            q = buckets.setdefault(tenant, deque())
            cutoff = now_ts - window_sec
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit_per_window:
                throttled += 1
            else:
                q.append(now_ts)
                allowed += 1
        samples_ns.append(time.perf_counter_ns() - t0)
    wall_ns = time.perf_counter_ns() - t_wall0

    stats = compute_latency_stats(samples_ns, wall_ns)
    return {
        "id": "gateway_auth_ratelimit",
        "name": "FastAPI Gateway HMAC Auth + Rate Limit",
        "unit": "reqs/sec",
        **stats,
        "details": {"allowed": allowed, "throttled": throttled, "unauthorized": unauthorized},
    }


def bench_sqlite_wal_concurrency(workers: int = 50, ops_per_worker: int = 40) -> dict[str, Any]:
    """Flow: launch `workers` concurrent threads reading/writing one SQLite WAL DB simultaneously and verify 0 lock errors."""
    samples_lock = threading.Lock()
    all_samples_ns: list[int] = []
    lock_errors = 0
    writes_done = 0
    reads_done = 0

    with tempfile.TemporaryDirectory(prefix="kl_bench_wal_") as tmp:
        db_path = Path(tmp) / "concurrent_wal.db"
        init_conn = sqlite3.connect(str(db_path), timeout=5.0)
        init_conn.execute("PRAGMA journal_mode=WAL")
        init_conn.execute("PRAGMA synchronous=NORMAL")
        init_conn.execute("PRAGMA busy_timeout=5000")
        init_conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, worker_id INTEGER NOT NULL, seq INTEGER NOT NULL, payload TEXT NOT NULL)"
        )
        init_conn.commit()
        init_conn.close()

        barrier = threading.Barrier(workers)

        def _worker(wid: int) -> tuple[list[int], int, int, int]:
            local_samples: list[int] = []
            local_locks = 0
            local_writes = 0
            local_reads = 0
            conn = sqlite3.connect(str(db_path), timeout=30.0)
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA synchronous=NORMAL")
            try:
                barrier.wait()
                for seq in range(ops_per_worker):
                    t0 = time.perf_counter_ns()
                    try:
                        if seq % 2 == 0:
                            conn.execute(
                                "INSERT INTO events (worker_id, seq, payload) VALUES (?, ?, ?)",
                                (wid, seq, f"w{wid}-s{seq}"),
                            )
                            conn.commit()
                            local_writes += 1
                        else:
                            conn.execute(
                                "SELECT COUNT(*) FROM events WHERE worker_id = ?",
                                (wid,),
                            ).fetchone()
                            local_reads += 1
                    except sqlite3.OperationalError as exc:
                        if "locked" in str(exc).lower():
                            local_locks += 1
                        else:
                            raise
                    local_samples.append(time.perf_counter_ns() - t0)
            finally:
                conn.close()
            return local_samples, local_locks, local_writes, local_reads

        t_wall0 = time.perf_counter_ns()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_worker, wid) for wid in range(workers)]
            for fut in futures:
                s, errs, w, r = fut.result()
                with samples_lock:
                    all_samples_ns.extend(s)
                    lock_errors += errs
                    writes_done += w
                    reads_done += r
        wall_ns = time.perf_counter_ns() - t_wall0

        verify_conn = sqlite3.connect(str(db_path))
        persisted_rows = int(verify_conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        journal_mode = str(verify_conn.execute("PRAGMA journal_mode").fetchone()[0]).upper()
        verify_conn.close()

    stats = compute_latency_stats(all_samples_ns, wall_ns)
    return {
        "id": "sqlite_wal_concurrency",
        "name": "SQLite WAL 50-Thread Concurrency",
        "unit": "ops/sec",
        **stats,
        "details": {
            "concurrent_threads": workers,
            "ops_per_thread": ops_per_worker,
            "writes_committed": writes_done,
            "reads_completed": reads_done,
            "persisted_rows": persisted_rows,
            "journal_mode": journal_mode,
            "lock_errors": lock_errors,
        },
    }


def run_all_benchmarks() -> dict[str, Any]:
    """Flow: execute all 5 core performance/concurrency benchmarks plus the 100+ payload Red-Team suite and return JSON report."""
    benchmarks = [
        bench_margin_sieve(),
        bench_lead_bot_nlu(),
        bench_rag_fts5_bm25(),
        bench_gateway_auth_ratelimit(),
        bench_sqlite_wal_concurrency(),
    ]
    redteam = run_redteam_suite()
    return {
        "schema_version": "1.0",
        "benchmark_suite_version": __version__,
        "environment": {
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python_version": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "cpu_count": os.cpu_count() or 1,
        },
        "benchmarks": benchmarks,
        "redteam": redteam,
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    """Flow: format measured JSON benchmark and Red-Team results into a deterministic Markdown report."""
    env = report["environment"]
    rt = report["redteam"]
    lines = [
        "# KiberLabs Reproducible Benchmark & Red-Team Report",
        "",
        f"- **Generated (UTC):** `{env['timestamp_utc']}`",
        f"- **Suite Version:** `v{report['benchmark_suite_version']}`",
        f"- **Runtime:** Python `{env['python_version']}` on `{env['platform']}` (`{env['cpu_count']}` CPUs)",
        "",
        "## 1. Performance & Zero-Lock Concurrency Benchmarks",
        "",
        "| Workload | Ops | Throughput | p50 (ms) | p95 (ms) | p99 (ms) | Wall (ms) |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for b in report["benchmarks"]:
        lines.append(
            f"| {b['name']} | {b['operations']:,} | **{b['ops_per_sec']:,.1f} {b['unit']}** | "
            f"{b['p50_ms']:.4f} | {b['p95_ms']:.4f} | {b['p99_ms']:.4f} | {b['wall_ms']:.2f} |"
        )

    wal = next(b for b in report["benchmarks"] if b["id"] == "sqlite_wal_concurrency")
    wd = wal["details"]
    lines.extend(
        [
            "",
            f"**SQLite WAL Verification:** `{wd['concurrent_threads']}` concurrent threads, "
            f"`{wd['writes_committed']:,}` writes + `{wd['reads_completed']:,}` reads, "
            f"`{wd['persisted_rows']:,}` persisted rows, journal mode `{wd['journal_mode']}`, "
            f"**`{wd['lock_errors']}` `database is locked` errors**.",
            "",
            "## 2. Adversarial Red-Team Security Suite",
            "",
            f"**Overall Block Rate:** **{rt['blocked_count']} / {rt['total_payloads']} ({rt['block_rate_pct']:.2f}%)** "
            f"blocked in `{rt['duration_ms']:.2f} ms` (`{rt['bypassed_count']}` bypassed).",
            "",
            "| Attack Category | Payloads | Blocked | Bypassed | Block Rate | Time (ms) |",
            "| :--- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for cat in rt["categories"]:
        lines.append(
            f"| {cat['name']} | {cat['total']} | {cat['blocked']} | {cat['bypassed']} | "
            f"**{cat['block_rate_pct']:.2f}%** | {cat['duration_ms']:.3f} |"
        )
    lines.extend(
        [
            "",
            "---",
            "*Reproduce locally with zero external dependencies:* `pip install -e . && kiberlabs-bench`",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Flow: parse CLI paths, run all real benchmarks + Red-Team suite, write JSON and Markdown outputs."""
    parser = argparse.ArgumentParser(description="Run KiberLabs reproducible benchmarks and Red-Team suite.")
    parser.add_argument("--json-out", default="results/benchmark_report.json", help="Output JSON report path")
    parser.add_argument("--md-out", default="BENCHMARK_REPORT.md", help="Output Markdown summary path")
    args = parser.parse_args(argv)

    report = run_all_benchmarks()
    json_path = Path(args.json_out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    md_path = Path(args.md_out)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown_report(report), encoding="utf-8")

    rt = report["redteam"]
    wal = next(b for b in report["benchmarks"] if b["id"] == "sqlite_wal_concurrency")
    print(
        f"KiberLabs Benchmarks OK | {len(report['benchmarks'])} workloads | "
        f"WAL lock_errors={wal['details']['lock_errors']} | "
        f"RedTeam={rt['blocked_count']}/{rt['total_payloads']} ({rt['block_rate_pct']}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
