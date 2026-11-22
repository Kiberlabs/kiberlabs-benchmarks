"""Automated pytest suite verifying KiberLabs benchmarks, WAL concurrency, and Red-Team guards."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from kiberlabs_bench.guards import (
    ReplayGuard,
    sanitize_fts5_query,
    validate_outbound_url,
    validate_safe_path,
    validate_sku_payload,
)
from kiberlabs_bench.runner import (
    bench_gateway_auth_ratelimit,
    bench_lead_bot_nlu,
    bench_margin_sieve,
    bench_rag_fts5_bm25,
    bench_sqlite_wal_concurrency,
    main,
    render_markdown_report,
)
from kiberlabs_bench.security_redteam import run_redteam_suite


def test_benign_controls_pass_security_guards() -> None:
    """Flow: verify clean production inputs pass all 5 boundary guards with zero false positives."""
    assert validate_outbound_url("https://api.supplier-eu.example/v1/skus") == "https://api.supplier-eu.example/v1/skus"
    with tempfile.TemporaryDirectory(prefix="kl_ok_") as tmp:
        base = Path(tmp)
        resolved = validate_safe_path(base, "reports/2026/summary.csv")
        assert resolved.is_relative_to(base.resolve())

        guard = ReplayGuard(base / "events.db", secret_key=b"test-secret")
        try:
            body = b'{"ok":true}'
            ts = 1_763_800_000
            sig = guard.sign(ts, body)
            assert guard.verify_and_record("evt_clean_001", ts, body, sig, now=ts)
        finally:
            guard.close()

    assert sanitize_fts5_query("GDPR data breach 72 hours") == '"GDPR" "data" "breach" "72" "hours"'
    clean_sku = validate_sku_payload(
        {
            "sku_id": "SKU-OK-100",
            "supplier_price": 45.0,
            "resale_price": 99.0,
            "shipping_cost": 5.0,
            "fee_pct": 12.0,
            "delivery_days": 2,
            "rating": 4.8,
            "source_url": "https://catalog.example.com/item/100",
        }
    )
    assert clean_sku["sku_id"] == "SKU-OK-100"


def test_redteam_suite_blocks_100_percent_of_100_plus_payloads() -> None:
    """Flow: execute full adversarial Red-Team suite and assert >=100 payloads with 100% block rate."""
    res = run_redteam_suite()
    assert res["total_payloads"] >= 100
    assert res["bypassed_count"] == 0
    assert res["blocked_count"] == res["total_payloads"]
    assert res["block_rate_pct"] == 100.0
    assert len(res["categories"]) == 5
    for cat in res["categories"]:
        assert cat["total"] >= 20
        assert cat["bypassed"] == 0


def test_core_workloads_produce_valid_real_metrics() -> None:
    """Flow: execute all 4 core pattern benchmarks and assert monotonic percentiles and positive throughput."""
    results = [
        bench_margin_sieve(count=500),
        bench_lead_bot_nlu(count=200),
        bench_rag_fts5_bm25(doc_count=40, query_count=100),
        bench_gateway_auth_ratelimit(count=300),
    ]
    for r in results:
        assert r["ops_per_sec"] > 0
        assert 0 <= r["min_ms"] <= r["p50_ms"] <= r["p95_ms"] <= r["p99_ms"] <= r["max_ms"]
        assert r["wall_ms"] > 0


def test_sqlite_wal_50_threads_zero_lock_errors() -> None:
    """Flow: run 50 concurrent threads reading and writing SQLite WAL simultaneously and verify 0 lock errors."""
    res = bench_sqlite_wal_concurrency(workers=50, ops_per_worker=20)
    details = res["details"]
    assert details["concurrent_threads"] == 50
    assert details["journal_mode"] == "WAL"
    assert details["lock_errors"] == 0
    assert details["persisted_rows"] == 50 * 10
    assert details["reads_completed"] == 50 * 10
    assert res["ops_per_sec"] > 0


def test_cli_generates_json_and_markdown_reports(tmp_path: Path) -> None:
    """Flow: invoke CLI entrypoint targeting temporary output paths and verify schema and Markdown consistency."""
    json_out = tmp_path / "results" / "benchmark_report.json"
    md_out = tmp_path / "BENCHMARK_REPORT.md"
    exit_code = main(["--json-out", str(json_out), "--md-out", str(md_out)])
    assert exit_code == 0
    assert json_out.exists()
    assert md_out.exists()

    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert len(data["benchmarks"]) == 5
    assert data["redteam"]["total_payloads"] >= 100
    assert data["redteam"]["bypassed_count"] == 0

    md_text = md_out.read_text(encoding="utf-8")
    assert "SQLite WAL 50-Thread Concurrency" in md_text
    assert "`0` `database is locked` errors" in md_text
    assert render_markdown_report(data) == md_text
