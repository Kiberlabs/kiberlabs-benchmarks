"""Automated pytest suite verifying KiberLabs benchmarks, WAL concurrency, and Red-Team guards."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import math
import random
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

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


def test_replay_guard_20_thread_stress_and_context_manager(tmp_path: Path) -> None:
    """Flow: verify 20 synchronized threads on same/unique event_ids with zero SQLite errors."""
    now_ts = int(time.time())
    body = b'{"event":"invoice.paid","amount":1500}'

    with ReplayGuard(tmp_path / "replay.db", secret_key=b"stress-key") as guard:
        sig = guard.sign(now_ts, body)
        barrier_dup = threading.Barrier(20)
        dup_ok = 0
        dup_rejected = 0
        dup_errors: list[BaseException] = []
        lock = threading.Lock()

        def hit_same_event() -> None:
            nonlocal dup_ok, dup_rejected
            try:
                barrier_dup.wait(timeout=5.0)
                guard.verify_and_record("evt_same_001", now_ts, body, sig, now=now_ts)
                with lock:
                    dup_ok += 1
            except ValueError:
                with lock:
                    dup_rejected += 1
            except BaseException as exc:  # pragma: no cover
                with lock:
                    dup_errors.append(exc)

        threads = [threading.Thread(target=hit_same_event) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        assert dup_errors == []
        assert dup_ok == 1
        assert dup_rejected == 19

        barrier_uniq = threading.Barrier(20)
        uniq_ok = 0
        uniq_errors: list[BaseException] = []

        def hit_unique_event(idx: int) -> None:
            nonlocal uniq_ok
            try:
                barrier_uniq.wait(timeout=5.0)
                if guard.verify_and_record(f"evt_uniq_{idx:03d}", now_ts, body, sig, now=now_ts):
                    with lock:
                        uniq_ok += 1
            except BaseException as exc:  # pragma: no cover
                with lock:
                    uniq_errors.append(exc)

        uniq_threads = [threading.Thread(target=hit_unique_event, args=(i,)) for i in range(20)]
        for t in uniq_threads:
            t.start()
        for t in uniq_threads:
            t.join(timeout=10.0)

        assert uniq_errors == []
        assert uniq_ok == 20


def test_sanitize_fts5_query_natural_words_and_real_fts5_execution() -> None:
    """Flow: allow lowercase/Title-Case natural words safely inside quotes while blocking uppercase FTS5 operators."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(body)")
    conn.execute(
        "INSERT INTO docs_fts (body) VALUES (?)",
        ("Breach and notification terms or conditions are not applicable near deadline; update retention or delete old backups",),
    )

    natural_queries = (
        "breach and notification",
        "terms or conditions",
        "not applicable",
        "Not found",
        "near deadline",
        "update retention policy",
        "delete old backups",
    )
    for q in natural_queries:
        sanitized = sanitize_fts5_query(q)
        assert all(part.startswith('"') and part.endswith('"') for part in sanitized.split())
        rows = conn.execute("SELECT body FROM docs_fts WHERE docs_fts MATCH ?", (sanitized,)).fetchall()
        assert isinstance(rows, list)
    assert len(conn.execute("SELECT body FROM docs_fts WHERE docs_fts MATCH ?", (sanitize_fts5_query("breach and notification"),)).fetchall()) == 1
    conn.close()

    for blocked in ("NOT compliance", "invoice OR receipt AND tax", "1 UNION SELECT sql FROM sqlite_master"):
        with pytest.raises(ValueError):
            sanitize_fts5_query(blocked)


def test_validate_outbound_url_and_path_redteam_hardening(tmp_path: Path) -> None:
    """Flow: reject tab/vtab/ff/6to4/teredo/site-local SSRF vectors and preserve ellipsis filename support."""
    bad_urls = (
        "https://example.com\t/v1",
        "https://example.com\x0b/v1",
        "https://example.com\x0c/v1",
        "http://[2002:7f00:0001::]/",
        "http://[2001:0000:7f00:0001::]/",
        "http://[fec0::1]/",
    )
    for url in bad_urls:
        with pytest.raises(ValueError):
            validate_outbound_url(url)

    assert validate_outbound_url("https://[2606:4700:4700::1111]/v1") == "https://[2606:4700:4700::1111]/v1"

    resolved = validate_safe_path(tmp_path, "reports/report...v2.csv")
    assert resolved.is_relative_to(tmp_path.resolve())
    for bad_path in (".../...//etc/passwd", "..../secret.txt"):
        with pytest.raises(ValueError):
            validate_safe_path(tmp_path, bad_path)


def test_sanitize_fts5_query_uppercase_and_rules_with_real_fts5() -> None:
    """Flow: allow interior alphabetic uppercase AND in all-caps queries while blocking operator/SQLi forms."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(body)")
    conn.execute(
        "INSERT INTO docs_fts (body) VALUES (?)",
        ("Standard TERMS AND CONDITIONS for GDPR AND NIS2 COMPLIANCE.",),
    )

    for ok_query in ("TERMS AND CONDITIONS", "GDPR AND NIS2 COMPLIANCE", "STANDARD-AND-CUSTOM"):
        sanitized = sanitize_fts5_query(ok_query)
        assert all(part.startswith('"') and part.endswith('"') for part in sanitized.split())
        rows = conn.execute("SELECT body FROM docs_fts WHERE docs_fts MATCH ?", (sanitized,)).fetchall()
        assert isinstance(rows, list)
    assert len(conn.execute("SELECT body FROM docs_fts WHERE docs_fts MATCH ?", (sanitize_fts5_query("TERMS AND CONDITIONS"),)).fetchall()) == 1
    assert len(conn.execute("SELECT body FROM docs_fts WHERE docs_fts MATCH ?", (sanitize_fts5_query("GDPR AND NIS2 COMPLIANCE"),)).fetchall()) == 1
    conn.close()

    for blocked in (
        "invoice AND 1=1",
        "INVOICE AND 1=1",
        "invoice AND tax",
        "Terms AND Conditions",
        "1 AND 1",
        "TERMS AND 1",
        "AND TERMS",
        "TERMS AND",
        "TERMS AND AND CONDITIONS",
    ):
        with pytest.raises(ValueError):
            sanitize_fts5_query(blocked)


def test_deterministic_seeded_heavy_adversarial_guard_fuzzing(tmp_path: Path) -> None:
    """Flow: deterministic seeded fuzzing across all 5 security guards."""
    rng = random.Random(20261123)

    # 1. FTS5 fuzzing (250+ cases)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(body)")
    conn.execute("INSERT INTO docs_fts (body) VALUES (?)", ("compliance audit retention policy terms conditions",))
    words_lower = ("compliance", "audit", "retention", "policy", "invoice", "breach", "gdpr")
    words_upper = ("TERMS", "CONDITIONS", "GDPR", "NIS2", "COMPLIANCE", "AUDIT")
    for i in range(130):
        if i % 2 == 0:
            q = " ".join(rng.choice(words_lower) for _ in range(rng.randint(1, 5)))
        else:
            q = f"{rng.choice(words_upper)} AND {rng.choice(words_upper)}"
        sq = sanitize_fts5_query(q)
        rows = conn.execute("SELECT body FROM docs_fts WHERE docs_fts MATCH ?", (sq,)).fetchall()
        assert isinstance(rows, list)
    conn.close()

    bad_fts_frags = ("OR", "NOT", "NEAR", "SELECT", "UNION", "PRAGMA", "'", '"', ";", "=", "(", ")", "--", "/*", "\x00")
    for i in range(130):
        if i % 3 == 0:
            bad_q = f"{rng.choice(words_lower)} AND {rng.choice(words_lower)}"
        elif i % 3 == 1:
            w = rng.choice(words_upper)
            bad_q = rng.choice([f"AND {w}", f"{w} AND", f"12 AND {w}", f"{w} AND 12", f"{w} AND AND {w}"])
        else:
            bad_q = f"{rng.choice(words_lower)} {rng.choice(bad_fts_frags)} {rng.choice(words_lower)}"
        with pytest.raises(ValueError):
            sanitize_fts5_query(bad_q)

    # 2. URL SSRF fuzzing (150+ cases)
    for i in range(80):
        oct1 = rng.choice((10, 127, 169, 172, 192, 100))
        oct2 = 254 if oct1 == 169 else (64 if oct1 == 100 else (16 if oct1 == 172 else (168 if oct1 == 192 else rng.randint(0, 255))))
        oct3 = rng.randint(0, 255)
        oct4 = rng.randint(1, 254)
        ip_int = (oct1 << 24) | (oct2 << 16) | (oct3 << 8) | oct4
        ctrl = rng.choice(["\t", "\n", "\x00"])
        bad_url = rng.choice(
            [
                f"http://{ip_int}/p",
                f"http://0x{ip_int:08x}/p",
                f"http://0{oct1:o}.{oct2}.{oct3}.{oct4}/p",
                f"http://{oct1}.{ip_int & 0xFFFFFF}/p",
                f"http://[::ffff:{oct1}.{oct2}.{oct3}.{oct4}]/p",
                f"http://[2002:{oct1:02x}{oct2:02x}:{oct3:02x}{oct4:02x}::]/p",
                f"https://user:pass@public{i}.example.com/v1",
                f"https://svc{i}.{rng.choice(['internal', 'local', 'corp', 'lan'])}/api",
                f"https://public{i}.example.com{ctrl}/v1",
            ]
        )
        with pytest.raises(ValueError):
            validate_outbound_url(bad_url)
    for i in range(75):
        ok_url = f"https://api-{i}.supplier-eu.example/v1/item/{rng.randint(1, 999)}"
        assert validate_outbound_url(ok_url) == ok_url
    assert validate_outbound_url("https://8.8.8.8/dns") == "https://8.8.8.8/dns"

    # 3. Path/Shell fuzzing (120+ cases)
    bad_path_templates = (
        "../secret_{i}.txt",
        "%2e%2e/secret_{i}.txt",
        "%252e%252e%252fsecret_{i}.txt",
        "a/../../etc/{i}",
        "..../file_{i}.csv",
        "\\\\server\\share\\file_{i}",
        "C:\\temp\\file_{i}.txt",
        "file_{i}.csv;whoami",
        "file_{i}.csv|cat",
        "file_{i}\x00.txt",
    )
    for i in range(70):
        bad_p = rng.choice(bad_path_templates).format(i=i)
        with pytest.raises(ValueError):
            validate_safe_path(tmp_path, bad_p)
    for i in range(60):
        rel = f"reports/2026/batch_{i}...v1.csv"
        resolved = validate_safe_path(tmp_path, rel)
        assert resolved.is_relative_to(tmp_path.resolve())

    # 4. SKU boundary fuzzing (120+ cases)
    base_sku = {
        "sku_id": "SKU-FZ-01",
        "supplier_price": 30.0,
        "resale_price": 80.0,
        "shipping_cost": 4.0,
        "fee_pct": 12.0,
        "delivery_days": 3,
        "rating": 4.5,
        "source_url": "https://catalog.example.com/sku/1",
    }
    for i in range(70):
        bad = dict(base_sku)
        kind = i % 7
        if kind == 0:
            bad["supplier_price"] = rng.choice([math.nan, math.inf, -math.inf, -1.0, 0.0, True])
        elif kind == 1:
            bad["resale_price"] = rng.choice([math.nan, math.inf, -5.0, 300_000.0, "99"])
        elif kind == 2:
            bad["fee_pct"] = rng.choice([-0.1, 60.1, math.nan])
        elif kind == 3:
            bad["delivery_days"] = rng.choice([0, 91, True, 3.5])
        elif kind == 4:
            bad["rating"] = rng.choice([-0.1, 5.1, math.inf])
        elif kind == 5:
            bad["source_url"] = "http://127.0.0.1/ssrf"
        else:
            del bad[rng.choice(["sku_id", "supplier_price", "source_url"])]
        with pytest.raises(ValueError):
            validate_sku_payload(bad)

    for i in range(60):
        good = {
            "sku_id": f"SKU-{i:04d}",
            "supplier_price": round(rng.uniform(1.0, 500.0), 2),
            "resale_price": round(rng.uniform(10.0, 1000.0), 2),
            "shipping_cost": round(rng.uniform(0.0, 50.0), 2),
            "fee_pct": round(rng.uniform(0.0, 60.0), 2),
            "delivery_days": rng.randint(1, 90),
            "rating": round(rng.uniform(0.0, 5.0), 2),
            "source_url": f"https://catalog.example.com/item/{i}",
        }
        assert validate_sku_payload(good)["sku_id"] == good["sku_id"]

    # 5. ReplayGuard invalid inputs (60+ cases)
    now_ts = 1_763_800_000
    body = b'{"ok":1}'
    with ReplayGuard(tmp_path / "fuzz_replay.db", secret_key=b"fuzz-secret") as rg:
        sig = rg.sign(now_ts, body)
        for i in range(64):
            kind = i % 6
            eid = f"evt_fuzz_{i}"
            ts = now_ts
            pl: Any = body
            s = sig
            if kind == 0:
                eid = rng.choice(["x", "ab", "A" * 129, 123])  # type: ignore[assignment]
            elif kind == 1:
                ts = rng.choice([0, -1, True])  # type: ignore[assignment]
            elif kind == 2:
                pl = rng.choice([b"", "str", None])
            elif kind == 3:
                s = rng.choice(["", "md5=" + "a" * 64, "sha256=short", "sha256=" + "z" * 64])
            elif kind == 4:
                ts = now_ts - rng.randint(301, 5000)
                s = rg.sign(ts, body)
            else:
                ts = now_ts + rng.randint(61, 5000)
                s = rg.sign(ts, body)
            with pytest.raises(ValueError):
                rg.verify_and_record(eid, ts, pl, s, now=now_ts)


def test_replay_guard_50_thread_wal_barrier_stress(tmp_path: Path) -> None:
    """Flow: 50-thread duplicate race + 50x10 mixed valid/replay/tampered/expired/future ops."""
    now_ts = 1_763_800_000
    body = b'{"event":"invoice.paid","amount":1500}'
    db_path = tmp_path / "replay50.db"

    with ReplayGuard(db_path, secret_key=b"stress-50-key") as guard:
        sig = guard.sign(now_ts, body)
        barrier_dup = threading.Barrier(50)

        def hit_same(_: int) -> str:
            barrier_dup.wait(timeout=10.0)
            try:
                guard.verify_and_record("evt_race_50", now_ts, body, sig, now=now_ts)
                return "ok"
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=50) as pool:
            outcomes = list(pool.map(hit_same, range(50)))
        assert outcomes.count("ok") == 1
        assert outcomes.count("rejected") == 49

        barrier_mix = threading.Barrier(50)

        def hit_mixed(wid: int) -> tuple[int, int]:
            barrier_mix.wait(timeout=10.0)
            ok_cnt = 0
            rej_cnt = 0
            for step in range(10):
                mode = step % 5
                try:
                    if mode == 0:
                        guard.verify_and_record(f"evt_m_{wid}_{step}", now_ts, body, sig, now=now_ts)
                    elif mode == 1:
                        guard.verify_and_record("evt_race_50", now_ts, body, sig, now=now_ts)
                    elif mode == 2:
                        guard.verify_and_record(f"evt_t_{wid}_{step}", now_ts, b'{"tampered":true}', sig, now=now_ts)
                    elif mode == 3:
                        exp_ts = now_ts - 400
                        guard.verify_and_record(f"evt_e_{wid}_{step}", exp_ts, body, guard.sign(exp_ts, body), now=now_ts)
                    else:
                        fut_ts = now_ts + 120
                        guard.verify_and_record(f"evt_f_{wid}_{step}", fut_ts, body, guard.sign(fut_ts, body), now=now_ts)
                    ok_cnt += 1
                except ValueError:
                    rej_cnt += 1
            return ok_cnt, rej_cnt

        with ThreadPoolExecutor(max_workers=50) as pool:
            mix_res = list(pool.map(hit_mixed, range(50)))
        assert sum(o for o, _ in mix_res) == 100  # 50 threads * 2 valid steps (0 and 5)
        assert sum(r for _, r in mix_res) == 400

    conn = sqlite3.connect(str(db_path))
    row_count = int(conn.execute("SELECT COUNT(*) FROM seen_events").fetchone()[0])
    conn.close()
    assert row_count == 101


def test_redteam_50_thread_concurrent_stress() -> None:
    """Flow: execute Red-Team suite across 50 concurrent threads behind a barrier and assert 100.0% block rate."""
    barrier = threading.Barrier(50)

    def run_once(_: int) -> tuple[int, int, float]:
        barrier.wait(timeout=15.0)
        res = run_redteam_suite()
        return res["total_payloads"], res["bypassed_count"], res["block_rate_pct"]

    with ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(run_once, range(50)))

    assert len(results) == 50
    assert all(total >= 100 and bypassed == 0 and rate == 100.0 for total, bypassed, rate in results)


class _BenchSpyConn:
    def __init__(self, inner: sqlite3.Connection, sql_log: list[str], fail_hook: Any = None) -> None:
        self._inner = inner
        self._sql_log = sql_log
        self._fail_hook = fail_hook
        self.closed = False

    @property
    def row_factory(self) -> Any:
        return self._inner.row_factory

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        self._inner.row_factory = value

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        normalized = " ".join(sql.split()).rstrip(";").upper()
        self._sql_log.append(normalized)
        if self._fail_hook is not None:
            self._fail_hook("execute", normalized)
        return self._inner.execute(sql, *args, **kwargs)

    def executescript(self, sql_script: str) -> sqlite3.Cursor:
        self._sql_log.append("EXECUTESCRIPT")
        if self._fail_hook is not None:
            self._fail_hook("executescript", sql_script)
        return self._inner.executescript(sql_script)

    def commit(self) -> None:
        self._inner.commit()

    def close(self) -> None:
        self.closed = True
        self._inner.close()

    def __enter__(self) -> _BenchSpyConn:
        self._inner.__enter__()
        return self

    def __exit__(self, *exc: object) -> bool | None:
        return self._inner.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_replay_guard_pragma_order_and_skips_redundant_wal(monkeypatch: pytest.MonkeyPatch) -> None:
    sql_log: list[str] = []
    timeouts: list[object] = []
    real_connect = sqlite3.connect

    def spy_connect(*args: object, **kwargs: object) -> _BenchSpyConn:
        timeouts.append(kwargs.get("timeout"))
        return _BenchSpyConn(real_connect(*args, **kwargs), sql_log)  # type: ignore[arg-type]

    monkeypatch.setattr(sqlite3, "connect", spy_connect)

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "replay_pragma.db"
        with ReplayGuard(db_path, secret_key=b"pragma-secret"):
            assert timeouts == [5.0]
            busy_idx = sql_log.index("PRAGMA BUSY_TIMEOUT=5000")
            mode_idx = sql_log.index("PRAGMA JOURNAL_MODE")
            wal_idx = sql_log.index("PRAGMA JOURNAL_MODE=WAL")
            assert busy_idx < mode_idx < wal_idx

        sql_log.clear()
        with ReplayGuard(db_path, secret_key=b"pragma-secret"):
            assert "PRAGMA BUSY_TIMEOUT=5000" in sql_log
            assert "PRAGMA JOURNAL_MODE" in sql_log
            assert "PRAGMA JOURNAL_MODE=WAL" not in sql_log

    sql_log.clear()
    with ReplayGuard(":memory:", secret_key=b"mem-secret") as mem_guard:
        ts = 1_763_800_000
        body = b'{"mem":true}'
        assert mem_guard.verify_and_record("evt_mem_001", ts, body, mem_guard.sign(ts, body), now=ts)
        assert "PRAGMA JOURNAL_MODE=WAL" not in sql_log


def test_replay_guard_cold_start_retry_and_tempdir_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = sqlite3.connect
    monkeypatch.setattr(time, "sleep", lambda _secs: None)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        db_path = tmp_dir / "retry.db"
        conns: list[_BenchSpyConn] = []
        sql_log: list[str] = []

        def flaky_wal_connect(*args: object, **kwargs: object) -> _BenchSpyConn:
            attempt = len(conns) + 1

            def fail_hook(kind: str, sql: str) -> None:
                if kind == "execute" and sql == "PRAGMA JOURNAL_MODE=WAL" and attempt <= 2:
                    raise sqlite3.OperationalError("database is locked")

            spy = _BenchSpyConn(real_connect(*args, **kwargs), sql_log, fail_hook)  # type: ignore[arg-type]
            conns.append(spy)
            return spy

        monkeypatch.setattr(sqlite3, "connect", flaky_wal_connect)
        guard = ReplayGuard(db_path, secret_key=b"retry-secret")
        assert len(conns) == 3
        assert conns[0].closed and conns[1].closed
        assert not conns[2].closed
        ts = 1_763_800_000
        body = b'{"ok":true}'
        assert guard.verify_and_record("evt_retry_01", ts, body, guard.sign(ts, body), now=ts)
        guard.close()
        assert conns[2].closed

    assert not tmp_dir.exists()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        db_path = tmp_dir / "always_locked.db"
        conns = []
        sql_log = []

        def always_locked_connect(*args: object, **kwargs: object) -> _BenchSpyConn:
            def fail_hook(kind: str, sql: str) -> None:
                if kind == "execute" and sql == "PRAGMA JOURNAL_MODE=WAL":
                    raise sqlite3.OperationalError("database is locked")

            spy = _BenchSpyConn(real_connect(*args, **kwargs), sql_log, fail_hook)  # type: ignore[arg-type]
            conns.append(spy)
            return spy

        monkeypatch.setattr(sqlite3, "connect", always_locked_connect)
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            ReplayGuard(db_path, secret_key=b"fail-secret")
        assert len(conns) == 6
        assert all(c.closed for c in conns)

    assert not tmp_dir.exists()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        db_path = tmp_dir / "non_lock.db"
        conns = []
        sql_log = []

        def non_lock_connect(*args: object, **kwargs: object) -> _BenchSpyConn:
            def fail_hook(kind: str, sql: str) -> None:
                if kind == "execute" and sql == "PRAGMA JOURNAL_MODE=WAL":
                    raise sqlite3.OperationalError("disk I/O error")

            spy = _BenchSpyConn(real_connect(*args, **kwargs), sql_log, fail_hook)  # type: ignore[arg-type]
            conns.append(spy)
            return spy

        monkeypatch.setattr(sqlite3, "connect", non_lock_connect)
        with pytest.raises(sqlite3.OperationalError, match="disk I/O"):
            ReplayGuard(db_path, secret_key=b"io-secret")
        assert len(conns) == 1
        assert conns[0].closed

    assert not tmp_dir.exists()
