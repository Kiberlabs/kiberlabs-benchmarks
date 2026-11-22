"""Production security boundary guards for KiberLabs automation engines."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_METADATA_NET = ipaddress.ip_network("169.254.0.0/16")

_INTERNAL_HOSTS = frozenset(
    {
        "localhost",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)
_INTERNAL_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".lan",
    ".home.arpa",
    ".corp",
    ".intranet",
)

_SHELL_META_RE = re.compile(r"[\x00-\x1f\x7f;|&`$><(){}*?'\"!]")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_HOST_CHARS_RE = re.compile(r"^[a-z0-9.-]+$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SKU_ID_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")

_FTS_FORBIDDEN_CHARS_RE = re.compile(r"[\x00-\x1f\x7f'\"`;*^:(){}=\\]|--|/\*|\*/")
_FTS_FORBIDDEN_KEYWORDS_RE = re.compile(
    r"\b(AND|OR|NOT|NEAR|SELECT|UNION|DROP|DELETE|INSERT|UPDATE|ATTACH|PRAGMA|SQLITE_MASTER)\b",
    re.IGNORECASE,
)
_FTS_TOKEN_RE = re.compile(r"[0-9A-Za-zÀ-ÿ_-]{2,40}")


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Flow: unwrap IPv4-mapped IPv6 addresses, then reject any non-public address range."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _CGNAT_NET or ip in _METADATA_NET:
            return True
    return False


def _parse_obfuscated_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Flow: detect single-integer, hex, octal, or shorthand dotted IPv4 hostnames."""
    try:
        # Single integer (decimal, 0x hex, or 0o/0 octal) e.g. 2130706433 or 0x7f000001
        if "." not in host:
            if host.startswith(("0x", "0X")):
                val = int(host, 16)
            elif host.startswith("0") and len(host) > 1 and host.isdigit():
                val = int(host, 8)
            elif host.isdigit():
                val = int(host, 10)
            else:
                return None
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
            return None
    except ValueError:
        return None

    parts = host.split(".")
    if 2 <= len(parts) <= 4:
        nums: list[int] = []
        has_obfuscation = len(parts) != 4
        for part in parts:
            if not part:
                return None
            try:
                if part.startswith(("0x", "0X")):
                    has_obfuscation = True
                    nums.append(int(part, 16))
                elif part.startswith("0") and len(part) > 1 and part.isdigit():
                    has_obfuscation = True
                    nums.append(int(part, 8))
                elif part.isdigit():
                    nums.append(int(part, 10))
                else:
                    return None
            except ValueError:
                return None
        if has_obfuscation:
            # Resolve shorthand/octal/hex IPv4 into a 32-bit integer (BSD inet_aton rules)
            if len(nums) == 4 and all(0 <= n <= 255 for n in nums):
                return ipaddress.IPv4Address((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3])
            if len(nums) == 2 and 0 <= nums[0] <= 255 and 0 <= nums[1] <= 0xFFFFFF:
                return ipaddress.IPv4Address((nums[0] << 24) | nums[1])
            if len(nums) == 3 and 0 <= nums[0] <= 255 and 0 <= nums[1] <= 255 and 0 <= nums[2] <= 0xFFFF:
                return ipaddress.IPv4Address((nums[0] << 24) | (nums[1] << 16) | nums[2])
    return None


def validate_outbound_url(url: str) -> str:
    """Flow: enforce http(s) scheme, reject credentials/internal suffixes, and block private/metadata/obfuscated IPs."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError("Invalid URL length or type")
    if any(ch in url for ch in ("\r", "\n", "\x00", " ")):
        raise ValueError("URL contains forbidden whitespace or control characters")

    parsed = urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("Embedded credentials in URL are forbidden")

    raw_host = parsed.hostname
    if not raw_host:
        raise ValueError("URL missing hostname")
    host = raw_host.lower().rstrip(".")

    if host in _INTERNAL_HOSTS or any(host.endswith(sfx) for sfx in _INTERNAL_SUFFIXES):
        raise ValueError(f"Internal hostname blocked: {host!r}")

    # Direct IPv4/IPv6 check
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = _parse_obfuscated_ipv4(host)

    if ip_obj is not None:
        if _is_forbidden_ip(ip_obj):
            raise ValueError(f"Non-public IP blocked: {ip_obj}")
        return url

    if "." not in host or not _HOST_CHARS_RE.match(host):
        raise ValueError(f"Invalid public hostname: {host!r}")
    return url


def validate_safe_path(base_dir: Path, untrusted_path: str) -> Path:
    """Flow: decode percent-encoding, block shell metacharacters/traversal/absolute roots, and confine path inside base_dir."""
    if not isinstance(untrusted_path, str) or not untrusted_path.strip() or len(untrusted_path) > 512:
        raise ValueError("Invalid path input")

    candidates = [untrusted_path]
    decoded = untrusted_path
    for _ in range(2):
        decoded = unquote(decoded)
        candidates.append(decoded)

    for candidate in candidates:
        if _SHELL_META_RE.search(candidate):
            raise ValueError("Path contains forbidden shell or control metacharacters")
        if candidate.startswith(("/", "\\", "~")) or _DRIVE_RE.match(candidate) or ":" in candidate:
            raise ValueError("Absolute paths, UNC paths, and drive letters are forbidden")
        segments = [seg for seg in re.split(r"[/\\]+", candidate) if seg != ""]
        if not segments or any(seg in (".", "..") or "..." in seg for seg in segments):
            raise ValueError("Path traversal segment detected")

    resolved_base = base_dir.resolve()
    target = (resolved_base / untrusted_path).resolve()
    if target == resolved_base or not target.is_relative_to(resolved_base):
        raise ValueError("Resolved path escapes base directory")
    return target


def sanitize_fts5_query(raw_query: str) -> str:
    """Flow: reject SQL/FTS5 injection operators and control syntax, then return strictly quoted safe FTS5 terms."""
    if not isinstance(raw_query, str) or not raw_query.strip() or len(raw_query) > 256:
        raise ValueError("Invalid FTS5 query input")
    if _FTS_FORBIDDEN_CHARS_RE.search(raw_query):
        raise ValueError("Forbidden SQL/FTS5 syntax character detected")
    if _FTS_FORBIDDEN_KEYWORDS_RE.search(raw_query):
        raise ValueError("Forbidden SQL/FTS5 operator keyword detected")

    tokens = _FTS_TOKEN_RE.findall(raw_query)[:12]
    if not tokens:
        raise ValueError("Query contains no valid searchable tokens")
    return " ".join(f'"{tok}"' for tok in tokens)


class ReplayGuard:
    """Atomic HMAC-SHA256 webhook signature, timestamp freshness, and SQLite WAL replay guard."""

    def __init__(
        self,
        db_path: Path | str,
        secret_key: bytes,
        max_age_sec: int = 300,
        max_future_skew_sec: int = 60,
    ) -> None:
        """Flow: initialize SQLite WAL seen_events table with busy_timeout=5000 for atomic event deduplication."""
        self._secret = secret_key
        self._max_age = max_age_sec
        self._max_future = max_future_skew_sec
        self._conn = sqlite3.connect(str(db_path), timeout=5.0, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS seen_events (event_id TEXT PRIMARY KEY, seen_at INTEGER NOT NULL)"
        )
        self._conn.commit()

    def sign(self, timestamp: int, payload: bytes) -> str:
        """Flow: compute canonical sha256=<hex> HMAC signature over '<timestamp>.<payload>'."""
        msg = f"{timestamp}.".encode("utf-8") + payload
        digest = hmac.new(self._secret, msg, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def verify_and_record(
        self,
        event_id: str,
        timestamp: int,
        payload: bytes,
        signature: str,
        now: int | None = None,
    ) -> bool:
        """Flow: validate event_id, enforce timestamp window, verify constant-time HMAC, and atomically record event_id."""
        if not isinstance(event_id, str) or not (4 <= len(event_id) <= 128):
            raise ValueError("Invalid event_id")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp <= 0:
            raise ValueError("Invalid webhook timestamp")
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise ValueError("Empty or invalid webhook payload")
        if not isinstance(signature, str) or not signature.startswith("sha256="):
            raise ValueError("Missing or malformed sha256 signature prefix")

        hex_sig = signature[7:]
        if not _HEX_RE.match(hex_sig):
            raise ValueError("Malformed hex HMAC digest")

        current_ts = int(time.time()) if now is None else now
        if current_ts - timestamp > self._max_age:
            raise ValueError("Webhook timestamp expired")
        if timestamp - current_ts > self._max_future:
            raise ValueError("Webhook timestamp skew too far in future")

        expected = self.sign(timestamp, bytes(payload))
        if not hmac.compare_digest(expected, signature):
            raise ValueError("HMAC signature mismatch")

        try:
            self._conn.execute(
                "INSERT INTO seen_events (event_id, seen_at) VALUES (?, ?)",
                (event_id, current_ts),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Duplicate webhook replay blocked: {event_id}") from exc
        return True

    def close(self) -> None:
        self._conn.close()


def _strict_float(val: Any, name: str) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"Field {name!r} must be numeric")
    fval = float(val)
    if not math.isfinite(fval):
        raise ValueError(f"Field {name!r} must be finite")
    return fval


def validate_sku_payload(payload: Any) -> dict[str, Any]:
    """Flow: validate types, finite numeric bounds, SKU identifier pattern, and outbound SSRF safety."""
    if not isinstance(payload, dict):
        raise ValueError("SKU payload must be a dict")

    required = (
        "sku_id",
        "supplier_price",
        "resale_price",
        "shipping_cost",
        "fee_pct",
        "delivery_days",
        "rating",
        "source_url",
    )
    missing = [k for k in required if k not in payload]
    if missing:
        raise ValueError(f"Missing required SKU fields: {missing}")

    sku_id = payload["sku_id"]
    if not isinstance(sku_id, str) or not _SKU_ID_RE.match(sku_id):
        raise ValueError("Invalid sku_id format")

    supplier_price = _strict_float(payload["supplier_price"], "supplier_price")
    resale_price = _strict_float(payload["resale_price"], "resale_price")
    shipping_cost = _strict_float(payload["shipping_cost"], "shipping_cost")
    fee_pct = _strict_float(payload["fee_pct"], "fee_pct")
    rating = _strict_float(payload["rating"], "rating")

    delivery_days = payload["delivery_days"]
    if isinstance(delivery_days, bool) or not isinstance(delivery_days, int):
        raise ValueError("delivery_days must be an integer")

    if supplier_price <= 0 or supplier_price > 100_000:
        raise ValueError("supplier_price out of valid range")
    if resale_price <= 0 or resale_price > 250_000:
        raise ValueError("resale_price out of valid range")
    if shipping_cost < 0 or shipping_cost > 10_000:
        raise ValueError("shipping_cost out of valid range")
    if not (0.0 <= fee_pct <= 60.0):
        raise ValueError("fee_pct must be between 0 and 60")
    if not (1 <= delivery_days <= 90):
        raise ValueError("delivery_days must be between 1 and 90")
    if not (0.0 <= rating <= 5.0):
        raise ValueError("rating must be between 0 and 5")

    safe_url = validate_outbound_url(payload["source_url"])
    return {
        "sku_id": sku_id,
        "supplier_price": supplier_price,
        "resale_price": resale_price,
        "shipping_cost": shipping_cost,
        "fee_pct": fee_pct,
        "delivery_days": delivery_days,
        "rating": rating,
        "source_url": safe_url,
        "in_stock": bool(payload.get("in_stock", True)),
        "eu_dispatch": bool(payload.get("eu_dispatch", True)),
    }
