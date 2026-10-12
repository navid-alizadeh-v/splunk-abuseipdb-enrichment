#!/usr/bin/env python3
# navid alizadeh vaghasloo 
import hashlib
import ipaddress
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

from pathlib import Path


SPLUNK_HOME = Path(
    os.environ.get("SPLUNK_HOME", "/opt/splunk")
)

APP_HOME = (
    SPLUNK_HOME
    / "etc"
    / "apps"
    / "splunk-abuseipdb-enrichment"
)

CONFIG_FILE = APP_HOME / "local" / "abuseipdb_keys.json"

STATE_DIR = (
    SPLUNK_HOME
    / "var"
    / "lib"
    / "splunk-abuseipdb-enrichment"
)

DB_FILE = STATE_DIR / "cache.sqlite3"

API_URL = "https://api.abuseipdb.com/api/v2/check"

OUTPUT_FIELDS = {
    "ipAddress": "abuseipdb_ipAddress",
    "isWhitelisted": "abuseipdb_isWhitelisted",
    "abuseConfidenceScore": "abuseipdb_abuseConfidenceScore",
    "countryCode": "abuseipdb_countryCode",
    "usageType": "abuseipdb_usageType",
    "isp": "abuseipdb_isp",
    "domain": "abuseipdb_domain",
    "hostnames": "abuseipdb_hostnames",
    "totalReports": "abuseipdb_totalReports",
    "lastReportedAt": "abuseipdb_lastReportedAt",
}


class AbuseIPDBError(Exception):
    pass


def load_config():
    if not CONFIG_FILE.is_file():
        raise AbuseIPDBError("Configuration file not found")

    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    keys = config.get("api_keys", [])

    if not isinstance(keys, list):
        raise AbuseIPDBError("api_keys must be a JSON array")

    keys = [
        key.strip()
        for key in keys
        if isinstance(key, str)
        and key.strip()
        and not key.startswith("REPLACE_WITH_")
    ]

    if not keys:
        raise AbuseIPDBError("No usable API keys configured")

    config["api_keys"] = keys
    config["max_age_in_days"] = int(
        config.get("max_age_in_days", 90)
    )
    config["cache_ttl_days"] = int(
        config.get("cache_ttl_days", 7)
    )
    config["request_timeout_seconds"] = int(
        config.get("request_timeout_seconds", 10)
    )

    if not 1 <= config["max_age_in_days"] <= 365:
        raise AbuseIPDBError("max_age_in_days must be 1..365")

    if not 1 <= config["cache_ttl_days"] <= 30:
        raise AbuseIPDBError("cache_ttl_days must be 1..30")

    if not 1 <= config["request_timeout_seconds"] <= 60:
        raise AbuseIPDBError(
            "request_timeout_seconds must be 1..60"
        )

    return config


def connect_db():
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(DB_FILE),
        timeout=15
    )

    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute("PRAGMA journal_mode = WAL")

    connection.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            checked_at INTEGER NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS key_state (
            key_hash TEXT PRIMARY KEY,
            blocked_until INTEGER NOT NULL DEFAULT 0,
            remaining INTEGER,
            reset_at INTEGER
        )
    """)

    connection.commit()
    return connection


def normalize_ip(value):
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None

    if not parsed.is_global:
        return None

    return str(parsed)


def read_cache(connection, ip, ttl_days):
    row = connection.execute(
        """
        SELECT payload, checked_at
        FROM ip_cache
        WHERE ip = ?
        """,
        (ip,)
    ).fetchone()

    if row is None:
        return None, None, None

    payload = json.loads(row[0])
    checked_at = int(row[1])

    age_seconds = max(0, int(time.time()) - checked_at)
    age_days = round(age_seconds / 86400, 3)

    is_fresh = age_seconds < ttl_days * 86400

    return payload, is_fresh, age_days


def write_cache(connection, ip, payload):
    connection.execute(
        """
        INSERT INTO ip_cache (ip, payload, checked_at)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            payload = excluded.payload,
            checked_at = excluded.checked_at
        """,
        (
            ip,
            json.dumps(payload, ensure_ascii=False),
            int(time.time())
        )
    )

    connection.commit()


def key_fingerprint(api_key):
    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


def get_key_state(connection, api_key):
    row = connection.execute(
        """
        SELECT blocked_until, remaining, reset_at
        FROM key_state
        WHERE key_hash = ?
        """,
        (key_fingerprint(api_key),)
    ).fetchone()

    if row is None:
        return {
            "blocked_until": 0,
            "remaining": None,
            "reset_at": None,
        }

    return {
        "blocked_until": int(row[0] or 0),
        "remaining": row[1],
        "reset_at": row[2],
    }


def update_key_state(
    connection,
    api_key,
    blocked_until=0,
    remaining=None,
    reset_at=None
):
    connection.execute(
        """
        INSERT INTO key_state (
            key_hash, blocked_until, remaining, reset_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(key_hash) DO UPDATE SET
            blocked_until = excluded.blocked_until,
            remaining = excluded.remaining,
            reset_at = excluded.reset_at
        """,
        (
            key_fingerprint(api_key),
            int(blocked_until or 0),
            remaining,
            reset_at
        )
    )

    connection.commit()


def header_int(headers, name):
    try:
        value = headers.get(name)
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def request_api(connection, api_key, ip, config):
    query = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": str(config["max_age_in_days"]),
    })

    request = urllib.request.Request(
        f"{API_URL}?{query}",
        headers={
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "splunk-abuseipdb-enrichment/1.0",
        },
        method="GET"
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=config["request_timeout_seconds"]
        ) as response:
            headers = response.headers
            body = response.read().decode("utf-8")
            document = json.loads(body)

            remaining = header_int(
                headers, "X-RateLimit-Remaining"
            )
            reset_at = header_int(
                headers, "X-RateLimit-Reset"
            )

            data = document.get("data")

            if not isinstance(data, dict):
                raise AbuseIPDBError(
                    "API response has no valid data object"
                )

            blocked_until = 0

            if remaining == 0 and reset_at:
                blocked_until = reset_at

            update_key_state(
                connection,
                api_key,
                blocked_until=blocked_until,
                remaining=remaining,
                reset_at=reset_at
            )

            return data

    except urllib.error.HTTPError as exc:
        headers = exc.headers

        remaining = header_int(
            headers, "X-RateLimit-Remaining"
        )
        reset_at = header_int(
            headers, "X-RateLimit-Reset"
        )
        retry_after = header_int(headers, "Retry-After")

        if exc.code == 429:
            now = int(time.time())

            if reset_at and reset_at > now:
                blocked_until = reset_at
            elif retry_after and retry_after > 0:
                blocked_until = now + retry_after
            else:
                blocked_until = now + 3600

            update_key_state(
                connection,
                api_key,
                blocked_until=blocked_until,
                remaining=0,
                reset_at=reset_at
            )

            raise AbuseIPDBError("RATE_LIMITED") from exc

        if exc.code in (401, 403):
            # Mark this key unavailable for one hour.
            # Do not include the key or response body in errors.
            update_key_state(
                connection,
                api_key,
                blocked_until=int(time.time()) + 3600,
                remaining=remaining,
                reset_at=reset_at
            )

            raise AbuseIPDBError(
                f"API_KEY_REJECTED_HTTP_{exc.code}"
            ) from exc

        raise AbuseIPDBError(
            f"API_HTTP_ERROR_{exc.code}"
        ) from exc

    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AbuseIPDBError(
            f"API_CONNECTION_ERROR_{type(exc).__name__}"
        ) from exc

    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AbuseIPDBError("API_INVALID_JSON") from exc


def lookup_online(connection, ip, config):
    now = int(time.time())
    errors = []

    for api_key in config["api_keys"]:
        state = get_key_state(connection, api_key)

        if state["blocked_until"] > now:
            continue

        try:
            payload = request_api(
                connection, api_key, ip, config
            )

            write_cache(connection, ip, payload)
            return payload

        except AbuseIPDBError as exc:
            error = str(exc)
            errors.append(error)

            if (
                error == "RATE_LIMITED"
                or error.startswith("API_KEY_REJECTED_")
            ):
                # A key-specific problem: try another key.
                continue

            # Network or service errors: avoid making a burst
            # of repeated requests with every configured key.
            break

    raise AbuseIPDBError(
        "; ".join(errors) if errors
        else "NO_API_KEY_AVAILABLE"
    )


def make_output(
    ip,
    payload,
    mode,
    cache_hit,
    age_days,
    status,
    error=""
):
    output = {
        "abuseipdb_check_mode": mode,
        "abuseipdb_cache_hit": cache_hit,
        "abuseipdb_cache_age_days": (
            age_days if age_days is not None else ""
        ),
        "abuseipdb_status": status,
        "abuseipdb_error": error,
    }

    for source, target in OUTPUT_FIELDS.items():
        value = payload.get(source, "")

        if isinstance(value, (list, dict)):
            value = json.dumps(value, ensure_ascii=False)

        if value is None:
            value = ""

        output[target] = value

    output["abuseipdb_ipAddress"] = (
        payload.get("ipAddress") or ip
    )

    return output


def enrich_ip(ip_value):
    ip = normalize_ip(ip_value)

    if ip is None:
        return {
            "abuseipdb_check_mode": "not_checked",
            "abuseipdb_cache_hit": False,
            "abuseipdb_cache_age_days": "",
            "abuseipdb_status": "invalid_or_non_public_ip",
            "abuseipdb_error": "",
        }

    try:
        config = load_config()
    except (AbuseIPDBError, OSError, ValueError, json.JSONDecodeError):
        return {
            "abuseipdb_ipAddress": ip,
            "abuseipdb_check_mode": "not_checked",
            "abuseipdb_cache_hit": False,
            "abuseipdb_cache_age_days": "",
            "abuseipdb_status": "configuration_error",
            "abuseipdb_error": "Configuration unavailable or invalid",
        }

    connection = connect_db()

    try:
        cached, fresh, age_days = read_cache(
            connection,
            ip,
            config["cache_ttl_days"]
        )

        if cached is not None and fresh:
            return make_output(
                ip,
                cached,
                mode="offline",
                cache_hit=True,
                age_days=age_days,
                status="success"
            )

        try:
            payload = lookup_online(connection, ip, config)

            return make_output(
                ip,
                payload,
                mode="online",
                cache_hit=False,
                age_days=0,
                status="success"
            )

        except AbuseIPDBError as exc:
            if cached is not None:
                return make_output(
                    ip,
                    cached,
                    mode="offline_stale",
                    cache_hit=True,
                    age_days=age_days,
                    status="stale_cache_fallback",
                    error=str(exc)
                )

            return {
                "abuseipdb_ipAddress": ip,
                "abuseipdb_check_mode": "online_failed",
                "abuseipdb_cache_hit": False,
                "abuseipdb_cache_age_days": "",
                "abuseipdb_status": "error",
                "abuseipdb_error": str(exc),
            }

    finally:
        connection.close()
