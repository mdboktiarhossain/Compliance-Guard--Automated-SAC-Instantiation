"""
service_base.py - Shared utilities for all Compliance Guard microservices.
Provides common patterns, fake-data helpers, and a simulate_traffic() function
that randomly increments in-memory metrics so dashboards look "live".
"""

import os
import time
import random
import threading
import uuid
import string


# ---------------------------------------------------------------------------
# Fake-data generators used across services
# ---------------------------------------------------------------------------

FIRST_NAMES = ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Hank",
               "Iris", "Jack", "Karen", "Leo", "Mia", "Ned", "Olivia", "Pete"]
LAST_NAMES  = ["Smith", "Jones", "Lee", "Brown", "Davis", "Miller", "Wilson",
               "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White"]
DOMAINS     = ["example.com", "corp.io", "testorg.net", "mailsim.dev"]
ROLES       = ["admin", "viewer", "editor", "auditor", "operator", "readonly"]
ACTIONS_LOG = ["login", "create_order", "view_report", "update_profile",
               "delete_record", "export_data", "change_role"]


def fake_user_id() -> str:
    return f"usr_{uuid.uuid4().hex[:8]}"


def fake_order_id() -> str:
    return f"ord_{uuid.uuid4().hex[:10].upper()}"


def fake_token() -> str:
    """Return a plausible-looking JWT-shaped string (not a real JWT)."""
    header  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = uuid.uuid4().hex + uuid.uuid4().hex
    sig     = "".join(random.choices(string.ascii_letters + string.digits + "-_", k=43))
    return f"{header}.{payload[:36]}.{sig}"


def fake_email(first=None, last=None) -> str:
    first = first or random.choice(FIRST_NAMES).lower()
    last  = last  or random.choice(LAST_NAMES).lower()
    return f"{first}.{last}@{random.choice(DOMAINS)}"


def fake_name() -> str:
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"


def fake_role() -> str:
    return random.choice(ROLES)


def fake_product_id() -> str:
    return f"prod_{uuid.uuid4().hex[:6]}"


def fake_session_id() -> str:
    return f"sess_{uuid.uuid4().hex}"


def fake_audit_id() -> str:
    return f"aud_{uuid.uuid4().hex[:12]}"


def fake_timestamp() -> str:
    """ISO-8601 timestamp offset randomly into the past (up to 7 days)."""
    t = time.time() - random.uniform(0, 7 * 86400)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def fake_ip() -> str:
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def fake_mfa_code() -> str:
    return str(random.randint(100000, 999999))


# ---------------------------------------------------------------------------
# Shared metrics store factory
# ---------------------------------------------------------------------------

def make_metrics() -> dict:
    """Return a fresh in-memory metrics dict."""
    return {
        "requests":   0,
        "errors":     0,
        "start_time": time.time(),
    }


def record_request(metrics: dict, lock: threading.Lock, error: bool = False) -> None:
    with lock:
        metrics["requests"] += 1
        if error:
            metrics["errors"] += 1


# ---------------------------------------------------------------------------
# Latency simulation
# ---------------------------------------------------------------------------

def simulate_latency(fail_mode: bool = False) -> float:
    """Return a simulated latency value in milliseconds."""
    base = 20 if not fail_mode else 500
    return random.uniform(base, base * 2)


# ---------------------------------------------------------------------------
# Health / metrics response builders
# ---------------------------------------------------------------------------

def build_health(service_name: str, port: int, metrics: dict,
                 fail_mode: bool) -> dict:
    reqs       = max(metrics["requests"], 1)
    error_rate = metrics["errors"] / reqs
    if fail_mode:
        status = "down"
        uptime = round(random.uniform(30, 60), 1)
    elif error_rate > 0.1:
        status = "degraded"
        uptime = round(min(99.9, 100 - error_rate * 100), 1)
    else:
        status = "ok"
        uptime = round(min(99.9, 100 - error_rate * 100), 1)
    return {
        "service":    service_name,
        "status":     status,
        "port":       port,
        "uptime_pct": uptime,
        "fail_mode":  fail_mode,
    }


def build_metrics(service_name: str, metrics: dict, fail_mode: bool) -> dict:
    reqs       = max(metrics["requests"], 1)
    errs       = metrics["errors"]
    error_rate = round(errs / reqs, 4)
    return {
        "service":        service_name,
        "requests_total": reqs,
        "errors_total":   errs,
        "error_rate":     error_rate,
        "latency_ms_avg": round(simulate_latency(fail_mode), 1),
        "availability":   round((1 - error_rate) * 100, 2),
    }


# ---------------------------------------------------------------------------
# simulate_traffic() - background thread that bumps metrics so dashboards
# look "live" even when no real requests arrive.
# ---------------------------------------------------------------------------

def simulate_traffic(metrics: dict, lock: threading.Lock,
                     fail_mode: bool, interval: float = 5.0) -> threading.Thread:
    """
    Spawn a daemon thread that randomly increments request/error counters
    every *interval* seconds to simulate background traffic.
    Returns the thread (already started).
    """
    def _worker():
        while True:
            time.sleep(interval + random.uniform(-1, 1))
            burst = random.randint(1, 8)
            with lock:
                metrics["requests"] += burst
                err_prob = 0.6 if fail_mode else 0.03
                metrics["errors"]   += sum(
                    1 for _ in range(burst) if random.random() < err_prob
                )

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# Common response helpers
# ---------------------------------------------------------------------------

def error_response(service_name: str, action: str, latency: float) -> dict:
    return {
        "service":    service_name,
        "action":     action,
        "result":     "error",
        "error":      "Service unavailable",
        "latency_ms": round(latency, 1),
    }


def success_response(service_name: str, action: str,
                     data: dict, latency: float) -> dict:
    return {
        "service":    service_name,
        "action":     action,
        "result":     "success",
        "data":       data,
        "latency_ms": round(latency, 1),
    }
