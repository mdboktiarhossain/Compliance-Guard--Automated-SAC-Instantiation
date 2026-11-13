"""
start_all.py - Launch all 14 Compliance Guard microservices in separate processes.

Usage:
    python start_all.py               # normal mode
    python start_all.py --fail        # start all services in FAIL_MODE
    python start_all.py --fail auth   # start only 'auth' services in FAIL_MODE

Press Ctrl+C to stop all services.
"""

import os
import sys
import time
import subprocess
import signal
import threading

# ---------------------------------------------------------------------------
# Service registry
# ---------------------------------------------------------------------------
SERVICES = [
    # (script_name,            friendly_name,          port)
    ("api_gateway.py",          "api-gateway",          8000),
    ("auth_service.py",         "auth-service",         8001),
    ("auth_service_v2.py",      "auth-service-v2",      8011),
    ("user_service.py",         "user-service",         8002),
    ("user_service_replica.py", "user-service-replica", 8012),
    ("product_service.py",      "product-service",      8003),
    ("catalog_service.py",      "catalog-service",      8013),
    ("order_service.py",        "order-service",        8004),
    ("order_service_v2.py",     "order-service-v2",     8014),
    ("notification_service.py", "notification-service", 8025),
    ("email_service.py",        "email-service",        8015),
    ("audit_service.py",        "audit-service",        8006),
    ("logging_service.py",      "logging-service",      8016),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESET   = "\033[0m"
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"

def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def _stream_output(proc: subprocess.Popen, name: str) -> None:
    """Drain stdout/stderr of a child process to console (prefixed with service name)."""
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                print(f"  [{name}] {line}")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main launcher
# ---------------------------------------------------------------------------

def main() -> None:
    args      = sys.argv[1:]
    fail_mode = "--fail" in args
    filter_kw = [a for a in args if not a.startswith("--")]

    script_dir = os.path.dirname(os.path.abspath(__file__))
    processes: list[tuple[str, int, subprocess.Popen]] = []

    print()
    print(color("=" * 60, BOLD))
    print(color("  Compliance Guard – Microservice Launcher", BOLD))
    print(color("=" * 60, BOLD))
    if fail_mode:
        print(color("  ⚠  FAIL_MODE=true  (all services will return 503s)", YELLOW))
    print()

    env = os.environ.copy()
    if fail_mode:
        env["FAIL_MODE"] = "true"

    for script, name, port in SERVICES:
        # Optional keyword filter
        if filter_kw and not any(kw in name for kw in filter_kw):
            continue

        script_path = os.path.join(script_dir, script)
        if not os.path.exists(script_path):
            print(color(f"  ✗ MISSING  {name:30s}  (port {port})  – {script} not found", RED))
            continue

        try:
            proc = subprocess.Popen(
                [sys.executable, script_path],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=script_dir,
            )
            processes.append((name, port, proc))

            # Drain output in background thread
            t = threading.Thread(target=_stream_output, args=(proc, name), daemon=True)
            t.start()

            print(color(f"  ✓ STARTED  {name:30s}  (port {port})  [PID {proc.pid}]", GREEN))

        except Exception as exc:
            print(color(f"  ✗ FAILED   {name:30s}  (port {port})  – {exc}", RED))

    print()
    print(color(f"  Started {len(processes)} / {len(SERVICES)} service(s).", CYAN))
    print(color("  Waiting 3s for startup...", CYAN))
    print()
    time.sleep(3)

    # Health check
    try:
        import urllib.request, json as _json
        print(color("  Health check results:", BOLD))
        for name, port, proc in processes:
            if proc.poll() is not None:
                print(f"    {color('✗ EXITED', RED)}   {name:30s} (port {port})")
                continue
            try:
                url  = f"http://localhost:{port}/health"
                resp = urllib.request.urlopen(url, timeout=2)
                data = _json.loads(resp.read())
                status = data.get("status", "?")
                sym  = color("✓ OK     ", GREEN) if status == "ok" else color(f"~ {status:7s}", YELLOW)
                print(f"    {sym}  {name:30s}  uptime={data.get('uptime_pct','?')}%")
            except Exception as e:
                print(f"    {color('? NO RESP', YELLOW)}  {name:30s}  ({e})")
        print()
    except ImportError:
        pass

    print(color("  All services running. Press Ctrl+C to stop.", CYAN))
    print()

    # ---------------------------------------------------------------------------
    # Wait for Ctrl+C
    # ---------------------------------------------------------------------------
    reported_exits: set = set()
    try:
        while True:
            # Check for unexpected exits – only warn once per service
            for name, port, proc in processes:
                if name not in reported_exits and proc.poll() is not None:
                    print(color(f"  ⚠  {name} exited unexpectedly (code {proc.returncode})", YELLOW))
                    reported_exits.add(name)
            time.sleep(5)

    except KeyboardInterrupt:
        print()
        print(color("  Stopping all services...", YELLOW))
        for name, port, proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
                print(color(f"  ✓ stopped {name}", GREEN))
            except subprocess.TimeoutExpired:
                proc.kill()
                print(color(f"  ✗ killed  {name}", RED))
            except Exception as exc:
                print(color(f"  ✗ error stopping {name}: {exc}", RED))
        print()
        print(color("  All services stopped. Goodbye.", BOLD))


if __name__ == "__main__":
    main()
