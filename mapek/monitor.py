"""
MAPE-K Monitor Component (M)
==============================
Polls each microservice's /health and /metrics endpoints
and stores results in the Knowledge base.
"""
import requests
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from mapek import knowledge

# Only monitor the main (non-alternative) services
MONITORED_SERVICES = {
    "api-gateway":          "http://localhost:8000",
    "auth-service":         "http://localhost:8001",
    "user-service":         "http://localhost:8002",
    "product-service":      "http://localhost:8003",
    "order-service":        "http://localhost:8004",
    "notification-service": "http://localhost:8025",
    "audit-service":        "http://localhost:8006",
}

TIMEOUT = 2.0  # seconds


def collect_metrics() -> dict:
    """
    Poll all monitored services and return collected metrics.
    Also updates the Knowledge base.
    """
    results = {}
    try:
        current_metrics = knowledge.get_service_metrics()
    except Exception:
        current_metrics = {}

    for service_id, base_url in MONITORED_SERVICES.items():
        # Preserve simulated failures from the dashboard
        curr = current_metrics.get(service_id, {})
        if not curr.get("reachable", True) and curr.get("reason") == "Simulated failure via API":
            print(f"  [Monitor] {service_id:30s} preserving simulated failure")
            results[service_id] = curr
            continue

        try:
            resp = requests.get(f"{base_url}/metrics", timeout=TIMEOUT)
            if resp.status_code == 200:
                metrics = resp.json()
                metrics["reachable"] = True
                metrics["status"] = "ok"
            else:
                metrics = _unreachable_metrics(service_id, f"HTTP {resp.status_code}")
        except requests.exceptions.ConnectionError:
            metrics = _unreachable_metrics(service_id, "ConnectionError - service down")
        except requests.exceptions.Timeout:
            metrics = _unreachable_metrics(service_id, "Timeout")
        except Exception as e:
            metrics = _unreachable_metrics(service_id, str(e))

        results[service_id] = metrics
        knowledge.update_metrics(service_id, metrics)
        _log(service_id, metrics)

    return results


def _unreachable_metrics(service_id: str, reason: str) -> dict:
    return {
        "service": service_id,
        "reachable": False,
        "status": "down",
        "requests_total": 0,
        "errors_total": 0,
        "error_rate": 1.0,
        "latency_ms_avg": 9999.0,
        "availability": 0.0,
        "reason": reason
    }


def _log(service_id: str, metrics: dict):
    status = metrics.get("status", "?")
    avail  = metrics.get("availability", 0)
    err    = metrics.get("error_rate", 0)
    print(f"  [Monitor] {service_id:30s} status={status:9s}  availability={avail:.1f}%  error_rate={err:.3f}")


def run_once():
    """Single monitoring pass — called by the MAPE-K loop."""
    knowledge.set_mape_state("monitoring")
    print("[Monitor] Collecting metrics from all services...")
    return collect_metrics()


if __name__ == "__main__":
    results = run_once()
    print(f"\n[Monitor] Collected metrics for {len(results)} services.")
