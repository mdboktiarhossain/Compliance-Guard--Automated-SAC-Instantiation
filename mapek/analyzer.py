"""
MAPE-K Analyzer Component (A)
================================
Analyzes the collected service metrics to detect:
- Failing services (down or very high error rate)
- Degraded services (elevated error rate or low availability)
- Healthy services

Stores analysis results in the Knowledge base.
"""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from mapek import knowledge

# Thresholds
FAIL_ERROR_RATE    = 0.30   # >30% error rate → failing
FAIL_AVAILABILITY  = 70.0   # <70% availability → failing
DEGRADE_ERROR_RATE = 0.10   # >10% error rate → degraded
DEGRADE_AVAIL      = 90.0   # <90% availability → degraded


def analyze(metrics: dict) -> dict:
    """
    Analyze service metrics and classify each service.
    
    Returns:
        {
          "failing":  [service_id, ...],
          "degraded": [service_id, ...],
          "healthy":  [service_id, ...]
        }
    """
    knowledge.set_mape_state("analyzing")
    failing  = []
    degraded = []
    healthy  = []

    active_svcs = knowledge.get_active_services()
    for service_id, m in metrics.items():
        # Only analyze services that are currently active in the configuration
        if active_svcs.get(service_id) != "active":
            continue

        if not m.get("reachable", True):
            failing.append(service_id)
            print(f"  [Analyzer] ❌ FAILING   {service_id} — unreachable: {m.get('reason','')}")
            continue

        error_rate   = m.get("error_rate", 0.0)
        availability = m.get("availability", 100.0)

        if error_rate >= FAIL_ERROR_RATE or availability <= FAIL_AVAILABILITY:
            failing.append(service_id)
            print(f"  [Analyzer] ❌ FAILING   {service_id} — error_rate={error_rate:.2%}, avail={availability:.1f}%")
        elif error_rate >= DEGRADE_ERROR_RATE or availability <= DEGRADE_AVAIL:
            degraded.append(service_id)
            print(f"  [Analyzer] ⚠️  DEGRADED  {service_id} — error_rate={error_rate:.2%}, avail={availability:.1f}%")
        else:
            healthy.append(service_id)
            print(f"  [Analyzer] ✅ HEALTHY   {service_id} — error_rate={error_rate:.2%}, avail={availability:.1f}%")

    knowledge.update_analysis(failing, degraded, healthy)
    return {"failing": failing, "degraded": degraded, "healthy": healthy}


def needs_adaptation(analysis: dict) -> bool:
    """Return True if any service is failing and needs replacement."""
    return len(analysis.get("failing", [])) > 0


def run_once(metrics: dict) -> dict:
    """Single analysis pass — called by MAPE-K loop."""
    print("[Analyzer] Analyzing service health...")
    result = analyze(metrics)
    failing = result["failing"]
    degraded = result["degraded"]
    if failing:
        print(f"[Analyzer] ⚠️  {len(failing)} failing service(s) detected: {failing}")
    if degraded:
        print(f"[Analyzer] ⚠️  {len(degraded)} degraded service(s): {degraded}")
    if not failing and not degraded:
        print("[Analyzer] ✅ All services healthy — no adaptation needed.")
    return result


if __name__ == "__main__":
    metrics = knowledge.get_service_metrics()
    result = run_once(metrics)
    print(result)
