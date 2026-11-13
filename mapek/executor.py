"""
MAPE-K Executor Component (E)
================================
Executes the adaptation plan by:
1. Deactivating the failing service
2. Activating the chosen alternative service
3. Updating the routing configuration in the Knowledge base
4. Recording the full adaptation event in history
"""
import json
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')
import requests
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from mapek import knowledge

ARCH_PATH = Path(__file__).parent.parent / "system_architecture.json"
TIMEOUT   = 3.0

# Port map for all services (used to check if alternative is reachable after activation)
SERVICE_PORTS = {
    "api-gateway":            8000,
    "auth-service":           8001, "auth-service-v2":      8011,
    "user-service":           8002, "user-service-replica": 8012,
    "product-service":        8003, "catalog-service":      8013,
    "order-service":          8004, "order-service-v2":     8014,
    "notification-service":   8025, "email-service":        8015,
    "audit-service":          8006, "logging-service":      8016,
}


def _verify_service(service_id: str) -> bool:
    """Check if a service is reachable (returns 200 on /health)."""
    port = SERVICE_PORTS.get(service_id)
    if not port:
        return False
    try:
        r = requests.get(f"http://localhost:{port}/health", timeout=TIMEOUT)
        return r.status_code == 200
    except Exception:
        return False


def execute_adaptation(plan: dict) -> list:
    """
    Execute all adaptations in the plan.
    
    Returns list of executed event records.
    """
    knowledge.set_mape_state("executing")
    executed = []

    for adaptation in plan.get("adaptations", []):
        failing_id  = adaptation["failing_service"]
        chosen_id   = adaptation["chosen_alternative"]
        reason      = adaptation["reason"]
        score_old   = adaptation.get("original_score", {})
        score_new   = adaptation.get("chosen_score", {})

        print(f"\n[Executor] Executing adaptation: '{failing_id}' → '{chosen_id}'")

        # Step 1: Mark failing service as failed in knowledge base
        knowledge.deactivate_service(failing_id, reason="failed")
        print(f"[Executor]   Deactivated '{failing_id}'")

        # Step 2: Verify the chosen alternative is reachable
        reachable = _verify_service(chosen_id)
        if reachable:
            print(f"[Executor]   ✅ Alternative '{chosen_id}' is reachable on port {SERVICE_PORTS.get(chosen_id)}")
        else:
            print(f"[Executor]   ⚠️  Alternative '{chosen_id}' not reachable — marking as active anyway (simulation mode)")

        # Step 3: Activate the chosen alternative
        knowledge.activate_service(chosen_id)
        print(f"[Executor]   Activated '{chosen_id}'")

        # Step 4: Update routing config (simulated — in real system this would update Istio VirtualService)
        _update_routing(failing_id, chosen_id)

        # Step 5: Record the adaptation event
        event = {
            "type":              "service_replacement",
            "failing_service":   failing_id,
            "chosen_service":    chosen_id,
            "reason":            reason,
            "original_completeness": score_old.get("completeness_pct", 0),
            "new_completeness":      score_new.get("completeness_pct", 0),
            "completeness_change":   round(
                score_new.get("completeness_pct", 0) - score_old.get("completeness_pct", 0), 2
            ),
            "alternative_reachable": reachable,
            "comparison":        adaptation.get("comparison", [])
        }
        knowledge.record_adaptation(event)
        executed.append(event)

        change = event["completeness_change"]
        sign   = "+" if change >= 0 else ""
        print(f"[Executor]   Completeness: {score_old.get('completeness_pct',0):.1f}% → {score_new.get('completeness_pct',0):.1f}% ({sign}{change:.1f}%)")

    return executed


def _update_routing(old_service_id: str, new_service_id: str):
    """
    Simulated routing update.
    In production: would patch Istio VirtualService or update api-gateway config.
    Here: updates the active_services in the knowledge base.
    """
    arch = json.loads(ARCH_PATH.read_text(encoding="utf-8"))
    old_port = SERVICE_PORTS.get(old_service_id, "?")
    new_port = SERVICE_PORTS.get(new_service_id, "?")
    print(f"[Executor]   Updated routing: port {old_port} ({old_service_id}) → port {new_port} ({new_service_id})")
    print(f"[Executor]   [SIMULATION] Istio VirtualService updated — traffic redirected.")


def run_once(plan: dict) -> list:
    """Single execution pass — called by MAPE-K loop."""
    if not plan.get("adaptations"):
        print("[Executor] No adaptations to execute.")
        return []
    return execute_adaptation(plan)


if __name__ == "__main__":
    kb = knowledge.get_all()
    plan = kb.get("current_plan", {})
    if plan:
        events = run_once(plan)
        print(f"\n[Executor] Executed {len(events)} adaptation(s).")
    else:
        print("[Executor] No current plan in knowledge base.")
