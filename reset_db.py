import json
from pathlib import Path
from datetime import datetime, timezone

KB_PATH = Path(__file__).parent / "knowledge_base.json"

def main():
    print("Resetting database (from scratch)...")

    # Start with a clean dictionary from scratch (ignore current corrupt file)
    data = {}

    # Reset active services to primary only
    data["active_services"] = {
        "api-gateway": "active",
        "auth-service": "active",
        "user-service": "active",
        "product-service": "active",
        "order-service": "active",
        "notification-service": "active",
        "audit-service": "active",
        "auth-service-v2": "inactive",
        "user-service-replica": "inactive",
        "catalog-service": "inactive",
        "order-service-v2": "inactive",
        "email-service": "inactive",
        "logging-service": "inactive"
    }

    # Reset metrics to healthy defaults
    now_str = datetime.now(timezone.utc).isoformat()
    data["service_metrics"] = {
        svc: {
            "service": svc,
            "availability": 100.0,
            "error_rate": 0.0,
            "errors_total": 0,
            "latency_ms_avg": 20.0,
            "requests_total": 100,
            "reachable": True,
            "status": "ok",
            "timestamp": now_str
        }
        for svc in [
            "api-gateway", "auth-service", "user-service", "product-service",
            "order-service", "notification-service", "audit-service"
        ]
    }

    # Reset adaptation states
    data["sac_instances"] = {}
    data["completeness_scores"] = {}
    data["adaptation_history"] = []
    data["current_plan"] = {}
    data["current_analysis"] = {
        "failing_services": [],
        "degraded_services": [],
        "healthy_services": [
            "api-gateway", "auth-service", "user-service", "product-service",
            "order-service", "notification-service", "audit-service"
        ],
        "timestamp": now_str
    }
    data["mape_state"] = "idle"
    data["loop_iteration"] = 0
    data["last_updated"] = now_str

    # Save to file
    with open(KB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    print("[SUCCESS] database (knowledge_base.json) successfully reset and repaired!")

if __name__ == "__main__":
    main()
