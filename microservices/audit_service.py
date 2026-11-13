"""
audit_service.py - Audit Logging Service (port 8006)
Logs privileged function calls, monitors account usage, reviews compliance.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_user_id, fake_timestamp, fake_audit_id, fake_session_id, fake_ip,
    ACTIONS_LOG,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "audit-service"
PORT         = 8006
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

COMPLIANCE_FRAMEWORKS = ["NIST SP 800-53", "HIPAA", "PCI-DSS", "SOC 2", "ISO 27001", "GDPR"]
SEVERITY_LEVELS       = ["info", "low", "medium", "high", "critical"]
PRIVILEGED_FUNCS      = ["delete_record", "export_data", "change_role",
                         "disable_account", "assign_role", "revoke_token",
                         "modify_policy", "override_control"]

_audit_log: list = []


def _gen_log_entry(event_type: str, details: dict) -> dict:
    entry = {
        "audit_id":   fake_audit_id(),
        "event_type": event_type,
        "severity":   random.choice(SEVERITY_LEVELS),
        "details":    details,
        "source_ip":  fake_ip(),
        "logged_at":  fake_timestamp(),
        "immutable":  True,
        "checksum":   "".join(random.choices("0123456789abcdef", k=32)),
    }
    _audit_log.append(entry)
    return entry


def handle_action(action: str, payload: dict) -> dict:
    if action == "log_privileged_function":
        func_name = payload.get("function",  random.choice(PRIVILEGED_FUNCS))
        actor     = payload.get("actor",     fake_user_id())
        target    = payload.get("target",    fake_user_id())
        entry = _gen_log_entry("privileged_function_call", {
            "function":    func_name,
            "actor":       actor,
            "target":      target,
            "authorized":  random.random() > 0.05,
            "parameters":  payload.get("parameters", {}),
        })
        return {
            "logged":    True,
            "audit":     entry,
            "retention": "7 years",
        }

    elif action == "monitor_account_usage":
        user_id = payload.get("user_id", fake_user_id())
        period  = payload.get("period_hours", 24)

        events = [
            {
                "timestamp":  fake_timestamp(),
                "action":     random.choice(ACTIONS_LOG),
                "source_ip":  fake_ip(),
                "success":    random.random() > 0.05,
            }
            for _ in range(random.randint(5, 30))
        ]
        anomalies = [e for e in events if not e["success"]]

        return {
            "user_id":            user_id,
            "period_hours":       period,
            "total_events":       len(events),
            "failed_events":      len(anomalies),
            "anomalies_detected": len(anomalies) > 3,
            "events_sample":      events[:5],
            "risk_score":         round(len(anomalies) / max(len(events), 1) * 100, 1),
            "monitored_at":       fake_timestamp(),
        }

    elif action == "review_compliance":
        framework   = payload.get("framework", random.choice(COMPLIANCE_FRAMEWORKS))
        scope       = payload.get("scope",     "full_system")
        total_ctrls = random.randint(80, 250)
        passed      = random.randint(int(total_ctrls * 0.80), total_ctrls)
        failed      = total_ctrls - passed

        findings = [
            {
                "control_id":  f"{framework[:3].upper()}-{random.randint(100, 999)}",
                "status":      "fail",
                "severity":    random.choice(["low", "medium", "high"]),
                "description": f"Control deficiency detected in {random.choice(['access','logging','encryption','monitoring'])} domain",
                "remediation": "Review and update control implementation",
            }
            for _ in range(min(failed, 5))
        ]

        return {
            "framework":         framework,
            "scope":             scope,
            "total_controls":    total_ctrls,
            "passed":            passed,
            "failed":            failed,
            "compliance_score":  round(passed / total_ctrls * 100, 1),
            "findings":          findings,
            "review_date":       fake_timestamp(),
            "next_review":       fake_timestamp(),
            "audit_id":          fake_audit_id(),
        }

    else:
        return {
            "message":    f"Audit service processed '{action}'",
            "log_entries": len(_audit_log) or random.randint(0, 100000),
            "timestamp":  fake_timestamp(),
        }


# ---------------------------------------------------------------------------
# Standard endpoints
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify(build_health(SERVICE_NAME, PORT, metrics, FAIL_MODE))


@app.route("/metrics")
def get_metrics():
    return jsonify(build_metrics(SERVICE_NAME, metrics, FAIL_MODE))


@app.route("/request", methods=["POST"])
def handle_request():
    data    = request.get_json() or {}
    latency = simulate_latency(FAIL_MODE)
    time.sleep(latency / 1000)

    if FAIL_MODE or random.random() < 0.02:
        record_request(metrics, metrics_lock, error=True)
        return jsonify(error_response(SERVICE_NAME, data.get("action", "unknown"), latency)), \
               503 if FAIL_MODE else 500

    record_request(metrics, metrics_lock)
    result = handle_action(data.get("action", "default"), data.get("payload", {}))
    return jsonify(success_response(SERVICE_NAME, data.get("action", "unknown"), result, latency))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
