"""
logging_service.py - Enhanced Logging Service (port 8016)
Extends audit_service with non-privileged enforcement, real-time alerting,
and violation detection capabilities.
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
SERVICE_NAME = "logging-service"
PORT         = 8016
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

COMPLIANCE_FRAMEWORKS = ["NIST SP 800-53", "HIPAA", "PCI-DSS", "SOC 2", "ISO 27001", "GDPR"]
SEVERITY_LEVELS       = ["info", "low", "medium", "high", "critical"]
PRIVILEGED_FUNCS      = ["delete_record", "export_data", "change_role",
                         "disable_account", "assign_role", "revoke_token",
                         "modify_policy", "override_control"]
VIOLATION_TYPES       = [
    "unauthorized_access", "privilege_escalation", "data_exfiltration",
    "policy_bypass", "integrity_violation", "anomalous_volume",
    "off_hours_access", "multiple_failed_logins"
]

_log_store: list  = []
_alert_queue: list = []


def _log_event(event_type: str, severity: str, details: dict) -> dict:
    entry = {
        "log_id":     fake_audit_id(),
        "event_type": event_type,
        "severity":   severity,
        "details":    details,
        "source_ip":  fake_ip(),
        "logged_at":  fake_timestamp(),
        "immutable":  True,
        "checksum":   "".join(random.choices("0123456789abcdef", k=32)),
    }
    _log_store.append(entry)
    return entry


def handle_action(action: str, payload: dict) -> dict:
    if action == "log_privileged_function":
        func_name = payload.get("function",  random.choice(PRIVILEGED_FUNCS))
        actor     = payload.get("actor",     fake_user_id())
        entry = _log_event("privileged_function_call",
                           random.choice(["medium", "high"]),
                           {"function": func_name, "actor": actor,
                            "authorized": random.random() > 0.05})
        return {"logged": True, "entry": entry, "retention": "7 years"}

    elif action == "monitor_account_usage":
        user_id = payload.get("user_id", fake_user_id())
        period  = payload.get("period_hours", 24)
        events  = [
            {"timestamp": fake_timestamp(), "action": random.choice(ACTIONS_LOG),
             "source_ip": fake_ip(), "success": random.random() > 0.05}
            for _ in range(random.randint(5, 30))
        ]
        fails = [e for e in events if not e["success"]]
        return {
            "user_id":            user_id,
            "period_hours":       period,
            "total_events":       len(events),
            "failed_events":      len(fails),
            "anomalies_detected": len(fails) > 3,
            "risk_score":         round(len(fails) / max(len(events), 1) * 100, 1),
            "monitored_at":       fake_timestamp(),
        }

    elif action == "review_compliance":
        framework   = payload.get("framework", random.choice(COMPLIANCE_FRAMEWORKS))
        total_ctrls = random.randint(80, 250)
        passed      = random.randint(int(total_ctrls * 0.80), total_ctrls)
        failed      = total_ctrls - passed
        return {
            "framework":        framework,
            "total_controls":   total_ctrls,
            "passed":           passed,
            "failed":           failed,
            "compliance_score": round(passed / total_ctrls * 100, 1),
            "review_date":      fake_timestamp(),
            "audit_id":         fake_audit_id(),
        }

    elif action == "enforce_non_privileged":
        user_id     = payload.get("user_id",     fake_user_id())
        action_req  = payload.get("action",      random.choice(ACTIONS_LOG))
        user_role   = payload.get("role",        "viewer")
        priv_needed = action_req in PRIVILEGED_FUNCS
        has_priv    = user_role in ["admin", "operator"]
        permitted   = not priv_needed or has_priv
        entry = _log_event("non_privileged_enforcement",
                           "high" if not permitted else "info",
                           {"user_id": user_id, "action": action_req,
                            "role": user_role, "permitted": permitted})
        return {
            "user_id":         user_id,
            "action":          action_req,
            "role":            user_role,
            "requires_priv":   priv_needed,
            "access_granted":  permitted,
            "policy":          "least_privilege",
            "reason": "insufficient privileges" if not permitted else "access within privilege scope",
            "log_entry":       entry,
        }

    elif action == "real_time_alert":
        alert_type = payload.get("alert_type", random.choice(VIOLATION_TYPES))
        user_id    = payload.get("user_id",    fake_user_id())
        severity   = payload.get("severity",   random.choice(["medium", "high", "critical"]))
        alert = {
            "alert_id":      fake_audit_id(),
            "alert_type":    alert_type,
            "user_id":       user_id,
            "severity":      severity,
            "source_ip":     fake_ip(),
            "auto_response": random.choice(["notify_admin", "block_session",
                                            "require_mfa", "lock_account"]),
            "triggered_at":  fake_timestamp(),
            "acknowledged":  False,
        }
        _alert_queue.append(alert)
        _log_event("real_time_alert", severity, alert)
        return {
            "alert_sent":   True,
            "alert":        alert,
            "queue_depth":  len(_alert_queue),
        }

    elif action == "detect_violation":
        scope      = payload.get("scope",   "full_system")
        since      = payload.get("since",   fake_timestamp())
        num_viol   = random.randint(0, 8)
        violations = [
            {
                "violation_id":   fake_audit_id(),
                "violation_type": random.choice(VIOLATION_TYPES),
                "user_id":        fake_user_id(),
                "severity":       random.choice(["medium", "high", "critical"]),
                "detected_at":    fake_timestamp(),
                "evidence":       {"events_count": random.randint(1, 50),
                                   "source_ip": fake_ip()},
                "auto_remediated": random.choice([True, False]),
            }
            for _ in range(num_viol)
        ]
        return {
            "scope":              scope,
            "since":              since,
            "violations_found":   num_viol,
            "violations":         violations,
            "high_severity":      sum(1 for v in violations if v["severity"] in ["high", "critical"]),
            "auto_remediated":    sum(1 for v in violations if v["auto_remediated"]),
            "scan_completed_at":  fake_timestamp(),
            "audit_id":           fake_audit_id(),
        }

    else:
        return {
            "message":    f"Logging service processed '{action}'",
            "log_size":   len(_log_store) or random.randint(0, 500000),
            "alert_queue": len(_alert_queue),
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
