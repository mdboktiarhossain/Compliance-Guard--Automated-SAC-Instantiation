"""
user_service_replica.py - User Service Replica (port 8012)
Same as user_service but on port 8012, adds monitor_usage action for
observability and compliance dashboards.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_user_id, fake_email, fake_name, fake_role,
    fake_timestamp, fake_session_id, fake_audit_id,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "user-service-replica"
PORT         = 8012
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

DEPARTMENTS = ["Engineering", "Finance", "HR", "Legal", "Marketing",
               "Operations", "Security", "Compliance"]
LOCATIONS   = ["New York", "London", "Tokyo", "Berlin", "Sydney", "Toronto"]

_users: dict = {}


def _make_user_profile(user_id=None, username=None, role=None) -> dict:
    uid = user_id or fake_user_id()
    return {
        "user_id":    uid,
        "username":   username or fake_email(),
        "full_name":  fake_name(),
        "role":       role or fake_role(),
        "department": random.choice(DEPARTMENTS),
        "location":   random.choice(LOCATIONS),
        "active":     True,
        "mfa_enabled": random.choice([True, False]),
        "created_at": fake_timestamp(),
        "last_login": fake_timestamp(),
        "replica":    True,
    }


def handle_action(action: str, payload: dict) -> dict:
    if action == "get_user":
        user_id = payload.get("user_id", fake_user_id())
        if user_id not in _users:
            _users[user_id] = _make_user_profile(user_id=user_id)
        return {"profile": _users[user_id], "fetched_at": fake_timestamp(), "source": "replica"}

    elif action == "create_user":
        user_id  = fake_user_id()
        username = payload.get("username", fake_email())
        role     = payload.get("role", "viewer")
        profile  = _make_user_profile(user_id=user_id, username=username, role=role)
        _users[user_id] = profile
        return {"created": True, "profile": profile, "audit_id": fake_audit_id()}

    elif action == "update_user":
        user_id = payload.get("user_id", fake_user_id())
        updates = {k: v for k, v in payload.items() if k != "user_id"}
        if user_id not in _users:
            _users[user_id] = _make_user_profile(user_id=user_id)
        _users[user_id].update(updates)
        return {
            "updated":    True,
            "user_id":    user_id,
            "fields":     list(updates.keys()),
            "updated_at": fake_timestamp(),
            "audit_id":   fake_audit_id(),
        }

    elif action == "deactivate_user":
        user_id = payload.get("user_id", fake_user_id())
        if user_id in _users:
            _users[user_id]["active"] = False
        return {
            "user_id":       user_id,
            "deactivated":   True,
            "deactivated_at": fake_timestamp(),
            "audit_id":      fake_audit_id(),
        }

    elif action == "transfer_account":
        from_user = payload.get("from_user", fake_user_id())
        to_user   = payload.get("to_user",   fake_user_id())
        return {
            "transfer_id":    fake_session_id(),
            "from_user":      from_user,
            "to_user":        to_user,
            "transferred":    True,
            "transferred_at": fake_timestamp(),
            "dual_approved":  True,
            "approver":       fake_user_id(),
            "audit_id":       fake_audit_id(),
        }

    elif action == "monitor_usage":
        # Unique to replica - provides usage statistics
        total_users  = len(_users) or random.randint(200, 8000)
        active_users = int(total_users * random.uniform(0.6, 0.95))
        return {
            "total_users":          total_users,
            "active_users":         active_users,
            "inactive_users":       total_users - active_users,
            "logins_last_24h":      random.randint(50, 500),
            "failed_logins_24h":    random.randint(0, 20),
            "mfa_adoption_pct":     round(random.uniform(60, 99), 1),
            "privileged_users":     random.randint(5, 30),
            "accounts_deactivated": random.randint(0, 10),
            "anomalies_detected":   random.randint(0, 5),
            "monitored_at":         fake_timestamp(),
            "source":               "replica",
        }

    else:
        return {
            "message":   f"User-replica processed '{action}'",
            "timestamp": fake_timestamp(),
            "source":    "replica",
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
