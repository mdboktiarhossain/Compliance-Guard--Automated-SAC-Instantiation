"""
user_service.py - User Profile Service (port 8002)
Manages user profiles, account lifecycle, and inter-account transfers.
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
    fake_timestamp, fake_session_id, fake_audit_id, fake_ip,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "user-service"
PORT         = 8002
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

DEPARTMENTS = ["Engineering", "Finance", "HR", "Legal", "Marketing",
               "Operations", "Security", "Compliance"]
LOCATIONS   = ["New York", "London", "Tokyo", "Berlin", "Sydney", "Toronto"]

# Simulated user store
_users: dict = {}


def _make_user_profile(user_id=None, username=None, role=None) -> dict:
    uid  = user_id  or fake_user_id()
    name = fake_name()
    return {
        "user_id":    uid,
        "username":   username or fake_email(),
        "full_name":  name,
        "role":       role or fake_role(),
        "department": random.choice(DEPARTMENTS),
        "location":   random.choice(LOCATIONS),
        "active":     True,
        "mfa_enabled": random.choice([True, False]),
        "created_at": fake_timestamp(),
        "last_login": fake_timestamp(),
    }


def handle_action(action: str, payload: dict) -> dict:
    if action == "get_user":
        user_id = payload.get("user_id", fake_user_id())
        if user_id in _users:
            profile = _users[user_id]
        else:
            profile = _make_user_profile(user_id=user_id)
            _users[user_id] = profile
        return {"profile": profile, "fetched_at": fake_timestamp()}

    elif action == "create_user":
        user_id  = fake_user_id()
        username = payload.get("username", fake_email())
        role     = payload.get("role", "viewer")
        profile  = _make_user_profile(user_id=user_id, username=username, role=role)
        _users[user_id] = profile
        return {
            "created":    True,
            "profile":    profile,
            "created_at": fake_timestamp(),
            "audit_id":   fake_audit_id(),
        }

    elif action == "update_user":
        user_id = payload.get("user_id", fake_user_id())
        updates = {k: v for k, v in payload.items() if k != "user_id"}
        if user_id in _users:
            _users[user_id].update(updates)
            profile = _users[user_id]
        else:
            profile = _make_user_profile(user_id=user_id)
            profile.update(updates)
            _users[user_id] = profile
        return {
            "updated":    True,
            "user_id":    user_id,
            "fields":     list(updates.keys()),
            "profile":    profile,
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
            "reason":        payload.get("reason", "account_policy"),
            "revoked_tokens": random.randint(1, 5),
            "audit_id":      fake_audit_id(),
        }

    elif action == "transfer_account":
        from_user = payload.get("from_user", fake_user_id())
        to_user   = payload.get("to_user",   fake_user_id())
        resources = payload.get("resources", ["files", "settings", "subscriptions"])
        return {
            "transfer_id":   fake_session_id(),
            "from_user":     from_user,
            "to_user":       to_user,
            "resources":     resources,
            "transferred":   True,
            "transferred_at": fake_timestamp(),
            "dual_approved": True,
            "approver":      fake_user_id(),
            "audit_id":      fake_audit_id(),
        }

    else:
        return {
            "message":   f"User service processed '{action}'",
            "timestamp": fake_timestamp(),
            "users_managed": len(_users) or random.randint(100, 5000),
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
