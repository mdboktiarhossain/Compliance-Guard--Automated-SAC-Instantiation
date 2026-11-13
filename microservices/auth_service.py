"""
auth_service.py - Authentication & Authorization Service (port 8001)
JWT auth + RBAC. Supports login, token validation, account management.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_token, fake_user_id, fake_email, fake_name, fake_role,
    fake_timestamp, fake_session_id,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "auth-service"
PORT         = 8001
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

# Simulated in-memory token store
_tokens: dict = {}
_accounts: dict = {}

PERMISSIONS_MAP = {
    "admin":    ["read", "write", "delete", "admin", "audit"],
    "editor":   ["read", "write"],
    "viewer":   ["read"],
    "auditor":  ["read", "audit"],
    "operator": ["read", "write", "operate"],
    "readonly": ["read"],
}


def handle_action(action: str, payload: dict) -> dict:
    if action == "login":
        username = payload.get("username", fake_email())
        password = payload.get("password", "***")
        role     = payload.get("role", fake_role())
        user_id  = fake_user_id()
        token    = fake_token()

        _tokens[token] = {
            "user_id":  user_id,
            "username": username,
            "role":     role,
            "issued_at": time.time(),
            "expires_in": 3600,
        }

        return {
            "user_id":     user_id,
            "username":    username,
            "role":        role,
            "token":       token,
            "token_type":  "Bearer",
            "expires_in":  3600,
            "issued_at":   fake_timestamp(),
            "permissions": PERMISSIONS_MAP.get(role, ["read"]),
        }

    elif action == "validate_token":
        token   = payload.get("token", "")
        # Simulate valid if token looks JWT-shaped; otherwise ~10% invalid
        valid   = token.startswith("eyJ") and random.random() > 0.1
        entry   = _tokens.get(token, {
            "user_id":  fake_user_id(),
            "username": fake_email(),
            "role":     fake_role(),
        })
        return {
            "valid":     valid,
            "token":     token[:20] + "..." if len(token) > 20 else token,
            "user_id":   entry.get("user_id"),
            "username":  entry.get("username"),
            "role":      entry.get("role"),
            "checked_at": fake_timestamp(),
            "reason":    None if valid else "token_expired_or_invalid",
        }

    elif action == "create_account":
        user_id  = fake_user_id()
        username = payload.get("username", fake_email())
        role     = payload.get("role", "viewer")
        _accounts[user_id] = {
            "username": username,
            "role":     role,
            "active":   True,
            "created":  fake_timestamp(),
        }
        return {
            "user_id":    user_id,
            "username":   username,
            "role":       role,
            "active":     True,
            "created_at": fake_timestamp(),
            "permissions": PERMISSIONS_MAP.get(role, ["read"]),
        }

    elif action == "disable_account":
        target_id = payload.get("user_id", fake_user_id())
        if target_id in _accounts:
            _accounts[target_id]["active"] = False
        return {
            "user_id":     target_id,
            "disabled":    True,
            "disabled_at": fake_timestamp(),
            "reason":      payload.get("reason", "administrative_action"),
        }

    elif action == "assign_role":
        target_id  = payload.get("user_id", fake_user_id())
        new_role   = payload.get("role", fake_role())
        old_role   = fake_role()
        return {
            "user_id":     target_id,
            "old_role":    old_role,
            "new_role":    new_role,
            "assigned_by": fake_user_id(),
            "assigned_at": fake_timestamp(),
            "permissions": PERMISSIONS_MAP.get(new_role, ["read"]),
        }

    elif action == "revoke_token":
        token = payload.get("token", fake_token())
        _tokens.pop(token, None)
        return {
            "token":      token[:20] + "..." if len(token) > 20 else token,
            "revoked":    True,
            "revoked_at": fake_timestamp(),
            "revoked_by": fake_user_id(),
        }

    else:
        return {
            "message":       f"Auth service processed '{action}'",
            "session_id":    fake_session_id(),
            "timestamp":     fake_timestamp(),
            "active_tokens": len(_tokens),
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
