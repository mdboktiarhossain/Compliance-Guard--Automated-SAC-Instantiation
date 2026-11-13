"""
auth_service_v2.py - Enhanced Auth Service with MFA (port 8011)
Same as auth_service plus MFA verification, privileged action logging,
and privilege monitoring. FAIL_MODE env var supported.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_token, fake_user_id, fake_email, fake_role,
    fake_timestamp, fake_session_id, fake_mfa_code, fake_audit_id,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "auth-service-v2"
PORT         = 8011
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

_tokens: dict  = {}
_mfa_pending: dict = {}
_priv_log: list = []

PERMISSIONS_MAP = {
    "admin":    ["read", "write", "delete", "admin", "audit", "mfa_bypass"],
    "editor":   ["read", "write"],
    "viewer":   ["read"],
    "auditor":  ["read", "audit"],
    "operator": ["read", "write", "operate"],
    "readonly": ["read"],
}

PRIVILEGED_ACTIONS = {"delete_record", "export_data", "change_role",
                      "disable_account", "assign_role", "revoke_token"}


def handle_action(action: str, payload: dict) -> dict:
    if action == "login":
        username = payload.get("username", fake_email())
        role     = payload.get("role", fake_role())
        user_id  = fake_user_id()
        mfa_ref  = fake_session_id()
        _mfa_pending[mfa_ref] = {"user_id": user_id, "username": username, "role": role}
        return {
            "user_id":        user_id,
            "username":       username,
            "mfa_required":   True,
            "mfa_reference":  mfa_ref,
            "mfa_method":     random.choice(["totp", "sms", "email_otp"]),
            "expires_in":     300,
            "message":        "MFA challenge issued. Call mfa_verify to complete login.",
        }

    elif action == "mfa_verify":
        mfa_ref  = payload.get("mfa_reference", fake_session_id())
        code     = payload.get("code", fake_mfa_code())
        # Simulate: 90% success rate
        verified = random.random() > 0.10
        pending  = _mfa_pending.pop(mfa_ref, {
            "user_id":  fake_user_id(),
            "username": fake_email(),
            "role":     fake_role(),
        })

        if not verified:
            return {
                "verified":     False,
                "reason":       "invalid_or_expired_code",
                "attempts_left": random.randint(1, 2),
            }

        token = fake_token()
        _tokens[token] = {**pending, "issued_at": time.time(), "expires_in": 3600}
        return {
            "verified":    True,
            "user_id":     pending["user_id"],
            "username":    pending["username"],
            "role":        pending["role"],
            "token":       token,
            "token_type":  "Bearer",
            "expires_in":  3600,
            "issued_at":   fake_timestamp(),
            "permissions": PERMISSIONS_MAP.get(pending["role"], ["read"]),
        }

    elif action == "validate_token":
        token   = payload.get("token", "")
        valid   = token.startswith("eyJ") and random.random() > 0.08
        entry   = _tokens.get(token, {
            "user_id":  fake_user_id(),
            "username": fake_email(),
            "role":     fake_role(),
        })
        return {
            "valid":      valid,
            "token":      token[:20] + "..." if len(token) > 20 else token,
            "user_id":    entry.get("user_id"),
            "username":   entry.get("username"),
            "role":       entry.get("role"),
            "mfa_passed": True,
            "checked_at": fake_timestamp(),
        }

    elif action == "create_account":
        user_id  = fake_user_id()
        username = payload.get("username", fake_email())
        role     = payload.get("role", "viewer")
        return {
            "user_id":    user_id,
            "username":   username,
            "role":       role,
            "active":     True,
            "mfa_enrolled": False,
            "created_at": fake_timestamp(),
            "permissions": PERMISSIONS_MAP.get(role, ["read"]),
        }

    elif action == "disable_account":
        target_id = payload.get("user_id", fake_user_id())
        return {
            "user_id":     target_id,
            "disabled":    True,
            "disabled_at": fake_timestamp(),
            "reason":      payload.get("reason", "administrative_action"),
            "audit_id":    fake_audit_id(),
        }

    elif action == "assign_role":
        target_id = payload.get("user_id", fake_user_id())
        new_role  = payload.get("role", fake_role())
        return {
            "user_id":     target_id,
            "new_role":    new_role,
            "assigned_by": fake_user_id(),
            "assigned_at": fake_timestamp(),
            "permissions": PERMISSIONS_MAP.get(new_role, ["read"]),
            "audit_id":    fake_audit_id(),
        }

    elif action == "revoke_token":
        token = payload.get("token", fake_token())
        _tokens.pop(token, None)
        return {
            "token":      token[:20] + "..." if len(token) > 20 else token,
            "revoked":    True,
            "revoked_at": fake_timestamp(),
            "revoked_by": fake_user_id(),
            "audit_id":   fake_audit_id(),
        }

    elif action == "log_privileged_action":
        priv_action = payload.get("priv_action", random.choice(list(PRIVILEGED_ACTIONS)))
        actor       = payload.get("actor", fake_user_id())
        entry = {
            "audit_id":   fake_audit_id(),
            "actor":      actor,
            "action":     priv_action,
            "privileged": priv_action in PRIVILEGED_ACTIONS,
            "logged_at":  fake_timestamp(),
            "source_ip":  f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        }
        _priv_log.append(entry)
        return entry

    elif action == "monitor_privilege":
        recent = _priv_log[-10:] if _priv_log else [
            {
                "audit_id": fake_audit_id(),
                "actor":    fake_user_id(),
                "action":   random.choice(list(PRIVILEGED_ACTIONS)),
                "privileged": True,
                "logged_at":  fake_timestamp(),
            }
            for _ in range(random.randint(2, 5))
        ]
        return {
            "privileged_events_last_hour": random.randint(5, 50),
            "recent_events":               recent,
            "anomalies_detected":          random.randint(0, 3),
            "monitored_at":                fake_timestamp(),
        }

    else:
        return {
            "message":    f"Auth-v2 processed '{action}'",
            "session_id": fake_session_id(),
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
