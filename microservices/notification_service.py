"""
notification_service.py - Push Notification Service (port 8005)
Handles push notifications, remote access authorization, and subscriptions.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_user_id, fake_email, fake_timestamp, fake_audit_id, fake_session_id,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "notification-service"
PORT         = 8025
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

CHANNELS      = ["push", "sms", "email", "in_app", "webhook"]
NOTIF_TYPES   = ["alert", "info", "warning", "critical", "compliance_event"]
ACCESS_LEVELS = ["read_only", "read_write", "admin", "monitor_only"]

_subscriptions: dict = {}
_notif_log: list     = []


def handle_action(action: str, payload: dict) -> dict:
    if action == "send_notification":
        notif_id  = fake_audit_id()
        user_id   = payload.get("user_id", fake_user_id())
        channel   = payload.get("channel",  random.choice(CHANNELS))
        notif_type = payload.get("type",    random.choice(NOTIF_TYPES))
        message   = payload.get("message",  f"Compliance alert: review required for {fake_session_id()}")
        delivered = random.random() > 0.03

        entry = {
            "notification_id": notif_id,
            "user_id":         user_id,
            "channel":         channel,
            "type":            notif_type,
            "message":         message,
            "delivered":       delivered,
            "sent_at":         fake_timestamp(),
            "retry_count":     0 if delivered else random.randint(1, 3),
        }
        _notif_log.append(entry)
        return entry

    elif action == "authorize_remote_access":
        session_id   = payload.get("session_id",    fake_session_id())
        user_id      = payload.get("user_id",        fake_user_id())
        access_level = payload.get("access_level",   random.choice(ACCESS_LEVELS))
        duration_min = payload.get("duration_min",   random.randint(15, 480))
        authorized   = random.random() > 0.10

        return {
            "session_id":       session_id,
            "user_id":          user_id,
            "access_level":     access_level,
            "authorized":       authorized,
            "duration_min":     duration_min if authorized else 0,
            "expires_at":       fake_timestamp() if authorized else None,
            "mfa_required":     True,
            "reason":    "access policy approved" if authorized else "policy restriction",
            "audit_id":         fake_audit_id(),
            "authorized_at":    fake_timestamp(),
        }

    elif action == "manage_subscriptions":
        user_id  = payload.get("user_id",    fake_user_id())
        op       = payload.get("operation",  random.choice(["subscribe", "unsubscribe", "list"]))
        channels = payload.get("channels",   random.sample(CHANNELS, random.randint(1, 3)))

        if op == "subscribe":
            _subscriptions[user_id] = list(set(
                _subscriptions.get(user_id, []) + channels
            ))
            return {
                "user_id":      user_id,
                "operation":    "subscribe",
                "subscribed":   channels,
                "all_channels": _subscriptions[user_id],
                "updated_at":   fake_timestamp(),
            }
        elif op == "unsubscribe":
            current = set(_subscriptions.get(user_id, channels))
            _subscriptions[user_id] = list(current - set(channels))
            return {
                "user_id":      user_id,
                "operation":    "unsubscribe",
                "removed":      channels,
                "all_channels": _subscriptions[user_id],
                "updated_at":   fake_timestamp(),
            }
        else:  # list
            return {
                "user_id":      user_id,
                "operation":    "list",
                "all_channels": _subscriptions.get(user_id, random.sample(CHANNELS, 2)),
                "total_subscribers": len(_subscriptions) or random.randint(50, 500),
                "fetched_at":   fake_timestamp(),
            }

    else:
        return {
            "message":        f"Notification service processed '{action}'",
            "notifications_sent": len(_notif_log) or random.randint(0, 1000),
            "timestamp":      fake_timestamp(),
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
