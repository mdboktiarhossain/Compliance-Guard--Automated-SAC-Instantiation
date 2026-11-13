"""
api_gateway.py - API Gateway Service (port 8000)
Routes requests, enforces access control, validates tokens.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_token, fake_user_id, fake_session_id, fake_timestamp, fake_ip,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "api-gateway"
PORT         = 8000
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

# Simulated route table
ROUTE_TABLE = {
    "auth":          "http://localhost:8001",
    "auth_v2":       "http://localhost:8011",
    "user":          "http://localhost:8002",
    "user_replica":  "http://localhost:8012",
    "product":       "http://localhost:8003",
    "catalog":       "http://localhost:8013",
    "order":         "http://localhost:8004",
    "order_v2":      "http://localhost:8014",
    "notification":  "http://localhost:8005",
    "email":         "http://localhost:8015",
    "audit":         "http://localhost:8006",
    "logging":       "http://localhost:8016",
}

BLOCKED_FLOWS = {"unclassified->classified", "low->high", "external->internal"}


def handle_action(action: str, payload: dict) -> dict:
    if action == "route_request":
        token   = payload.get("token", fake_token())
        target  = payload.get("target_service", random.choice(list(ROUTE_TABLE)))
        user_id = payload.get("user_id", fake_user_id())

        # Validate token (simulated)
        token_valid = len(token) > 20 and token.startswith("eyJ")
        if not token_valid:
            return {
                "routed":          False,
                "reason":          "invalid_token",
                "target_service":  target,
                "user_id":         user_id,
                "request_id":      fake_session_id(),
                "timestamp":       fake_timestamp(),
            }

        dest_url = ROUTE_TABLE.get(target, f"http://localhost:9999")
        return {
            "routed":          True,
            "target_service":  target,
            "destination_url": dest_url,
            "user_id":         user_id,
            "request_id":      fake_session_id(),
            "token_valid":     True,
            "forwarded_at":    fake_timestamp(),
            "source_ip":       fake_ip(),
        }

    elif action == "enforce_flow":
        src   = payload.get("source_label", "unclassified")
        dst   = payload.get("dest_label",   "classified")
        flow  = f"{src}->{dst}"
        blocked = flow in BLOCKED_FLOWS or random.random() < 0.15

        return {
            "flow":          flow,
            "blocked":       blocked,
            "policy":        "Bell-LaPadula no-write-down",
            "reason":        "information flow policy violation" if blocked else "flow permitted",
            "evaluated_at":  fake_timestamp(),
            "policy_id":     f"POL-{random.randint(1000, 9999)}",
        }

    else:
        return {
            "message":       f"Gateway processed action '{action}'",
            "request_id":    fake_session_id(),
            "timestamp":     fake_timestamp(),
            "source_ip":     fake_ip(),
            "routes_active": len(ROUTE_TABLE),
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
