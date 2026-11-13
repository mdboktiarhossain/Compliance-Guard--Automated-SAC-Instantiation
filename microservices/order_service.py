"""
order_service.py - Order Management Service (port 8004)
Handles order lifecycle with separation of duties and dual approval.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_order_id, fake_user_id, fake_timestamp, fake_audit_id, fake_session_id,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "order-service"
PORT         = 8004
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

STATUSES      = ["pending", "approved", "processing", "shipped", "delivered", "cancelled"]
PAYMENT_TYPES = ["credit_card", "wire_transfer", "purchase_order", "crypto", "bank_draft"]

_orders: dict = {}


def handle_action(action: str, payload: dict) -> dict:
    if action == "create_order":
        order_id = fake_order_id()
        user_id  = payload.get("user_id", fake_user_id())
        items    = payload.get("items", [
            {"product_id": f"prod_{i:04x}", "qty": random.randint(1, 5),
             "unit_price": round(random.uniform(9.99, 499.99), 2)}
            for i in range(random.randint(1, 4))
        ])
        total = sum(i.get("qty", 1) * i.get("unit_price", 0) for i in items)
        order = {
            "order_id":       order_id,
            "user_id":        user_id,
            "items":          items,
            "total_usd":      round(total, 2),
            "status":         "pending",
            "created_at":     fake_timestamp(),
            "requires_approval": total > 10000,
        }
        _orders[order_id] = order
        return {"order": order, "audit_id": fake_audit_id()}

    elif action == "process_payment":
        order_id     = payload.get("order_id", fake_order_id())
        payment_type = payload.get("payment_type", random.choice(PAYMENT_TYPES))
        amount_usd   = payload.get("amount_usd", round(random.uniform(10, 50000), 2))
        success      = random.random() > 0.05

        if order_id in _orders:
            _orders[order_id]["status"] = "processing" if success else "pending"

        return {
            "order_id":     order_id,
            "payment_type": payment_type,
            "amount_usd":   amount_usd,
            "success":      success,
            "transaction_id": fake_session_id() if success else None,
            "reason":       None if success else "payment_gateway_declined",
            "processed_at": fake_timestamp(),
            "audit_id":     fake_audit_id(),
        }

    elif action == "require_dual_approval":
        order_id   = payload.get("order_id", fake_order_id())
        approver_1 = payload.get("approver_1", fake_user_id())
        approver_2 = payload.get("approver_2", fake_user_id())
        # Both must be different users (simulated check)
        both_approved = approver_1 != approver_2 and random.random() > 0.1
        if both_approved and order_id in _orders:
            _orders[order_id]["status"] = "approved"
        return {
            "order_id":       order_id,
            "approver_1":     approver_1,
            "approver_2":     approver_2,
            "dual_approved":  both_approved,
            "reason":  None if both_approved else "same_approver_or_timeout",
            "approved_at":    fake_timestamp() if both_approved else None,
            "audit_id":       fake_audit_id(),
        }

    elif action == "separate_duties":
        role_creator   = payload.get("creator_role", random.choice(["editor", "operator"]))
        role_approver  = payload.get("approver_role", random.choice(["admin", "auditor"]))
        order_id       = payload.get("order_id", fake_order_id())
        # Duty separation: creator must NOT be approver
        violation      = role_creator == role_approver
        return {
            "order_id":       order_id,
            "creator_role":   role_creator,
            "approver_role":  role_approver,
            "duties_separated": not violation,
            "violation":      violation,
            "policy":         "separation_of_duties",
            "reason":  "same role cannot create and approve" if violation else "duties properly separated",
            "evaluated_at":   fake_timestamp(),
            "audit_id":       fake_audit_id(),
        }

    else:
        return {
            "message":      f"Order service processed '{action}'",
            "orders_total": len(_orders) or random.randint(100, 5000),
            "timestamp":    fake_timestamp(),
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
