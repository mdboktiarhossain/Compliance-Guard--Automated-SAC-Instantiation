"""
order_service_v2.py - Enhanced Order Service with Audit Trail (port 8014)
Extends order_service with full audit trail, access revocation logging,
and access decision enforcement.
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
SERVICE_NAME = "order-service-v2"
PORT         = 8014
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

PAYMENT_TYPES  = ["credit_card", "wire_transfer", "purchase_order", "bank_draft"]
ACCESS_REASONS = ["role_expired", "account_deactivated", "policy_change",
                  "manual_revocation", "suspicious_activity"]

_orders: dict    = {}
_audit_trail: list = []


def _append_audit(event_type: str, details: dict) -> dict:
    entry = {
        "audit_id":   fake_audit_id(),
        "event_type": event_type,
        "details":    details,
        "logged_at":  fake_timestamp(),
        "immutable":  True,
    }
    _audit_trail.append(entry)
    return entry


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
            "order_id":          order_id,
            "user_id":           user_id,
            "items":             items,
            "total_usd":         round(total, 2),
            "status":            "pending",
            "created_at":        fake_timestamp(),
            "requires_approval": total > 10000,
            "audit_trail":       [],
        }
        _orders[order_id] = order
        audit = _append_audit("order_created", {"order_id": order_id, "user_id": user_id})
        return {"order": order, "audit": audit}

    elif action == "process_payment":
        order_id     = payload.get("order_id", fake_order_id())
        payment_type = payload.get("payment_type", random.choice(PAYMENT_TYPES))
        amount_usd   = payload.get("amount_usd", round(random.uniform(10, 50000), 2))
        success      = random.random() > 0.05
        audit = _append_audit("payment_processed", {
            "order_id":     order_id,
            "payment_type": payment_type,
            "amount_usd":   amount_usd,
            "success":      success,
        })
        return {
            "order_id":       order_id,
            "payment_type":   payment_type,
            "amount_usd":     amount_usd,
            "success":        success,
            "transaction_id": fake_session_id() if success else None,
            "processed_at":   fake_timestamp(),
            "audit":          audit,
        }

    elif action == "require_dual_approval":
        order_id   = payload.get("order_id", fake_order_id())
        approver_1 = payload.get("approver_1", fake_user_id())
        approver_2 = payload.get("approver_2", fake_user_id())
        approved   = approver_1 != approver_2 and random.random() > 0.1
        audit = _append_audit("dual_approval", {
            "order_id": order_id, "approved": approved,
            "approver_1": approver_1, "approver_2": approver_2,
        })
        return {
            "order_id":      order_id,
            "dual_approved": approved,
            "approver_1":    approver_1,
            "approver_2":    approver_2,
            "approved_at":   fake_timestamp() if approved else None,
            "audit":         audit,
        }

    elif action == "separate_duties":
        role_creator  = payload.get("creator_role",  random.choice(["editor", "operator"]))
        role_approver = payload.get("approver_role", random.choice(["admin", "auditor"]))
        violation     = role_creator == role_approver
        audit = _append_audit("duties_check", {
            "creator_role": role_creator, "approver_role": role_approver,
            "violation": violation,
        })
        return {
            "duties_separated": not violation,
            "violation":        violation,
            "creator_role":     role_creator,
            "approver_role":    role_approver,
            "audit":            audit,
        }

    elif action == "audit_order":
        order_id = payload.get("order_id", fake_order_id())
        history  = [e for e in _audit_trail if e["details"].get("order_id") == order_id]
        if not history:
            history = [_append_audit("synthetic_audit", {"order_id": order_id})]
        return {
            "order_id":     order_id,
            "audit_events": history,
            "event_count":  len(history),
            "retrieved_at": fake_timestamp(),
        }

    elif action == "log_access_revocation":
        user_id   = payload.get("user_id", fake_user_id())
        reason    = payload.get("reason", random.choice(ACCESS_REASONS))
        audit = _append_audit("access_revoked", {
            "user_id":       user_id,
            "reason":        reason,
            "revoked_by":    fake_user_id(),
            "affected_orders": random.randint(0, 10),
        })
        return {
            "user_id":         user_id,
            "access_revoked":  True,
            "reason":          reason,
            "revoked_at":      fake_timestamp(),
            "affected_orders": audit["details"]["affected_orders"],
            "audit":           audit,
        }

    elif action == "enforce_access_decision":
        user_id    = payload.get("user_id", fake_user_id())
        order_id   = payload.get("order_id", fake_order_id())
        action_req = payload.get("requested_action", "view")
        granted    = random.random() > 0.15
        audit = _append_audit("access_decision", {
            "user_id":  user_id, "order_id": order_id,
            "action":   action_req, "granted": granted,
        })
        return {
            "user_id":          user_id,
            "order_id":         order_id,
            "requested_action": action_req,
            "access_granted":   granted,
            "policy":           "RBAC + order-ownership",
            "decided_at":       fake_timestamp(),
            "audit":            audit,
        }

    else:
        return {
            "message":    f"Order-v2 processed '{action}'",
            "timestamp":  fake_timestamp(),
            "trail_size": len(_audit_trail),
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
