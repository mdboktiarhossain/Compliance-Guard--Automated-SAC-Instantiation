"""
product_service.py - Product Catalog Service (port 8003)
Manages product catalog with information-flow policy enforcement.
"""

import os
import time
import random
import threading
from flask import Flask, request, jsonify
from service_base import (
    make_metrics, record_request, simulate_latency,
    build_health, build_metrics, simulate_traffic,
    fake_product_id, fake_timestamp, fake_user_id, fake_audit_id,
    error_response, success_response
)

app = Flask(__name__)
SERVICE_NAME = "product-service"
PORT         = 8003
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

CATEGORIES    = ["Electronics", "Software", "Services", "Hardware", "Consulting", "Data"]
SECURITY_TAGS = ["public", "internal", "confidential", "restricted"]

_PRODUCTS = [
    {
        "product_id":   fake_product_id(),
        "name":         name,
        "category":     random.choice(CATEGORIES),
        "price_usd":    round(random.uniform(9.99, 9999.99), 2),
        "in_stock":     random.choice([True, True, True, False]),
        "security_tag": random.choice(SECURITY_TAGS),
        "created_at":   fake_timestamp(),
    }
    for name in [
        "CloudShield Pro", "DataVault Enterprise", "SecureNet Basic",
        "ComplianceOS", "AuditTracer", "PolicyEngine", "AccessGuard Plus",
        "LogSentinel", "RiskMatrix", "IdentityBridge",
    ]
]


def handle_action(action: str, payload: dict) -> dict:
    if action == "get_products":
        page     = payload.get("page", 1)
        per_page = payload.get("per_page", 5)
        start    = (page - 1) * per_page
        end      = start + per_page
        return {
            "products":   _PRODUCTS[start:end],
            "total":      len(_PRODUCTS),
            "page":       page,
            "per_page":   per_page,
            "fetched_at": fake_timestamp(),
        }

    elif action == "filter_products":
        category = payload.get("category", "")
        tag      = payload.get("security_tag", "")
        results  = [
            p for p in _PRODUCTS
            if (not category or p["category"] == category)
            and (not tag or p["security_tag"] == tag)
        ]
        if not results:
            results = random.sample(_PRODUCTS, min(3, len(_PRODUCTS)))
        return {
            "products":      results,
            "filter_applied": {"category": category, "security_tag": tag},
            "count":         len(results),
            "filtered_at":   fake_timestamp(),
        }

    elif action == "enforce_flow_policy":
        requester_tag = payload.get("requester_tag", random.choice(SECURITY_TAGS))
        product_tag   = payload.get("product_tag",   random.choice(SECURITY_TAGS))
        tag_rank      = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
        permitted     = tag_rank.get(requester_tag, 0) >= tag_rank.get(product_tag, 0)
        return {
            "requester_tag":  requester_tag,
            "product_tag":    product_tag,
            "access_granted": permitted,
            "policy":         "mandatory_access_control",
            "reason":  "clearance level sufficient" if permitted else "insufficient clearance",
            "evaluated_at":   fake_timestamp(),
            "audit_id":       fake_audit_id(),
        }

    elif action == "get_product_by_id":
        product_id = payload.get("product_id", fake_product_id())
        match = next((p for p in _PRODUCTS if p["product_id"] == product_id), None)
        if match is None:
            match = {
                "product_id":   product_id,
                "name":         f"Product-{product_id[-4:]}",
                "category":     random.choice(CATEGORIES),
                "price_usd":    round(random.uniform(9.99, 4999.99), 2),
                "in_stock":     True,
                "security_tag": "internal",
                "created_at":   fake_timestamp(),
            }
        return {"product": match, "fetched_at": fake_timestamp()}

    else:
        return {
            "message":        f"Product service processed '{action}'",
            "catalog_size":   len(_PRODUCTS),
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
