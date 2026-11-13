"""
catalog_service.py - Enhanced Catalog Service (port 8013)
Extended product catalog with security attribute management,
encrypted-bypass blocking, and privacy enforcement.
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
SERVICE_NAME = "catalog-service"
PORT         = 8013
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

CATEGORIES    = ["Electronics", "Software", "Services", "Hardware", "Consulting", "Data"]
SECURITY_TAGS = ["public", "internal", "confidential", "restricted"]
PRIVACY_CATS  = ["PII", "PHI", "PCI", "proprietary", "none"]

_CATALOG = [
    {
        "product_id":    fake_product_id(),
        "name":          name,
        "category":      random.choice(CATEGORIES),
        "price_usd":     round(random.uniform(9.99, 14999.99), 2),
        "in_stock":      random.choice([True, True, False]),
        "security_tag":  random.choice(SECURITY_TAGS),
        "privacy_cat":   random.choice(PRIVACY_CATS),
        "encrypted":     random.choice([True, False]),
        "created_at":    fake_timestamp(),
    }
    for name in [
        "CloudShield Pro", "DataVault Enterprise", "SecureNet Basic",
        "ComplianceOS", "AuditTracer", "PolicyEngine", "AccessGuard Plus",
        "LogSentinel", "RiskMatrix", "IdentityBridge", "PrivacyVault",
        "CryptoProxy", "FlowController", "AttributeManager",
    ]
]


def handle_action(action: str, payload: dict) -> dict:
    if action == "get_products":
        page     = payload.get("page", 1)
        per_page = payload.get("per_page", 5)
        start    = (page - 1) * per_page
        end      = start + per_page
        return {
            "products":   _CATALOG[start:end],
            "total":      len(_CATALOG),
            "page":       page,
            "fetched_at": fake_timestamp(),
        }

    elif action == "filter_products":
        cat = payload.get("category", "")
        tag = payload.get("security_tag", "")
        results = [
            p for p in _CATALOG
            if (not cat or p["category"] == cat)
            and (not tag or p["security_tag"] == tag)
        ] or random.sample(_CATALOG, 3)
        return {"products": results, "count": len(results), "filtered_at": fake_timestamp()}

    elif action == "get_product_by_id":
        pid   = payload.get("product_id", fake_product_id())
        match = next((p for p in _CATALOG if p["product_id"] == pid), None) or {
            "product_id": pid,
            "name":        f"Catalog-Item-{pid[-4:]}",
            "category":    random.choice(CATEGORIES),
            "price_usd":   round(random.uniform(9.99, 4999.99), 2),
            "in_stock":    True,
            "security_tag": "internal",
            "privacy_cat": "none",
            "encrypted":   False,
            "created_at":  fake_timestamp(),
        }
        return {"product": match, "fetched_at": fake_timestamp()}

    elif action == "manage_security_attributes":
        product_id = payload.get("product_id", fake_product_id())
        new_tag    = payload.get("security_tag", random.choice(SECURITY_TAGS))
        new_priv   = payload.get("privacy_cat",  random.choice(PRIVACY_CATS))
        return {
            "product_id":       product_id,
            "security_tag":     new_tag,
            "privacy_category": new_priv,
            "updated_by":       fake_user_id(),
            "updated_at":       fake_timestamp(),
            "audit_id":         fake_audit_id(),
            "propagated":       True,
        }

    elif action == "block_encrypted_bypass":
        request_id = payload.get("request_id", fake_audit_id())
        # Simulate detection of covert channel via encryption bypass
        detected = random.random() < 0.25
        return {
            "request_id":        request_id,
            "bypass_detected":   detected,
            "encryption_method": payload.get("encryption_method", "TLS1.2"),
            "policy":            "covert_channel_prevention",
            "blocked":           detected,
            "reason": "encrypted bypass attempt detected" if detected else "traffic within policy",
            "evaluated_at":      fake_timestamp(),
            "audit_id":          fake_audit_id(),
        }

    elif action == "enforce_privacy":
        user_id       = payload.get("user_id", fake_user_id())
        privacy_cat   = payload.get("privacy_category", random.choice(PRIVACY_CATS))
        user_clearance = payload.get("clearance", random.choice(PRIVACY_CATS))
        permitted     = privacy_cat == "none" or user_clearance == privacy_cat
        return {
            "user_id":          user_id,
            "privacy_category": privacy_cat,
            "user_clearance":   user_clearance,
            "access_granted":   permitted,
            "policy":           "privacy_enforcement",
            "reason":    "clearance matches" if permitted else "privacy policy violation",
            "evaluated_at":     fake_timestamp(),
            "audit_id":         fake_audit_id(),
        }

    else:
        return {
            "message":      f"Catalog service processed '{action}'",
            "catalog_size": len(_CATALOG),
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
