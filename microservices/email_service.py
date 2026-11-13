"""
email_service.py - Secure Email Service (port 8015)
Handles secure email delivery, session encryption, integrity verification,
and remote session monitoring.
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
SERVICE_NAME = "email-service"
PORT         = 8015
FAIL_MODE    = os.getenv("FAIL_MODE", "false").lower() == "true"

metrics      = make_metrics()
metrics_lock = threading.Lock()

simulate_traffic(metrics, metrics_lock, FAIL_MODE)

ENCRYPTION_METHODS = ["AES-256-GCM", "RSA-4096", "ECC-P384", "ChaCha20-Poly1305"]
TLS_VERSIONS       = ["TLS 1.3", "TLS 1.2"]
HASH_ALGOS         = ["SHA-256", "SHA-384", "SHA-512", "BLAKE3"]

_email_log: list    = []
_sessions:  dict    = {}


def handle_action(action: str, payload: dict) -> dict:
    if action == "send_email":
        msg_id    = fake_audit_id()
        sender    = payload.get("from",    fake_email())
        recipient = payload.get("to",      fake_email())
        subject   = payload.get("subject", "Compliance Notification")
        encrypted = payload.get("encrypted", True)
        delivered = random.random() > 0.02

        entry = {
            "message_id":       msg_id,
            "from":             sender,
            "to":               recipient,
            "subject":          subject,
            "encrypted":        encrypted,
            "encryption_method": random.choice(ENCRYPTION_METHODS) if encrypted else None,
            "delivered":        delivered,
            "sent_at":          fake_timestamp(),
            "spam_score":       round(random.uniform(0, 2.5), 2),
            "audit_id":         fake_audit_id(),
        }
        _email_log.append(entry)
        return entry

    elif action == "encrypt_session":
        session_id = payload.get("session_id", fake_session_id())
        user_id    = payload.get("user_id",    fake_user_id())
        method     = payload.get("method",     random.choice(ENCRYPTION_METHODS))
        tls        = payload.get("tls",        random.choice(TLS_VERSIONS))

        _sessions[session_id] = {
            "user_id":   user_id,
            "method":    method,
            "tls":       tls,
            "start":     time.time(),
        }
        return {
            "session_id":          session_id,
            "user_id":             user_id,
            "encryption_method":   method,
            "tls_version":         tls,
            "key_length_bits":     256 if "AES" in method else 384,
            "session_established": True,
            "established_at":      fake_timestamp(),
            "expires_in_s":        3600,
            "audit_id":            fake_audit_id(),
        }

    elif action == "verify_integrity":
        message_id = payload.get("message_id", fake_audit_id())
        algo       = payload.get("algorithm",  random.choice(HASH_ALGOS))
        # Simulate: 97% pass integrity check
        valid      = random.random() > 0.03
        return {
            "message_id":         message_id,
            "hash_algorithm":     algo,
            "signature_valid":    valid,
            "tampered":           not valid,
            "hash_value":         "".join(random.choices("0123456789abcdef", k=64)),
            "verified_at":        fake_timestamp(),
            "audit_id":           fake_audit_id(),
        }

    elif action == "monitor_remote_session":
        session_id  = payload.get("session_id", fake_session_id())
        session     = _sessions.get(session_id, {
            "user_id": fake_user_id(),
            "method":  random.choice(ENCRYPTION_METHODS),
            "tls":     random.choice(TLS_VERSIONS),
            "start":   time.time() - random.uniform(60, 3600),
        })
        duration    = time.time() - session.get("start", time.time())
        anomalous   = random.random() < 0.08
        return {
            "session_id":        session_id,
            "user_id":           session.get("user_id"),
            "duration_s":        round(duration, 1),
            "encryption_method": session.get("method"),
            "tls_version":       session.get("tls"),
            "bytes_transferred": random.randint(1024, 10_485_760),
            "anomalous_activity": anomalous,
            "alerts": [
                {"type": "unusual_transfer_volume", "severity": "medium"}
            ] if anomalous else [],
            "monitored_at":      fake_timestamp(),
            "audit_id":          fake_audit_id(),
        }

    else:
        return {
            "message":     f"Email service processed '{action}'",
            "emails_sent": len(_email_log) or random.randint(0, 5000),
            "timestamp":   fake_timestamp(),
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
