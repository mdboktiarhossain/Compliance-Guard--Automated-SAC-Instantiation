"""
Compliance Guard — Main Server
================================
Flask server that:
1. Runs the MAPE-K loop in a background thread (every 15 seconds)
2. Exposes a REST API for the dashboard
3. Serves the web dashboard at /
4. Acts as the MAPE-K Knowledge base server

Run: python server.py
Dashboard: http://localhost:5000
"""
import json
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

# Add parent to path for imports
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')
sys.path.insert(0, str(Path(__file__).parent))

from mapek import knowledge
from mapek.monitor  import run_once as monitor_run
from mapek.analyzer import run_once as analyzer_run, needs_adaptation
from mapek.planner  import run_once as planner_run
from mapek.executor import run_once as executor_run

app  = Flask(__name__, static_folder=".")
CORS(app)

ARCH_PATH     = Path(__file__).parent / "system_architecture.json"
SCHEMA_PATH   = Path(__file__).parent / "extracted_schema.json"
LOOP_INTERVAL = 15   # seconds between MAPE-K cycles
_loop_running = False
_loop_thread  = None

# ─── MAPE-K Loop ────────────────────────────────────────────────────────────

def update_active_service_scores():
    """Compute and store completeness scores for all currently active services."""
    try:
        from sac.instantiate_sac import instantiate_sac
        from sac.score_completeness import score_sac
        
        active_svcs = knowledge.get_active_services()
        active_ids = [sid for sid, status in active_svcs.items() if status == "active"]
        
        new_scores = {}
        for service_id in active_ids:
            sac_inst = instantiate_sac(service_id)
            score = score_sac(sac_inst)
            knowledge.store_sac_instance(service_id, sac_inst)
            new_scores[service_id] = {
                "score": score["weighted_score"],
                "details": score,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        knowledge.set_all_completeness_scores(new_scores)
        print(f"[MAPE-K] Updated completeness scores for {len(active_ids)} active services.")
    except Exception as e:
        print(f"[MAPE-K] ⚠️ Error updating active service scores: {e}")


def mape_k_loop():
    """Background MAPE-K loop thread."""
    global _loop_running
    print("[MAPE-K] Loop started.")
    
    # Run initial score calculation on startup
    update_active_service_scores()
    while _loop_running:
        try:
            print(f"\n{'='*55}")
            print(f"[MAPE-K] Cycle at {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*55}")

            # M — Monitor
            metrics  = monitor_run()

            # A — Analyze
            analysis = analyzer_run(metrics)

            # P — Plan (only if adaptation needed)
            if needs_adaptation(analysis):
                plan = planner_run(analysis)

                # E — Execute (only if plan has adaptations)
                if plan.get("adaptations"):
                    executor_run(plan)
                else:
                    print("[MAPE-K] No executable plan produced.")
            else:
                print("[MAPE-K] ✅ System healthy — no adaptation needed.")

            # Update scores for all active services
            update_active_service_scores()

            knowledge.set_mape_state("idle")

        except Exception as e:
            print(f"[MAPE-K] ⚠️  Loop error: {e}")
            traceback.print_exc()
            knowledge.set_mape_state("idle")

        time.sleep(LOOP_INTERVAL)

    print("[MAPE-K] Loop stopped.")


def start_loop():
    global _loop_running, _loop_thread
    if not _loop_running:
        _loop_running = True
        _loop_thread  = threading.Thread(target=mape_k_loop, daemon=True)
        _loop_thread.start()


def stop_loop():
    global _loop_running
    _loop_running = False


# ─── REST API ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "sac_dashboard.html")


@app.route("/api/architecture")
def api_architecture():
    data = json.loads(ARCH_PATH.read_text(encoding="utf-8"))
    return jsonify(data)


@app.route("/api/knowledge")
def api_knowledge():
    return jsonify(knowledge.get_all())


@app.route("/api/metrics")
def api_metrics():
    return jsonify(knowledge.get_service_metrics())


@app.route("/api/scores")
def api_scores():
    return jsonify(knowledge.get_completeness_scores())


@app.route("/api/history")
def api_history():
    return jsonify(knowledge.get_adaptation_history())


@app.route("/api/sac/<service_id>")
def api_sac(service_id):
    sacs = knowledge.get_all().get("sac_instances", {})
    sac  = sacs.get(service_id)
    if not sac:
        return jsonify({"error": f"No SAC instance found for '{service_id}'"}), 404
    return jsonify(sac)


@app.route("/api/status")
def api_status():
    kb = knowledge.get_all()
    return jsonify({
        "mape_state":       kb.get("mape_state", "idle"),
        "loop_iteration":   kb.get("loop_iteration", 0),
        "last_updated":     kb.get("last_updated"),
        "active_services":  kb.get("active_services", {}),
        "adaptations_total": len(kb.get("adaptation_history", [])),
        "loop_running":     _loop_running,
        "loop_interval_s":  LOOP_INTERVAL
    })


@app.route("/api/simulate/fail/<service_id>", methods=["POST"])
def simulate_fail(service_id):
    """
    Simulate a service failure for demo purposes.
    Sets the service metrics to show high error rate in knowledge base.
    NOTE: This doesn't actually stop the service — it simulates degraded metrics
    so the MAPE-K loop will trigger adaptation on the next cycle.
    """
    knowledge.update_metrics(service_id, {
        "service":       service_id,
        "reachable":     False,
        "status":        "down",
        "requests_total": 100,
        "errors_total":   98,
        "error_rate":     0.98,
        "latency_ms_avg": 9999.0,
        "availability":   2.0,
        "reason":         "Simulated failure via API"
    })
    return jsonify({
        "message": f"Simulated failure for '{service_id}'. Next MAPE-K cycle will trigger adaptation.",
        "service": service_id
    })


@app.route("/api/simulate/recover/<service_id>", methods=["POST"])
def simulate_recover(service_id):
    """Reset a service back to healthy metrics."""
    knowledge.update_metrics(service_id, {
        "service":        service_id,
        "reachable":      True,
        "status":         "ok",
        "requests_total":  500,
        "errors_total":    5,
        "error_rate":      0.01,
        "latency_ms_avg":  45.0,
        "availability":    99.0,
        "reason":          "Recovered via API"
    })
    knowledge.activate_service(service_id)
    return jsonify({
        "message": f"Service '{service_id}' marked as recovered.",
        "service": service_id
    })


@app.route("/api/loop/start", methods=["POST"])
def loop_start():
    start_loop()
    return jsonify({"message": "MAPE-K loop started", "interval_s": LOOP_INTERVAL})


@app.route("/api/loop/stop", methods=["POST"])
def loop_stop():
    stop_loop()
    return jsonify({"message": "MAPE-K loop stopped"})


@app.route("/api/schema")
def api_schema():
    """Return the extracted NIST compliance schema."""
    data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return jsonify(data)


# ─── Startup ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Compliance Guard — MAPE-K Server")
    print("  Dashboard: http://localhost:5000")
    print("=" * 55)
    start_loop()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
