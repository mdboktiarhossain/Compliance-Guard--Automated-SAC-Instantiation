"""
MAPE-K Knowledge Component (K)
================================
Persistent read/write interface to knowledge_base.json.
This is the central data store for the entire MAPE-K loop.
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

KB_PATH = Path(__file__).parent.parent / "knowledge_base.json"
_lock = threading.Lock()


def _load() -> dict:
    with open(KB_PATH, encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict):
    with open(KB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def get_all() -> dict:
    """Return the entire knowledge base."""
    with _lock:
        return _load()


def get_active_services() -> dict:
    """Return dict of service_id -> 'active'|'inactive'|'failed'."""
    with _lock:
        return _load().get("active_services", {})


def get_service_metrics() -> dict:
    """Return latest metrics snapshot for all services."""
    with _lock:
        return _load().get("service_metrics", {})


def update_metrics(service_id: str, metrics: dict):
    """Update metrics for a single service."""
    with _lock:
        data = _load()
        data.setdefault("service_metrics", {})[service_id] = {
            **metrics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        _save(data)


def update_analysis(failing: list, degraded: list, healthy: list):
    """Store the latest analysis results."""
    with _lock:
        data = _load()
        data["current_analysis"] = {
            "failing_services": failing,
            "degraded_services": degraded,
            "healthy_services": healthy,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        _save(data)


def store_plan(plan: dict):
    """Store the current adaptation plan."""
    with _lock:
        data = _load()
        data["current_plan"] = {
            **plan,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        _save(data)


def store_sac_instance(service_id: str, sac: dict):
    """Store the SAC instance for a service."""
    with _lock:
        data = _load()
        data.setdefault("sac_instances", {})[service_id] = {
            **sac,
            "instantiated_at": datetime.now(timezone.utc).isoformat()
        }
        _save(data)


def update_completeness_score(service_id: str, score: float, details: dict):
    """Store the completeness score for a service."""
    with _lock:
        data = _load()
        data.setdefault("completeness_scores", {})[service_id] = {
            "score": score,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        _save(data)


def set_all_completeness_scores(scores_dict: dict):
    """Overwrite the entire completeness_scores dictionary in the KB."""
    with _lock:
        data = _load()
        data["completeness_scores"] = scores_dict
        _save(data)


def get_completeness_scores() -> dict:
    """Return all completeness scores."""
    with _lock:
        return _load().get("completeness_scores", {})


def record_adaptation(event: dict):
    """Append an adaptation event to history."""
    with _lock:
        data = _load()
        data.setdefault("adaptation_history", []).append({
            **event,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        _save(data)


def activate_service(service_id: str):
    """Mark a service as active."""
    with _lock:
        data = _load()
        data.setdefault("active_services", {})[service_id] = "active"
        _save(data)


def deactivate_service(service_id: str, reason: str = "failed"):
    """Mark a service as inactive/failed."""
    with _lock:
        data = _load()
        data.setdefault("active_services", {})[service_id] = reason
        _save(data)


def set_mape_state(state: str):
    """Update current MAPE-K loop state: idle|monitoring|analyzing|planning|executing."""
    with _lock:
        data = _load()
        data["mape_state"] = state
        data["loop_iteration"] = data.get("loop_iteration", 0) + (1 if state == "idle" else 0)
        _save(data)


def get_adaptation_history() -> list:
    """Return the full adaptation history."""
    with _lock:
        return _load().get("adaptation_history", [])
