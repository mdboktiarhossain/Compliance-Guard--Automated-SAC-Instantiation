"""
sac/change_impact.py — SAC Change Impact Reporter
===================================================
Compares two SAC instances (before and after an architectural change)
and produces a Change Impact Report showing:
  - Which rules improved (missing/partial → satisfied)
  - Which rules degraded (satisfied/partial → missing)
  - Overall completeness delta

Pure Python — no dependencies.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


STATUS_SCORE = {"satisfied": 1.0, "partial": 0.5, "missing": 0.0}


def compute_completeness(sac_instance: dict) -> float:
    """
    Weighted completeness score for a SAC instance.
    Completeness = Σ (rule_score × impact_factor) / Σ (impact_factor)
    """
    mappings = sac_instance.get("rule_mappings", [])
    if not mappings:
        return 0.0

    weighted_sum   = 0.0
    total_weight   = 0.0
    for m in mappings:
        score         = STATUS_SCORE.get(m.get("satisfaction_status", "missing"), 0.0)
        impact_factor = float(m.get("impact_factor", 0.5))
        weighted_sum  += score * impact_factor
        total_weight  += impact_factor

    return round(weighted_sum / total_weight, 4) if total_weight > 0 else 0.0


def compare_sac_instances(
    sac_before: dict,
    sac_after:  dict,
    change_event: str = "architectural change",
) -> dict:
    """
    Diff two SAC instances and produce a Change Impact Report.

    Args:
        sac_before:   SAC instance BEFORE the change
        sac_after:    SAC instance AFTER the change
        change_event: Human-readable description of what changed

    Returns:
        A Change Impact Report dict.
    """
    completeness_before = compute_completeness(sac_before)
    completeness_after  = compute_completeness(sac_after)
    delta               = round(completeness_after - completeness_before, 4)

    # Index rules by rule_id
    before_map = {m["rule_id"]: m for m in sac_before.get("rule_mappings", [])}
    after_map  = {m["rule_id"]: m for m in sac_after.get("rule_mappings",  [])}

    improved  = []
    degraded  = []
    unchanged = []

    all_rule_ids = set(before_map) | set(after_map)
    for rule_id in sorted(all_rule_ids):
        b = before_map.get(rule_id)
        a = after_map.get(rule_id)

        if b is None or a is None:
            continue

        status_before = b.get("satisfaction_status", "missing")
        status_after  = a.get("satisfaction_status", "missing")
        score_before  = STATUS_SCORE.get(status_before, 0.0)
        score_after   = STATUS_SCORE.get(status_after,  0.0)

        entry = {
            "rule_id":        rule_id,
            "control_title":  b.get("control_title", ""),
            "status_before":  status_before,
            "status_after":   status_after,
            "score_before":   score_before,
            "score_after":    score_after,
            "impact_factor":  b.get("impact_factor", 0.5),
            "missing_before": b.get("missing", []),
            "missing_after":  a.get("missing", []),
        }

        if score_after > score_before:
            newly_satisfied = [
                c for c in entry["missing_before"]
                if c not in entry["missing_after"]
            ]
            scope_items = [
                c.replace("control ", "").replace(" not in service scope", "")
                for c in newly_satisfied if c.endswith(" not in service scope")
            ]
            cap_items = [
                c for c in newly_satisfied if not c.endswith(" not in service scope")
            ]
            parts = []
            if scope_items:
                parts.append(f"Added to service scope: {', '.join(scope_items)}")
            if cap_items:
                parts.append(f"Newly satisfied: {', '.join(cap_items)}")
            entry["reason"] = "; ".join(parts) if parts else "Status improved"
            improved.append(entry)
        elif score_after < score_before:
            newly_missing = [
                c for c in entry["missing_after"]
                if c not in entry["missing_before"]
            ]
            scope_items = [
                c.replace("control ", "").replace(" not in service scope", "")
                for c in newly_missing if c.endswith(" not in service scope")
            ]
            cap_items = [
                c for c in newly_missing if not c.endswith(" not in service scope")
            ]
            parts = []
            if scope_items:
                parts.append(f"Removed from service scope: {', '.join(scope_items)}")
            if cap_items:
                parts.append(f"Now missing: {', '.join(cap_items)}")
            entry["reason"] = "; ".join(parts) if parts else "Status degraded"
            degraded.append(entry)
        else:
            unchanged.append({"rule_id": rule_id, "status": status_after})

    if delta > 0:
        overall_impact = "IMPROVED"
    elif delta < 0:
        overall_impact = "DEGRADED"
    else:
        overall_impact = "UNCHANGED"

    return {
        "report_id":            f"impact-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
        "timestamp":            datetime.now(timezone.utc).isoformat(),
        "change_event":         change_event,
        "service_before":       sac_before.get("service_id", ""),
        "service_after":        sac_after.get("service_id",  ""),
        "completeness_before":  completeness_before,
        "completeness_after":   completeness_after,
        "delta":                delta,
        "overall_impact":       overall_impact,
        "improved_rules_count": len(improved),
        "degraded_rules_count": len(degraded),
        "unchanged_rules_count":len(unchanged),
        "improved_rules":       improved,
        "degraded_rules":       degraded,
        "summary": (
            f"{change_event}: completeness {overall_impact} "
            f"from {completeness_before:.1%} to {completeness_after:.1%} "
            f"(delta {delta:+.1%}). "
            f"{len(improved)} rules improved, {len(degraded)} degraded."
        ),
    }


# ── CLI entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python change_impact.py <sac_before.json> <sac_after.json> [change_event]")
        sys.exit(1)

    before_path = Path(sys.argv[1])
    after_path  = Path(sys.argv[2])
    event_label = sys.argv[3] if len(sys.argv) > 3 else "architectural change"

    sac_before = json.loads(before_path.read_text(encoding="utf-8"))
    sac_after  = json.loads(after_path.read_text(encoding="utf-8"))

    report = compare_sac_instances(sac_before, sac_after, event_label)

    output_path = Path(__file__).parent.parent / "sac_instances" / \
        f"change_impact_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\n{report['summary']}")
    print(f"\nImproved rules ({len(report['improved_rules'])}):")
    for r in report["improved_rules"]:
        print(f"  {r['rule_id']} [{r['status_before']} -> {r['status_after']}]: {r['reason']}")

    print(f"\nDegraded rules ({len(report['degraded_rules'])}):")
    for r in report["degraded_rules"]:
        print(f"  {r['rule_id']} [{r['status_before']} -> {r['status_after']}]: {r['reason']}")

    print(f"\nSaved -> {output_path}")
