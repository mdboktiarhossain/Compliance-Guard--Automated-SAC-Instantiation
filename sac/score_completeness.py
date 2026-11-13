"""
SAC Completeness Scorer
========================
Computes the completeness percentage and confidence score
for a SAC instance, using impact_factor weights from the
extracted NIST compliance rules.

Directly implements the formal satisficing level metric.
"""
import json
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent.parent / "extracted_schema.json"
STATUS_SCORE = {"satisfied": 1.0, "partial": 0.5, "missing": 0.0}


def score_sac(sac_instance: dict) -> dict:
    """
    Compute completeness score for a SAC instance.
    
    Returns:
        {
          "service_id": str,
          "completeness_pct": float,       # 0-100
          "weighted_score": float,          # 0.0-1.0 (satisficing level)
          "satisfied_count": int,
          "partial_count": int,
          "missing_count": int,
          "total_rules": int,
          "impact_weighted_satisfied": float,
          "impact_weighted_total": float,
          "missing_critical": list,         # High-impact missing rules
          "missing_medium": list,
          "missing_low": list,
          "per_rule_scores": list
        }
    """
    # Load impact factors from the compliance schema
    schema_data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    impact_map = {
        r["rule_id"]: r.get("impact_factor", 0.5)
        for r in schema_data.get("rules", [])
    }

    rule_mappings = sac_instance.get("rule_mappings", [])
    
    weighted_achieved = 0.0
    weighted_total    = 0.0
    per_rule_scores   = []
    missing_critical  = []
    missing_medium    = []
    missing_low       = []

    for rm in rule_mappings:
        rule_id   = rm.get("rule_id", "")
        status    = rm.get("satisfaction_status", "missing")
        confidence = rm.get("confidence", 0.0)
        impact    = float(rm.get("impact_factor", impact_map.get(rule_id, 0.5)))

        # Satisficing level for this rule (1.0 satisfied | 0.5 partial | 0.0 missing)
        satisficing = STATUS_SCORE.get(status, 0.0)

        weighted_achieved += impact * satisficing
        weighted_total    += impact

        per_rule_scores.append({
            "rule_id":      rule_id,
            "status":       status,
            "confidence":   confidence,
            "impact_factor": impact,
            "contribution": round(impact * satisficing, 4),
            "gap":          rm.get("gap_description", "")
        })

        # Track missing/partial rules by criticality
        if status in ("missing", "partial") and impact >= 0.8:
            missing_critical.append({"rule_id": rule_id, "impact": impact, "gap": rm.get("gap_description","")})
        elif status in ("missing", "partial") and impact >= 0.5:
            missing_medium.append({"rule_id": rule_id, "impact": impact, "gap": rm.get("gap_description","")})
        elif status in ("missing", "partial"):
            missing_low.append({"rule_id": rule_id, "impact": impact, "gap": rm.get("gap_description","")})

    weighted_score    = weighted_achieved / weighted_total if weighted_total > 0 else 0.0
    completeness_pct  = round(weighted_score * 100, 1)

    return {
        "service_id":               sac_instance.get("service_id", "unknown"),
        "completeness_pct":         completeness_pct,
        "weighted_score":           round(weighted_score, 4),
        "satisfied_count":          sac_instance.get("satisfied", 0),
        "partial_count":            sac_instance.get("partial",    0),
        "missing_count":            sac_instance.get("missing",    0),
        "total_rules":              len(rule_mappings),
        "impact_weighted_achieved": round(weighted_achieved, 4),
        "impact_weighted_total":    round(weighted_total,    4),
        "missing_critical":         missing_critical,
        "missing_medium":           missing_medium,
        "missing_low":              missing_low,
        "per_rule_scores":          per_rule_scores
    }


def compare_alternatives(original_score: dict, alternatives: dict) -> dict:
    """
    Compare completeness scores of alternative services.
    Used by the Planner to select the best replacement.
    
    Args:
        original_score: score dict for the failing service
        alternatives:   {service_id: score_dict} for each alternative
    
    Returns:
        {
          "recommended": service_id of best alternative,
          "reason": explanation,
          "comparison": sorted list of alternatives with scores
        }
    """
    ranked = sorted(
        alternatives.items(),
        key=lambda x: x[1]["weighted_score"],
        reverse=True
    )

    best_id, best_score = ranked[0] if ranked else (None, None)
    
    comparison = [
        {
            "service_id":       sid,
            "completeness_pct": sc["completeness_pct"],
            "weighted_score":   sc["weighted_score"],
            "satisfied":        sc["satisfied_count"],
            "missing_critical": len(sc["missing_critical"]),
        }
        for sid, sc in ranked
    ]

    reason = (
        f"'{best_id}' selected: highest completeness {best_score['completeness_pct']:.1f}% "
        f"(weighted satisficing score {best_score['weighted_score']:.3f}), "
        f"with only {len(best_score['missing_critical'])} critical gaps."
    ) if best_id else "No alternatives available."

    return {
        "recommended": best_id,
        "reason":      reason,
        "comparison":  comparison,
        "original_completeness": original_score.get("completeness_pct", 0)
    }


if __name__ == "__main__":
    import sys
    sac_file = sys.argv[1] if len(sys.argv) > 1 else None
    if not sac_file:
        print("Usage: python score_completeness.py <sac_instance.json>")
        sys.exit(1)
    sac = json.loads(Path(sac_file).read_text(encoding="utf-8"))
    result = score_sac(sac)
    print(f"\nService: {result['service_id']}")
    print(f"Completeness: {result['completeness_pct']}%")
    print(f"Weighted Score: {result['weighted_score']}")
    print(f"Rules: {result['satisfied_count']} satisfied / {result['partial_count']} partial / {result['missing_count']} missing")
    print(f"Critical gaps: {len(result['missing_critical'])}")
