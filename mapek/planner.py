"""
MAPE-K Planner Component (P) — v2.0
=====================================
For each failing service:
1. Finds its alternatives from the LPG (system_architecture_graph.json)
2. Builds a hypothetical LPG for each alternative (replaces failing node)
3. Runs the Procedural Mapping Engine on the hypothetical LPG (NO LLM)
4. Scores each alternative using weighted completeness
5. Selects the best alternative (highest completeness score)
6. Stores plan + change impact report in the Knowledge base

Updated to use Procedural Mapping Engine:
  No LLM. Pure Python. Machine independent.
"""
import json
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from mapek import knowledge
from sac.instantiate_sac import instantiate_sac
from sac.score_completeness import score_sac, compare_alternatives
from sac.change_impact import compare_sac_instances
from graph_builder import load_graph, get_alternatives, replace_service_in_graph

GRAPH_PATH = Path(__file__).parent.parent / "system_architecture_graph.json"


def plan_adaptation(failing_services: list) -> dict:
    """
    For each failing service, evaluate alternatives via SAC procedural mapping
    and pick the best one based on compliance completeness.

    Returns:
        {
          "adaptations": [
            {
              "failing_service":    str,
              "chosen_alternative": str,
              "reason":             str,
              "completeness_before": float,
              "completeness_after":  float,
              "delta":               float,
              "impact_report":       dict,
              "chosen_sac":          dict,
              "chosen_score":        dict
            }
          ],
          "no_alternative": [service_id, ...]
        }
    """
    knowledge.set_mape_state("planning")
    adaptations    = []
    no_alternative = []

    base_graph = load_graph(GRAPH_PATH)

    for failing_id in failing_services:
        print(f"\n[Planner] Planning for failing service: '{failing_id}'")
        alternatives = get_alternatives(base_graph, failing_id)

        if not alternatives:
            print(f"[Planner] No alternatives available for '{failing_id}'")
            no_alternative.append(failing_id)
            continue

        print(f"[Planner] Found {len(alternatives)} alternative(s): {alternatives}")

        # SAC for failing service on current graph
        print(f"[Planner] Scoring failing service '{failing_id}'...")
        failing_sac   = instantiate_sac(failing_id, graph=base_graph)
        failing_score = score_sac(failing_sac)
        knowledge.store_sac_instance(failing_id, failing_sac)

        # Evaluate each alternative on a hypothetical LPG
        alt_scores  = {}
        alt_sacs    = {}
        alt_impacts = {}

        for alt_id in alternatives:
            print(f"[Planner]   Evaluating alternative '{alt_id}'...")
            try:
                # Build hypothetical graph: deactivate failing, activate alternative
                hypo_graph = replace_service_in_graph(base_graph, failing_id, alt_id)

                # Run procedural mapping on the hypothetical graph
                alt_sac   = instantiate_sac(alt_id, graph=hypo_graph)
                alt_score = score_sac(alt_sac)

                # Compute change impact vs failing service
                impact = compare_sac_instances(
                    failing_sac, alt_sac,
                    change_event=f"{failing_id} replaced by {alt_id}"
                )

                alt_sacs[alt_id]    = alt_sac
                alt_scores[alt_id]  = alt_score
                alt_impacts[alt_id] = impact

                knowledge.store_sac_instance(alt_id, alt_sac)
                knowledge.update_completeness_score(alt_id, alt_score["weighted_score"], alt_score)
                print(f"[Planner]   '{alt_id}': {alt_score['completeness_pct']:.1f}% "
                      f"({impact['overall_impact']} delta {impact['delta']:+.1%})")
            except Exception as e:
                print(f"[Planner]   Failed to evaluate '{alt_id}': {e}")

        if not alt_scores:
            print(f"[Planner] All alternatives failed for '{failing_id}'")
            no_alternative.append(failing_id)
            continue

        # Select best alternative by completeness
        comparison = compare_alternatives(failing_score, alt_scores)
        best_id    = comparison["recommended"]
        best_sac   = alt_sacs[best_id]
        best_score = alt_scores[best_id]
        best_impact = alt_impacts[best_id]

        print(f"[Planner] Best alternative: '{best_id}' "
              f"({best_score['completeness_pct']:.1f}%)")
        print(f"[Planner] Reason: {comparison['reason']}")

        adaptation = {
            "failing_service":      failing_id,
            "chosen_alternative":   best_id,
            "reason":               comparison["reason"],
            "completeness_before":  failing_score["weighted_score"],
            "completeness_after":   best_score["weighted_score"],
            "delta":                best_impact["delta"],
            "overall_impact":       best_impact["overall_impact"],
            "improved_rules_count": best_impact["improved_rules_count"],
            "degraded_rules_count": best_impact["degraded_rules_count"],
            "impact_report":        best_impact,
            "comparison":           comparison["comparison"],
            "chosen_sac":           best_sac,
            "chosen_score":         best_score,
            "original_score":       failing_score,
        }
        adaptations.append(adaptation)

    plan = {"adaptations": adaptations, "no_alternative": no_alternative}
    knowledge.store_plan(plan)
    return plan


def run_once(analysis: dict) -> dict:
    """Single planning pass — called by MAPE-K loop."""
    failing = analysis.get("failing", [])
    if not failing:
        print("[Planner] No failing services — nothing to plan.")
        return {"adaptations": [], "no_alternative": []}
    return plan_adaptation(failing)


if __name__ == "__main__":
    service = sys.argv[1] if len(sys.argv) > 1 else "auth-service"
    plan = plan_adaptation([service])
    # Print summary only (SAC details can be large)
    summary = {
        "adaptations": [
            {k: v for k, v in a.items() if k not in ("chosen_sac", "impact_report")}
            for a in plan["adaptations"]
        ],
        "no_alternative": plan["no_alternative"]
    }
    print(json.dumps(summary, indent=2, default=str))
