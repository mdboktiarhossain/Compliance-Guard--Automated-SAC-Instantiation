"""
demo_run.py — Full Pipeline Demo
===================================
Runs the complete SAC Procedural Mapping pipeline and prints
a clean summary of all results.

Usage:
    python demo_run.py

No arguments needed. Runs on auth-service vs auth-service-v2 by default.
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

# Make sure modules resolve
sys.path.insert(0, str(Path(__file__).parent))

from graph_builder import load_graph, graph_summary, get_capabilities_of_service
from sac.instantiate_sac import instantiate_sac
from sac.score_completeness import score_sac
from sac.change_impact import compare_sac_instances

SEP  = "=" * 60
SEP2 = "-" * 60

def banner(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)

def main():
    OUTPUT_DIR = Path(__file__).parent / "sac_instances"
    OUTPUT_DIR.mkdir(exist_ok=True)

    # ── Step 1: Load LPG ─────────────────────────────────────────
    banner("STEP 1 — Load LPG (system_architecture_graph.json)")
    graph = load_graph()
    summary = graph_summary(graph)
    print(f"  Total nodes    : {summary['total_nodes']}")
    print(f"  Total edges    : {summary['total_edges']}")
    print(f"  Services       : {summary['services']} total")
    print(f"  Active         : {summary['active_services']}")
    print(f"  Inactive (alts): {summary['inactive_services']}")
    print(f"  Functions      : {summary['functions']}")
    print(f"  Capabilities   : {summary['capabilities']}")

    # ── Step 2: Capabilities comparison ──────────────────────────
    banner("STEP 2 — Capability Comparison (auth-service vs auth-service-v2)")
    caps_v1 = set(get_capabilities_of_service(graph, "auth-service"))
    caps_v2 = set(get_capabilities_of_service(graph, "auth-service-v2"))
    added   = sorted(caps_v2 - caps_v1)
    shared  = sorted(caps_v1 & caps_v2)
    print(f"  auth-service capabilities    : {len(caps_v1)}")
    print(f"  auth-service-v2 capabilities : {len(caps_v2)}")
    print(f"  Shared                       : {len(shared)}")
    print(f"  Added in v2 (MFA extras)     : {added}")

    # ── Step 3: SAC Instantiation ─────────────────────────────────
    banner("STEP 3 — SAC Instantiation (Procedural Mapping + Hybrid LLM/LPG for AC-3)")

    print(f"\n  [Object 1] extracted_schema.json (NIST rules)")
    print(f"  [Object 2] system_architecture_graph.json (LPG)")
    print(f"  [Engine  ] sac/instantiate_sac.py (3-layer procedural mapping + AC-3 LLM/LPG GSN)")
    print(f"\n{SEP2}")

    sac_v1    = instantiate_sac("auth-service",    graph=graph)
    score_v1  = score_sac(sac_v1)

    print(SEP2)
    sac_v2    = instantiate_sac("auth-service-v2", graph=graph)
    score_v2  = score_sac(sac_v2)

    # Save
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    f_v1 = OUTPUT_DIR / f"demo_sac_auth-service_{ts}.json"
    f_v2 = OUTPUT_DIR / f"demo_sac_auth-service-v2_{ts}.json"
    f_v1.write_text(json.dumps(sac_v1, indent=2), encoding="utf-8")
    f_v2.write_text(json.dumps(sac_v2, indent=2), encoding="utf-8")

    print(f"\n{SEP2}")
    print(f"  SAC RESULTS SUMMARY")
    print(f"{SEP2}")
    print(f"  {'Service':<25} {'Satisfied':>9} {'Partial':>8} {'Missing':>8} {'Compliance':>11}")
    print(f"  {'-'*24} {'-'*9} {'-'*8} {'-'*8} {'-'*11}")

    for svc, sac, score in [
        ("auth-service",    sac_v1, score_v1),
        ("auth-service-v2", sac_v2, score_v2),
    ]:
        pct = score['completeness_pct']
        print(f"  {svc:<25} {sac['satisfied']:>9} {sac['partial']:>8} {sac['missing']:>8} {pct:>10.1f}%")

    # ── Step 4: Change Impact ─────────────────────────────────────
    banner("STEP 4 — Change Impact Report (auth-service -> auth-service-v2)")

    report = compare_sac_instances(
        sac_v1, sac_v2,
        change_event="auth-service replaced by auth-service-v2 (MFA upgrade)"
    )
    f_impact = OUTPUT_DIR / f"demo_impact_{ts}.json"
    f_impact.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\n  {report['summary']}")
    print(f"\n  Completeness BEFORE : {report['completeness_before']:.1%}")
    print(f"  Completeness AFTER  : {report['completeness_after']:.1%}")
    print(f"  Delta               : {report['delta']:+.1%}")
    print(f"  Overall Impact      : {report['overall_impact']}")
    print(f"  Rules Improved      : {report['improved_rules_count']}")
    print(f"  Rules Degraded      : {report['degraded_rules_count']}")

    if report['improved_rules']:
        print(f"\n  Improved Rules:")
        for r in report['improved_rules']:
            print(f"    {r['rule_id']:20s} [{r['status_before']:9s} -> {r['status_after']:9s}]  {r['reason']}")

    if report['degraded_rules']:
        print(f"\n  Degraded Rules:")
        for r in report['degraded_rules']:
            print(f"    {r['rule_id']:20s} [{r['status_before']:9s} -> {r['status_after']:9s}]  {r['reason']}")

    # ── Step 5: MAPE-K Planning Decision ─────────────────────────
    banner("STEP 5 — MAPE-K Planning Decision")
    print(f"\n  Scenario: auth-service has FAILED")
    print(f"  Question: Which alternative should we activate?")
    print(f"\n  Evaluation:")
    print(f"    auth-service-v2 completeness : {score_v2['completeness_pct']:.1f}%")
    print(f"    (only one alternative available for auth-service)")
    print(f"\n  Decision: ACTIVATE auth-service-v2")
    print(f"  Reason  : Highest compliance completeness ({score_v2['completeness_pct']:.1f}%)")
    print(f"            +{report['delta']:.1%} improvement over failing service")
    print(f"            {report['improved_rules_count']} rules newly satisfied")

    # ── Summary ───────────────────────────────────────────────────
    banner("PIPELINE COMPLETE — Output Files")
    print(f"\n  SAC auth-service     : {f_v1.name}")
    print(f"  SAC auth-service-v2  : {f_v2.name}")
    print(f"  Change Impact Report : {f_impact.name}")
    print(f"\n  All saved to: {OUTPUT_DIR}")
    print(f"\n{SEP}\n")


if __name__ == "__main__":
    main()
