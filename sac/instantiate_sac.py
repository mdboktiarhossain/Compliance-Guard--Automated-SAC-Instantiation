"""
sac/instantiate_sac.py — Procedural Mapping Engine (v4.0)
===========================================================
Maps Object 1 (extracted_schema.json — LLM-extracted NIST rules)
against Object 2 (system_architecture_graph.json — LPG)
using pure Python procedural mapping.

Generates a FULL GSN (Goal Structuring Notation) structured SAC instance
matching the reference SAC format, including:
  - Context      : Tailored NIST ODP assignments (LLM + LPG hybrid for AC-3)
  - MainGoal     : Top-level NIST control goals (with provision_set)
  - ReqGoal      : Functional requirement goals — LLM-extracted for AC-3
  - ModuleGoal   : Module/process-level decomposition from LPG functions
  - OpGoal       : Lowest-level operational variable goals
  - Strategy     : Argument strategies linking goals
  - Solution     : Evidence nodes from LPG evidence_list (AC-3) or templates
  - SupportedBy  : Parent→Child links (including Requires/Provides provisions)
  - InContextOf  : Goal ↔ Context associations

v4.0 Changes:
  - AC-3 ReqGoal.functional_requirement now LLM-extracted (main novelty)
  - AC-3 Context tailoring now hybrid LLM + LPG scan
  - AC-3 Solution nodes now built from LPG evidence_list attributes
  - AC-3 assessment_process derived from LPG function names
  - Provenance tracking: req_goal_source, assessment_process_source fields
  - All other controls keep hardcoded templates as before

Based on reference SAC examples: AC-3, AC-4, AU-5(1), IA-3, SC-40, SI-4, SI-7.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from graph_builder import (
    load_graph,
    get_capabilities_of_service,
    get_properties_of_service,
    get_active_services,
    get_node,
)

# LLM-based extractors for AC-3 (main research contribution)
try:
    from sac.extract_req_goals import extract as llm_extract_req
    from sac.extract_context   import extract as llm_extract_context
    _LLM_AVAILABLE = True
except ImportError:
    try:
        from extract_req_goals import extract as llm_extract_req
        from extract_context   import extract as llm_extract_context
        _LLM_AVAILABLE = True
    except ImportError:
        _LLM_AVAILABLE = False
        print("[instantiate_sac] WARNING: LLM extractor modules not found. AC-3 will use fallback.")

SCHEMA_PATH = Path(__file__).parent.parent / "extracted_schema.json"
GRAPH_PATH  = Path(__file__).parent.parent / "system_architecture_graph.json"
OUTPUT_DIR  = Path(__file__).parent.parent / "sac_instances"

# ── Scope-action → capability keyword mapping ─────────────────────────────────
ACTION_TO_CAPABILITY_KEYWORDS = {
    "create":       ["create-account", "create-profile", "create-order"],
    "enable":       ["activate-account"],
    "modify":       ["modify-account", "update-profile"],
    "disable":      ["disable-account", "deactivate-account"],
    "remove":       ["delete-profile"],
    "monitor":      ["monitor-account-usage", "audit-trail", "session-tracking", "monitor-privileged-access"],
    "review":       ["review-accounts", "review-compliance"],
    "authorize":    ["enforce-access-control", "role-based-access", "validate-tokens"],
    "enforce":      ["enforce-access-control", "enforce-flow-policy", "enforce-non-privileged-accounts"],
    "notify":       [],
    "assign":       [],
    "designate":    [],
    "develop":      [],
    "document":     [],
    "disseminate":  [],
    "require":      [],
    "specify":      [],
    "facilitate":   [],
    "establish":    [],
    "implement":    ["enforce-access-control", "role-based-access"],
    "separate":     ["separate-duties", "require-dual-approval"],
    "control":      ["control-information-flow", "control-data-access"],
    "log":          ["audit-trail", "log-privileged-functions", "privileged-function-log"],
    "detect":       ["detect-privilege-escalation", "detect-misuse", "detect-anomalies", "detect-violations"],
    "restrict":     ["restrict-remote-connections", "rate-limiting"],
    "encrypt":      ["encrypt-remote-session", "encrypt-email"],
    "verify":       ["verify-session-integrity", "validate-jwt"],
}

PROCEDURAL_ACTIONS = {
    "notify", "assign", "designate", "develop", "document",
    "disseminate", "require", "specify", "facilitate", "establish",
    "define", "address", "update", "report", "transfer"
}

# ── NIST control → GSN structural knowledge base ──────────────────────────────
# Defines the full GSN hierarchy for each NIST AC control family:
# Derived from reference paramList files (AC-3, AC-4, AU-5(1), IA-3, SC-40, SI-4, SI-7)
# Structure: control → {req_goals, module_goals, op_goals, strategies, inter_control_links}
CONTROL_GSN_TEMPLATES = {
    "AC-2": {
        "control_action": "manage information system accounts",
        "implemented_by": "organization",
        "provision_set": "val(accountTypes),val(accountConditions),val(accountApprovers)",
        "req_goals": [
            {"id": "Req1", "assessment_process": "accountManagementMechanism",
             "functional_requirement": "identify and select account types for organizational mission"},
            {"id": "Req2", "assessment_process": "accountAuthorizationMechanism",
             "functional_requirement": "assign account managers for each account type"},
        ],
        "module_goals": [
            {"id": "M1", "assessment_process": "createAccount"},
            {"id": "M2", "assessment_process": "modifyAccount"},
            {"id": "M3", "assessment_process": "disableAccount"},
            {"id": "M4", "assessment_process": "reviewAccount"},
        ],
        "op_goals": [
            {"id": "M1 G1", "variable": "AccountId", "condition": "create new account with assigned role"},
            {"id": "M1 G2", "variable": "RoleAssignment", "condition": "set role for account"},
            {"id": "M2 G1", "variable": "AccountId", "condition": "update account attributes"},
            {"id": "M3 G1", "variable": "AccountId", "condition": "disable inactive account"},
            {"id": "M4 G1", "variable": "AccountList", "condition": "review all active accounts"},
        ],
        "strategies": [
            {"id": "S1", "assessment_process": "accountManagementMechanism"},
            {"id": "M1S1", "assessment_process": "createAccount"},
            {"id": "M2S1", "assessment_process": "modifyAccount"},
        ],
        "solutions": [
            {"id": "Sn1", "assessment": "audit log of account creation events"},
            {"id": "Sn2", "assessment": "test cases of account modification"},
            {"id": "Sn3", "assessment": "log of account disabling events"},
            {"id": "Sn4", "assessment": "account review report"},
        ],
        "hierarchy": [
            ("Main", "S1"), ("S1", "Req1"), ("S1", "Req2"),
            ("Req1", "M1"), ("Req1", "M2"), ("Req2", "M3"), ("Req2", "M4"),
            ("M1", "M1 G1"), ("M1", "M1 G2"),
            ("M2", "M2 G1"), ("M3", "M3 G1"), ("M4", "M4 G1"),
            ("M1 G1", "Sn1"), ("M1 G2", "Sn2"), ("M2 G1", "Sn2"),
            ("M3 G1", "Sn3"), ("M4 G1", "Sn4"),
        ],
    },
    "AC-3": {
        "control_action": "enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies",
        "implemented_by": "information system",
        "provision_set": "val(authorizationApproval),val(accessControlPolicy)",
        "req_goals": [
            {"id": "Req1", "assessment_process": "enforceAuthorization",
             "functional_requirement": "check connection request and enforce authorization approval"},
        ],
        "module_goals": [
            {"id": "M1", "assessment_process": "getAuthorization"},
            {"id": "M2", "assessment_process": "applyAuthorization"},
        ],
        "op_goals": [
            {"id": "M1 G1", "variable": "Conn", "condition": "get request"},
            {"id": "M1 G2", "variable": "AuthConn", "condition": "set true for authorized connection"},
            {"id": "M2 G1", "variable": "AuthConn", "condition": "set true for authorized connection"},
            {"id": "M2 G2", "variable": "send", "condition": "send data"},
        ],
        "strategies": [
            {"id": "S1", "assessment_process": "enforceAuthorization"},
            {"id": "M1S1", "assessment_process": "getAuthorization"},
            {"id": "M2S1", "assessment_process": "applyAuthorization"},
        ],
        "solutions": [
            {"id": "M1Sn1", "assessment": "log of connection request"},
            {"id": "M1Sn2", "assessment": "log of auth decision"},
            {"id": "M2Sn2", "assessment": "test cases of apply authorization"},
            {"id": "M2Sn3", "assessment": "log of send data"},
        ],
        "hierarchy": [
            ("Main", "S1"), ("S1", "Req1"),
            ("Req1", "M1"), ("Req1", "M2"),
            ("M1", "M1 G1"), ("M1", "M1 G2"),
            ("M2", "M2 G1"), ("M2", "M2 G2"),
            ("M1 G1", "M1Sn1"), ("M1 G2", "M1Sn2"),
            ("M2 G1", "M2Sn2"), ("M2 G2", "M2Sn3"),
        ],
        "inter_control_links": [
            {"from": "Main", "to": "AC-21 Main", "requires": "val(accessControlPolicy)"},
            {"from": "AC-21 Main", "to": "Main", "requires": "val(authorizationDecision)"},
        ],
        "related_main_goals": [
            {"id": "AC-21 Main", "family": "AC", "number": "21",
             "implemented_by": "organization",
             "control_action": "enable authorized users to determine whether access authorizations assigned to a sharing partner match the information's access and use restrictions",
             "provision_set": "val(authorizationDecision)"},
        ],
    },
    "AC-4": {
        "control_action": "enforces approved authorizations for controlling the flow of information within the system and between connected systems",
        "implemented_by": "information system",
        "provision_set": "val(informationFlowPolicy),val(flowControlDecision)",
        "req_goals": [
            {"id": "Req1", "assessment_process": "enforceFlowControl",
             "functional_requirement": "check information flow against approved policy"},
        ],
        "module_goals": [
            {"id": "M1", "assessment_process": "inspectFlow"},
            {"id": "M2", "assessment_process": "applyFlowDecision"},
        ],
        "op_goals": [
            {"id": "M1 G1", "variable": "DataPacket", "condition": "inspect incoming data packet"},
            {"id": "M1 G2", "variable": "FlowPolicy", "condition": "evaluate against flow control policy"},
            {"id": "M2 G1", "variable": "FlowDecision", "condition": "allow or deny flow based on policy"},
        ],
        "strategies": [
            {"id": "S1", "assessment_process": "enforceFlowControl"},
            {"id": "M1S1", "assessment_process": "inspectFlow"},
            {"id": "M2S1", "assessment_process": "applyFlowDecision"},
        ],
        "solutions": [
            {"id": "Sn1", "assessment": "log of data flow decisions"},
            {"id": "Sn2", "assessment": "test cases for flow control enforcement"},
            {"id": "Sn3", "assessment": "audit trail of denied flows"},
        ],
        "hierarchy": [
            ("Main", "S1"), ("S1", "Req1"),
            ("Req1", "M1"), ("Req1", "M2"),
            ("M1", "M1 G1"), ("M1", "M1 G2"),
            ("M2", "M2 G1"),
            ("M1 G1", "Sn1"), ("M1 G2", "Sn2"), ("M2 G1", "Sn3"),
        ],
    },
    "AC-5": {
        "control_action": "separate the duties of individuals to reduce the risk of malevolent activity without collusion",
        "implemented_by": "information system",
        "provision_set": "val(separationOfDuties),val(dutyAssignment)",
        "req_goals": [
            {"id": "Req1", "assessment_process": "separateDutiesMechanism",
             "functional_requirement": "identify and document separation of duties requirements"},
            {"id": "Req2", "assessment_process": "enforceSeparation",
             "functional_requirement": "enforce separation of duties access authorizations"},
        ],
        "module_goals": [
            {"id": "M1", "assessment_process": "defineDutyConflict"},
            {"id": "M2", "assessment_process": "enforceConflict"},
        ],
        "op_goals": [
            {"id": "M1 G1", "variable": "DutyConflictMatrix", "condition": "define conflicting duty pairs"},
            {"id": "M2 G1", "variable": "RoleAssignment", "condition": "prevent conflicting role assignment"},
        ],
        "strategies": [
            {"id": "S1", "assessment_process": "separateDutiesMechanism"},
            {"id": "M1S1", "assessment_process": "defineDutyConflict"},
        ],
        "solutions": [
            {"id": "Sn1", "assessment": "separation of duties policy document"},
            {"id": "Sn2", "assessment": "test cases for role conflict prevention"},
            {"id": "Sn3", "assessment": "audit log of privilege assignments"},
        ],
        "hierarchy": [
            ("Main", "S1"), ("S1", "Req1"), ("S1", "Req2"),
            ("Req1", "M1"), ("Req2", "M2"),
            ("M1", "M1 G1"), ("M2", "M2 G1"),
            ("M1 G1", "Sn1"), ("M2 G1", "Sn2"), ("M2 G1", "Sn3"),
        ],
    },
    "AC-6": {
        "control_action": "employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned tasks",
        "implemented_by": "information system",
        "provision_set": "val(leastPrivilege),val(privilegeAssignment)",
        "req_goals": [
            {"id": "Req1", "assessment_process": "leastPrivilegeMechanism",
             "functional_requirement": "restrict privileged accounts to security functions"},
            {"id": "Req2", "assessment_process": "privilegedFunctionLog",
             "functional_requirement": "log use of privileged functions"},
        ],
        "module_goals": [
            {"id": "M1", "assessment_process": "assignMinimalPrivilege"},
            {"id": "M2", "assessment_process": "auditPrivilegedFunctions"},
            {"id": "M3", "assessment_process": "reviewPrivilegedAccounts"},
        ],
        "op_goals": [
            {"id": "M1 G1", "variable": "UserPrivilege", "condition": "assign minimum necessary privilege"},
            {"id": "M1 G2", "variable": "PrivilegedAccount", "condition": "restrict to security personnel"},
            {"id": "M2 G1", "variable": "FunctionLog", "condition": "log all privileged function invocations"},
            {"id": "M3 G1", "variable": "AccountList", "condition": "review privileged accounts periodically"},
        ],
        "strategies": [
            {"id": "S1", "assessment_process": "leastPrivilegeMechanism"},
            {"id": "M1S1", "assessment_process": "assignMinimalPrivilege"},
            {"id": "M2S1", "assessment_process": "auditPrivilegedFunctions"},
        ],
        "solutions": [
            {"id": "Sn1", "assessment": "privilege assignment audit log"},
            {"id": "Sn2", "assessment": "privileged function usage log"},
            {"id": "Sn3", "assessment": "test cases for non-privileged user restriction"},
            {"id": "Sn4", "assessment": "periodic review report of privileged accounts"},
        ],
        "hierarchy": [
            ("Main", "S1"), ("S1", "Req1"), ("S1", "Req2"),
            ("Req1", "M1"), ("Req1", "M3"), ("Req2", "M2"),
            ("M1", "M1 G1"), ("M1", "M1 G2"),
            ("M2", "M2 G1"), ("M3", "M3 G1"),
            ("M1 G1", "Sn1"), ("M1 G2", "Sn3"),
            ("M2 G1", "Sn2"), ("M3 G1", "Sn4"),
        ],
    },
    "AC-17": {
        "control_action": "establish and document usage restrictions and implementation guidance for remote access",
        "implemented_by": "organization",
        "provision_set": "val(remoteAccessPolicy),val(sessionMonitoring)",
        "req_goals": [
            {"id": "Req1", "assessment_process": "remoteAccessControl",
             "functional_requirement": "authorize remote access sessions before connection"},
            {"id": "Req2", "assessment_process": "remoteSessionMonitoring",
             "functional_requirement": "monitor and control remote access sessions"},
        ],
        "module_goals": [
            {"id": "M1", "assessment_process": "authenticateRemoteUser"},
            {"id": "M2", "assessment_process": "encryptRemoteSession"},
            {"id": "M3", "assessment_process": "monitorRemoteSession"},
        ],
        "op_goals": [
            {"id": "M1 G1", "variable": "RemoteUser", "condition": "authenticate remote user before session"},
            {"id": "M2 G1", "variable": "SessionChannel", "condition": "encrypt remote session data"},
            {"id": "M3 G1", "variable": "SessionLog", "condition": "log remote session activity"},
        ],
        "strategies": [
            {"id": "S1", "assessment_process": "remoteAccessControl"},
            {"id": "M1S1", "assessment_process": "authenticateRemoteUser"},
            {"id": "M2S1", "assessment_process": "encryptRemoteSession"},
        ],
        "solutions": [
            {"id": "Sn1", "assessment": "remote access authorization log"},
            {"id": "Sn2", "assessment": "encrypted session test results"},
            {"id": "Sn3", "assessment": "remote session activity log"},
        ],
        "hierarchy": [
            ("Main", "S1"), ("S1", "Req1"), ("S1", "Req2"),
            ("Req1", "M1"), ("Req2", "M2"), ("Req2", "M3"),
            ("M1", "M1 G1"), ("M2", "M2 G1"), ("M3", "M3 G1"),
            ("M1 G1", "Sn1"), ("M2 G1", "Sn2"), ("M3 G1", "Sn3"),
        ],
    },
}

# Default template for controls not explicitly defined
DEFAULT_GSN_TEMPLATE = {
    "req_goals": [
        {"id": "Req1", "assessment_process": "complianceMechanism",
         "functional_requirement": "satisfy control requirement through system capabilities"},
    ],
    "module_goals": [
        {"id": "M1", "assessment_process": "verifyCompliance"},
        {"id": "M2", "assessment_process": "logEvidence"},
    ],
    "op_goals": [
        {"id": "M1 G1", "variable": "ComplianceState", "condition": "verify control is implemented"},
        {"id": "M2 G1", "variable": "EvidenceLog", "condition": "produce audit evidence for control"},
    ],
    "strategies": [
        {"id": "S1", "assessment_process": "complianceMechanism"},
        {"id": "M1S1", "assessment_process": "verifyCompliance"},
    ],
    "solutions": [
        {"id": "Sn1", "assessment": "compliance verification test result"},
        {"id": "Sn2", "assessment": "audit evidence log"},
    ],
    "hierarchy": [
        ("Main", "S1"), ("S1", "Req1"),
        ("Req1", "M1"), ("Req1", "M2"),
        ("M1", "M1 G1"), ("M2", "M2 G1"),
        ("M1 G1", "Sn1"), ("M2 G1", "Sn2"),
    ],
}


# ── Helper functions ───────────────────────────────────────────────────────────

def _normalize_citation(citation: str) -> str:
    return citation.replace("NIST-", "").strip()


def _get_parent_control(citation: str) -> str:
    m = re.match(r'^([A-Z]+-\d+)', citation)
    return m.group(1) if m else citation


def _get_control_family(citation: str) -> str:
    m = re.match(r'^([A-Z]+)', citation)
    return m.group(1) if m else "AC"


def _service_nist_controls(graph: dict, service_id: str) -> list:
    node = get_node(graph, service_id)
    if node:
        return node["properties"].get("nist_controls", [])
    return []


def _citation_matches_controls(citation: str, nist_controls: list) -> bool:
    norm = _normalize_citation(citation)
    for ctrl in nist_controls:
        c = _normalize_citation(ctrl)
        if c == norm:
            return True
        if norm.startswith(c + "(") or norm.startswith(c + "-"):
            return True
    return False


def _get_required_capabilities_from_scope(scope: dict) -> list:
    actions = scope.get("action", [])
    caps = []
    for action in actions:
        caps.extend(ACTION_TO_CAPABILITY_KEYWORDS.get(action.lower(), []))
    return list(set(caps))


def _is_procedural_rule(rule: dict) -> bool:
    if rule.get("implemented_by", "") != "organization":
        return False
    actions = rule.get("scope", {}).get("action", [])
    return all(a.lower() in PROCEDURAL_ACTIONS for a in actions)


def _get_service_name(graph: dict, service_id: str) -> str:
    for n in graph["nodes"]:
        if n["id"] == service_id:
            return n["properties"].get("name", service_id)
    return service_id


# ── Core mapping function (layer 1/2/3) ───────────────────────────────────────

def map_rule_to_service(rule: dict, service_id: str, graph: dict) -> dict:
    citation      = rule.get("source_citation", rule.get("rule_id", ""))
    nist_controls = _service_nist_controls(graph, service_id)
    service_caps  = get_capabilities_of_service(graph, service_id)
    service_props = get_properties_of_service(graph, service_id)

    if _is_procedural_rule(rule):
        return {
            "rule_id":             rule.get("rule_id", ""),
            "source_citation":     citation,
            "control_title":       rule.get("control_title", ""),
            "satisfaction_status": "partial",
            "confidence":          0.5,
            "impact_factor":       rule.get("impact_factor", 0.5),
            "implemented_by":      rule.get("implemented_by", "organization"),
            "evidence": [{
                "type":    "implementation_type",
                "note":    "Organizational/procedural rule. System provides technical support "
                           "(audit logging, account management) but policy must be implemented by the organization.",
                "node_id": service_id,
            }],
            "missing": ["organizational-policy-implementation"],
            "gap_description": "Requires organizational procedures — system provides technical foundations only.",
        }

    control_matched = _citation_matches_controls(citation, nist_controls)
    required_caps   = _get_required_capabilities_from_scope(rule.get("scope", {}))
    matched_caps    = [c for c in required_caps if c in service_caps]
    missing_caps    = [c for c in required_caps if c not in service_caps]

    evidence = []
    for cap in matched_caps:
        evidence.append({
            "type": "capability_match",
            "node_id": service_id,
            "matched_capability": cap,
        })

    required_props = rule.get("required_properties", {})
    for prop, val in required_props.items():
        actual = service_props.get(prop)
        if actual == val:
            evidence.append({"type": "property_match", "node_id": service_id,
                              "property": prop, "value": actual})
        else:
            missing_caps.append(f"{prop}={val}")

    if not control_matched and not matched_caps:
        status     = "missing"
        confidence = 0.0
        missing    = missing_caps or [f"control {citation} not in service scope"]
        gap        = f"Service '{service_id}' does not implement {citation}."
    elif control_matched and len(matched_caps) == len(required_caps):
        status     = "satisfied"
        confidence = 1.0
        missing    = []
        gap        = ""
        evidence.append({"type": "control_scope_match", "node_id": service_id,
                         "nist_control": citation, "service_controls": nist_controls})
    elif control_matched or matched_caps:
        ratio      = (len(matched_caps) / len(required_caps)) if required_caps else 0.7
        status     = "partial"
        confidence = round(max(0.4, ratio), 2)
        missing    = missing_caps
        gap        = (f"Missing capabilities: {', '.join(missing_caps)}" if missing_caps
                      else f"Control {citation} in scope but capability evidence incomplete.")
        if control_matched:
            evidence.append({"type": "control_scope_match", "node_id": service_id,
                             "nist_control": citation, "service_controls": nist_controls})
    else:
        status     = "missing"
        confidence = 0.0
        missing    = missing_caps or [f"control {citation} not in service scope"]
        gap        = f"Service '{service_id}' does not implement {citation}."

    return {
        "rule_id":             rule.get("rule_id", ""),
        "source_citation":     citation,
        "control_title":       rule.get("control_title", ""),
        "satisfaction_status": status,
        "confidence":          confidence,
        "impact_factor":       rule.get("impact_factor", 0.5),
        "implemented_by":      rule.get("implemented_by", "information system"),
        "evidence":            evidence,
        "missing":             missing,
        "gap_description":     gap,
    }


# ── GSN Structure Builder (Full GSN format) ──────────────────────────────────

def _safe_id(s: str) -> str:
    """Make a string safe to use as part of an XML/JSON identifier."""
    return re.sub(r'[^A-Za-z0-9_\-]', '_', s)


def _make_context_nodes(rule: dict, parent_id: str) -> list:
    """Build Context nodes from ODP assignments in the rule."""
    contexts = []
    for i, odp in enumerate(rule.get("odp_assignments", []), 1):
        ctx_id = f"{parent_id}[{i}]"
        tailoring = f"{odp.get('placeholder','param')} = \"{odp.get('suggested_value','TBD')}\""
        contexts.append({
            "identifier": ctx_id,
            "tailoring": tailoring,
            "statement": f"Context: {ctx_id}: Assignment: {tailoring}",
        })
    return contexts


def _get_ac3_statement_from_schema(schema_rules: list) -> str:
    """Find the AC-3 control statement from the schema rules."""
    for rule in schema_rules:
        citation = rule.get("source_citation", "")
        if citation == "AC-3":
            return rule.get("requirement", "")
    # Authoritative fallback from NIST SP 800-53 Rev.5
    return (
        "The information system enforces approved authorizations for logical access "
        "to information and system resources in accordance with applicable access "
        "control policies."
    )


def _get_lpg_functions_for_service(graph: dict, service_id: str) -> list:
    """
    Return all Function nodes reachable from the service via HAS_FUNCTION edges.
    Each entry: {id, name, type, evidence_list}
    """
    functions = []
    for edge in graph.get("edges", []):
        if edge.get("source") == service_id and edge.get("label") == "HAS_FUNCTION":
            fn_id = edge.get("target", "")
            fn_node = get_node(graph, fn_id)
            if fn_node:
                props = fn_node.get("properties", {})
                functions.append({
                    "id":           fn_id,
                    "name":         props.get("name", fn_id),
                    "type":         props.get("type", ""),
                    "has_evidence": props.get("has_evidence", False),
                    "evidence_list": props.get("evidence_list", []),
                })
    return functions


def _collect_lpg_solutions_for_control(graph: dict, service_id: str,
                                       control_id: str) -> list:
    """
    Collect Solution node definitions from LPG evidence_list attributes
    on function nodes belonging to service_id.
    Returns list of {identifier, assessment, statement, evidence_type}
    """
    solutions = []
    functions = _get_lpg_functions_for_service(graph, service_id)
    for fn in functions:
        for ev in fn.get("evidence_list", []):
            sol_id  = f"{control_id} {ev.get('solution_id', 'Sn0')}"
            desc    = ev.get("description", "evidence")
            ev_type = ev.get("type", "log")
            solutions.append({
                "identifier":   sol_id,
                "assessment":   desc,
                "statement":    f"Solution: {sol_id}: {desc}",
                "evidence_type": ev_type,
                "source":        "lpg",
            })
    return solutions


def _get_lpg_assessment_process(graph: dict, service_id: str,
                                fn_type: str = "access_control") -> str:
    """
    Find the function name in the LPG matching the given type for this service.
    Used to derive assessment_process from the architecture rather than hardcoding.
    """
    functions = _get_lpg_functions_for_service(graph, service_id)
    for fn in functions:
        if fn.get("type") == fn_type:
            return fn["id"]  # e.g. 'fn-authv2-rbac-enforcer'
    # Fallback: return first function
    if functions:
        return functions[0]["id"]
    return f"{service_id}-enforcer"


def build_gsn_structure(service_id: str, service_name: str,
                        rule_mappings: list, schema_rules: list,
                        graph: dict = None) -> dict:
    """
    Build a complete GSN-structured assurance case in standard GSN format.

    For AC-3 specifically (v4.0+):
      - functional_requirement extracted by LLM (main research novelty)
      - Context tailoring derived by hybrid LLM + LPG scan
      - Solution nodes built from LPG evidence_list attributes
      - assessment_process derived from LPG function names

    Returns a dict with:
      contexts, main_goals, req_goals, module_goals, op_goals,
      strategies, solutions, in_context_of_links, supported_by_links
    """
    # Group rules by parent control (e.g. AC-3, AC-6)
    grouped = {}
    rule_by_id = {r["rule_id"]: r for r in schema_rules}

    for rm in rule_mappings:
        citation = rm.get("source_citation", "")
        parent   = _get_parent_control(citation)
        grouped.setdefault(parent, []).append(rm)

    gsn = {
        "contexts":           [],
        "main_goals":         [],
        "req_goals":          [],
        "module_goals":       [],
        "op_goals":           [],
        "strategies":         [],
        "solutions":          [],
        "in_context_of":      [],
        "supported_by":       [],
    }

    # Principal (top-level) main goal for the entire service
    principal_id = f"{service_id}-Principal"
    principal_ctx_id = f"CTX-{service_id}-scope"
    gsn["contexts"].append({
        "identifier": principal_ctx_id,
        "tailoring":  f"service = \"{service_name}\"",
        "statement":  f"Context: {principal_ctx_id}: NIST SP 800-53 Rev.5 AC family scope for {service_name}",
    })
    gsn["main_goals"].append({
        "identifier":         principal_id,
        "family":             "AC",
        "number":             "0",
        "implemented_by":     "information system",
        "control_action":     f"satisfies all applicable NIST SP 800-53 Access Control requirements",
        "baseline_allocation":"high",
        "provision_set":      ",".join(
            [f"val({_safe_id(p)})" for p in sorted(grouped.keys())]
        ),
        "achievement_weight": "1",
        "statement":          (f"Goal: {principal_id}: {service_name} satisfies all applicable "
                               f"NIST SP 800-53 Access Control security requirements; Impact = high; aw = 1"),
        "satisfaction_status": "partial",
        "compliance_summary": {
            "total_controls": len(rule_mappings),
            "satisfied": sum(1 for r in rule_mappings if r["satisfaction_status"] == "satisfied"),
            "partial":   sum(1 for r in rule_mappings if r["satisfaction_status"] == "partial"),
            "missing":   sum(1 for r in rule_mappings if r["satisfaction_status"] == "missing"),
        }
    })
    gsn["in_context_of"].append({"source": principal_id, "destination": principal_ctx_id})

    principal_strategy_id = f"S-{service_id}-decompose"
    gsn["strategies"].append({
        "identifier": principal_strategy_id,
        "assessment_process": "controlFamilyDecomposition",
        "statement": f"Strategy: {principal_strategy_id}: Decompose by NIST control and argue compliance for each",
    })
    gsn["supported_by"].append({"source": principal_id, "destination": principal_strategy_id})

    # Per-control GSN subtree
    processed_inter_links = set()

    for parent_ctrl, mappings in sorted(grouped.items()):
        template = CONTROL_GSN_TEMPLATES.get(parent_ctrl, None)
        ctrl_id  = _safe_id(parent_ctrl)
        p        = ctrl_id  # prefix for identifiers

        # Determine overall satisfaction for this control
        statuses   = [m["satisfaction_status"] for m in mappings]
        if all(s == "satisfied" for s in statuses):
            ctrl_status = "satisfied"
        elif all(s == "missing" for s in statuses):
            ctrl_status = "missing"
        else:
            ctrl_status = "partial"

        conf_avg = round(sum(m["confidence"] for m in mappings) / len(mappings), 2)

        # Get odp from first rule in group that matches this parent
        sample_rule = {}
        for rm in mappings:
            rid = rm["rule_id"]
            if rid in rule_by_id:
                sample_rule = rule_by_id[rid]
                break

        # ── Context nodes (ODP assignments) ─────────────────────────
        # AC-3: use hybrid LLM+LPG extraction
        # Others: use ODP assignments from schema (or default)
        if parent_ctrl == "AC-3" and _LLM_AVAILABLE and graph is not None:
            ac3_stmt = _get_ac3_statement_from_schema(schema_rules)
            llm_ctx  = llm_extract_context("AC-3", ac3_stmt, service_id, graph)
            ctrl_contexts = [{
                "identifier": llm_ctx["identifier"],
                "tailoring":  llm_ctx["tailoring"],
                "statement":  llm_ctx["statement"],
                "param_source": llm_ctx.get("param_source", "llm"),
                "value_source": llm_ctx.get("value_source", "lpg"),
            }]
        else:
            ctrl_contexts = _make_context_nodes(sample_rule, parent_ctrl)
            if not ctrl_contexts:
                impl_by = sample_rule.get("implemented_by", "information system")
                ctrl_contexts = [{
                    "identifier": f"{parent_ctrl}[1]",
                    "tailoring":  f"implementedBy = \"{impl_by}\"",
                    "statement":  f"Context: {parent_ctrl}[1]: implementedBy = \"{impl_by}\"",
                }]
        for ctx in ctrl_contexts:
            gsn["contexts"].append(ctx)

        # ── Main goal for this control ───────────────────────────────
        if template:
            ctrl_action   = template["control_action"]
            impl_by       = template["implemented_by"]
            provision_set = template["provision_set"]
        else:
            ctrl_action   = sample_rule.get("requirement", f"comply with {parent_ctrl}")
            impl_by       = sample_rule.get("implemented_by", "information system")
            provision_set = f"val({ctrl_id}Compliance)"

        main_goal_id = f"{parent_ctrl} Main"
        family       = _get_control_family(parent_ctrl)
        number       = re.sub(r'[^0-9]', '', parent_ctrl.split('-')[-1].split('(')[0]) or "0"

        gsn["main_goals"].append({
            "identifier":         main_goal_id,
            "family":             family,
            "number":             number,
            "implemented_by":     impl_by,
            "control_action":     ctrl_action,
            "baseline_allocation": sample_rule.get("baseline_allocation", "high").lower(),
            "provision_set":      provision_set,
            "achievement_weight": "1",
            "statement":          (f"Goal: {family}-{number} {main_goal_id} Main: {impl_by} {ctrl_action}; "
                                   f"Impact = {sample_rule.get('baseline_allocation','high').lower()}, "
                                   f"Provides= [ {provision_set}]; aw = 1"),
            "satisfaction_status": ctrl_status,
            "confidence":          conf_avg,
        })

        # Link principal strategy → this control's main goal
        gsn["supported_by"].append({"source": principal_strategy_id, "destination": main_goal_id})

        # InContextOf: main goal ↔ contexts
        for ctx in ctrl_contexts:
            gsn["in_context_of"].append({"source": main_goal_id, "destination": ctx["identifier"]})

        # ── Related main goals (inter-control) from template ─────────
        if template:
            for rg in template.get("related_main_goals", []):
                rg_id = rg["id"]
                if rg_id not in [g["identifier"] for g in gsn["main_goals"]]:
                    gsn["main_goals"].append({
                        "identifier":         rg_id,
                        "family":             rg["family"],
                        "number":             rg["number"],
                        "implemented_by":     rg["implemented_by"],
                        "control_action":     rg["control_action"],
                        "baseline_allocation":"high",
                        "provision_set":      rg["provision_set"],
                        "achievement_weight": "1",
                        "statement":          (f"Goal: {rg['family']}-{rg['number']} {rg_id} Main: "
                                               f"{rg['implemented_by']} {rg['control_action']}; "
                                               f"Impact = high, Provides= [ {rg['provision_set']}]; aw = 1"),
                    })

        # ── Strategy nodes ───────────────────────────────────────────
        tmpl_strategies = template["strategies"] if template else DEFAULT_GSN_TEMPLATE["strategies"]
        for strat in tmpl_strategies:
            s_id = f"{parent_ctrl} {strat['id']}"
            gsn["strategies"].append({
                "identifier":       s_id,
                "assessment_process": strat["assessment_process"],
                "statement":        f"Strategy: {s_id}: Argument over {strat['assessment_process']}",
            })

        # ── ReqGoal nodes ────────────────────────────────────────────
        # AC-3: use LLM to extract functional_requirement (main novelty)
        # Others: use hardcoded template
        tmpl_req = template["req_goals"] if template else DEFAULT_GSN_TEMPLATE["req_goals"]
        ac3_stmt = _get_ac3_statement_from_schema(schema_rules)
        lpg_ap   = _get_lpg_assessment_process(graph, service_id, "access_control") if graph else None

        for rg in tmpl_req:
            rg_id = f"{parent_ctrl} {rg['id']}"

            if parent_ctrl == "AC-3" and _LLM_AVAILABLE:
                # LLM extracts functional_requirement
                llm_rg = llm_extract_req("AC-3", ac3_stmt)
                func_req   = llm_rg["functional_requirement"]
                rg_source  = llm_rg["source"]
                # assessment_process from LPG
                ap_name    = lpg_ap if lpg_ap else rg["assessment_process"]
                ap_source  = "lpg" if lpg_ap else "fallback"
            else:
                func_req  = rg["functional_requirement"]
                rg_source = "template"
                ap_name   = rg["assessment_process"]
                ap_source = "template"

            gsn["req_goals"].append({
                "identifier":               rg_id,
                "assessment_process":        ap_name,
                "assessment_process_source": ap_source,
                "functional_requirement":    func_req,
                "req_goal_source":           rg_source,
                "achievement_weight":        "1",
                "satisfaction_status":       ctrl_status,
                "statement": (
                    f"Goal: {rg_id}: {ap_name} maintains "
                    f"{func_req}; aw = 1"
                ),
            })

        # ── ModuleGoal nodes ─────────────────────────────────────────
        tmpl_mod = template["module_goals"] if template else DEFAULT_GSN_TEMPLATE["module_goals"]
        for mg in tmpl_mod:
            mg_id = f"{parent_ctrl} {mg['id']}"
            gsn["module_goals"].append({
                "identifier":         mg_id,
                "assessment_process": mg["assessment_process"],
                "achievement_weight": "1",
                "statement":          (f"Module: {mg_id} : Argument over operational subgoal(s) of "
                                       f"{mg['assessment_process']}; aw = 1"),
            })

        # ── OpGoal nodes ─────────────────────────────────────────────
        tmpl_op = template["op_goals"] if template else DEFAULT_GSN_TEMPLATE["op_goals"]
        for og in tmpl_op:
            og_id = f"{parent_ctrl} {og['id']}"
            gsn["op_goals"].append({
                "identifier":         og_id,
                "variable":           og["variable"],
                "condition":          og["condition"],
                "achievement_weight": "1",
                "statement":          (f"Goal: {og_id}: Variables = {og['variable']}; "
                                       f"Condition = {og['condition']}; aw = 1"),
            })

        # ── Solution nodes ────────────────────────────────────────────
        # AC-3: build Solution nodes from LPG evidence_list
        # Others: use hardcoded template
        if parent_ctrl == "AC-3" and graph is not None:
            lpg_solutions = _collect_lpg_solutions_for_control(graph, service_id, "AC-3")
            if lpg_solutions:
                for sol in lpg_solutions:
                    if not any(s["assessment"] == sol["assessment"] for s in gsn["solutions"]):
                        gsn["solutions"].append(sol)
                print(f"[SAC] AC-3 Solution nodes: {len(lpg_solutions)} from LPG evidence_list")
            else:
                # Fallback to template solutions
                tmpl_sol = template["solutions"] if template else DEFAULT_GSN_TEMPLATE["solutions"]
                for sol in tmpl_sol:
                    sol_id = f"{parent_ctrl} {sol['id']}"
                    gsn["solutions"].append({
                        "identifier": sol_id,
                        "assessment": sol["assessment"],
                        "statement":  f"Solution: {sol_id}: {sol['assessment']}",
                        "source":     "template_fallback",
                    })
        else:
            tmpl_sol = template["solutions"] if template else DEFAULT_GSN_TEMPLATE["solutions"]
            for sol in tmpl_sol:
                sol_id = f"{parent_ctrl} {sol['id']}"
                gsn["solutions"].append({
                    "identifier": sol_id,
                    "assessment": sol["assessment"],
                    "statement":  f"Solution: {sol_id}: {sol['assessment']}",
                })

        # Also generate solutions from actual LPG evidence
        for rm in mappings:
            for idx, ev in enumerate(rm.get("evidence", []), 1):
                ev_type = ev.get("type", "")
                if ev_type == "capability_match":
                    ev_sol_id = f"{parent_ctrl} LPG-Sn{_safe_id(rm['rule_id'])}-{idx}"
                    desc = f"LPG capability match: '{ev.get('matched_capability')}' on {service_id}"
                    if not any(s["assessment"] == desc for s in gsn["solutions"]):
                        gsn["solutions"].append({
                            "identifier": ev_sol_id,
                            "assessment": desc,
                            "statement":  f"Solution: {ev_sol_id}: {desc}",
                        })
                elif ev_type == "control_scope_match":
                    ev_sol_id = f"{parent_ctrl} LPG-CSM-{_safe_id(rm['rule_id'])}"
                    desc = f"LPG control scope match: {rm['source_citation']} in {service_id}.nist_controls"
                    if not any(s["assessment"] == desc for s in gsn["solutions"]):
                        gsn["solutions"].append({
                            "identifier": ev_sol_id,
                            "assessment": desc,
                            "statement":  f"Solution: {ev_sol_id}: {desc}",
                        })

        # ── SupportedBy hierarchy links ──────────────────────────────
        tmpl_hier = template["hierarchy"] if template else DEFAULT_GSN_TEMPLATE["hierarchy"]

        def resolve_id(short_id: str, ctrl_prefix: str) -> str:
            """Resolve short template IDs to full qualified IDs."""
            if short_id == "Main":
                return f"{ctrl_prefix} Main"
            # Check if it looks like a strategy (S1, M1S1, M2S1...)
            if re.match(r'^(S\d+|M\d+S\d+)$', short_id):
                return f"{ctrl_prefix} {short_id}"
            # Req, Module, Op goals
            if re.match(r'^(Req\d+|M\d+|M\d+ G\d+|G-\d+)$', short_id):
                return f"{ctrl_prefix} {short_id}"
            # Solution
            if re.match(r'^(Sn\d+|M\d+Sn\d+|MSn\d+|LPG-.+)$', short_id):
                return f"{ctrl_prefix} {short_id}"
            return f"{ctrl_prefix} {short_id}"

        for (src_short, dst_short) in tmpl_hier:
            src_full = resolve_id(src_short, parent_ctrl)
            dst_full = resolve_id(dst_short, parent_ctrl)
            gsn["supported_by"].append({"source": src_full, "destination": dst_full})

        # ── Inter-control SupportedBy links (Requires/Provides) ─────
        if template:
            for link in template.get("inter_control_links", []):
                src_full = (f"{parent_ctrl} Main" if link["from"] == "Main"
                            else link["from"])
                dst_full = link["to"]
                link_key = (src_full, dst_full)
                if link_key not in processed_inter_links:
                    processed_inter_links.add(link_key)
                    gsn["supported_by"].append({
                        "source":      src_full,
                        "destination": dst_full,
                        "requires":    link["requires"],
                    })

    return gsn


# ── SAC instantiation ──────────────────────────────────────────────────────────

def instantiate_sac(
    service_id: str,
    graph: dict = None,
    schema_path: Path = SCHEMA_PATH,
) -> dict:
    """
    Procedurally map all NIST rules against the given service.
    Returns a complete SAC instance dict with full GSN structure.
    """
    if graph is None:
        graph = load_graph(GRAPH_PATH)

    schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
    rules       = schema_data.get("rules", [])

    llm_status = "with LLM (AC-3)" if _LLM_AVAILABLE else "fallback only"
    print(f"[SAC] Mapping {len(rules)} rules -> '{service_id}' ({llm_status})...")

    rule_mappings = []
    satisfied = partial = missing_count = 0

    for rule in rules:
        mapping = map_rule_to_service(rule, service_id, graph)
        rule_mappings.append(mapping)
        s = mapping["satisfaction_status"]
        if s == "satisfied":
            satisfied += 1
        elif s == "partial":
            partial += 1
        else:
            missing_count += 1

    service_name = _get_service_name(graph, service_id)
    gsn_case     = build_gsn_structure(service_id, service_name, rule_mappings, rules, graph=graph)

    result = {
        "sac_instance_id":    f"sac-{service_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
        "service_id":         service_id,
        "service_name":       service_name,
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "total_rules":        len(rules),
        "satisfied":          satisfied,
        "partial":            partial,
        "missing":            missing_count,
        "rule_mappings":      rule_mappings,
        "gsn_assurance_case": gsn_case,
    }

    status_weights = {"satisfied": 1.0, "partial": 0.5, "missing": 0.0}
    weighted_sum   = sum(
        status_weights.get(m["satisfaction_status"], 0.0) * float(m.get("impact_factor", 0.5))
        for m in rule_mappings
    )
    total_weight   = sum(float(m.get("impact_factor", 0.5)) for m in rule_mappings)
    pct            = round(100 * weighted_sum / total_weight, 1) if total_weight > 0 else 0.0
    print(f"[SAC] Done: {satisfied} satisfied | {partial} partial | {missing_count} missing | {pct:.1f}% compliant")

    gsn = gsn_case
    print(f"[SAC] GSN structure: "
          f"{len(gsn['contexts'])} contexts, "
          f"{len(gsn['main_goals'])} main_goals, "
          f"{len(gsn['req_goals'])} req_goals, "
          f"{len(gsn['module_goals'])} module_goals, "
          f"{len(gsn['op_goals'])} op_goals, "
          f"{len(gsn['strategies'])} strategies, "
          f"{len(gsn['solutions'])} solutions, "
          f"{len(gsn['supported_by'])} supported_by links")
    return result


def instantiate_sac_all_active(graph: dict = None) -> dict:
    """Run SAC for ALL active services. Returns combined report."""
    if graph is None:
        graph = load_graph(GRAPH_PATH)
    active  = get_active_services(graph)
    results = {}
    for svc in active:
        results[svc["id"]] = instantiate_sac(svc["id"], graph=graph)
    return {
        "report_id": f"sac-all-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services":  results,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    OUTPUT_DIR.mkdir(exist_ok=True)

    if len(sys.argv) > 1 and sys.argv[1] == "all":
        report = instantiate_sac_all_active()
        out = OUTPUT_DIR / f"sac_all_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Saved -> {out}")
    else:
        service_id = sys.argv[1] if len(sys.argv) > 1 else "auth-service"
        sac = instantiate_sac(service_id)
        out = OUTPUT_DIR / f"sac_{service_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(sac, indent=2), encoding="utf-8")
        print(f"Saved -> {out}")
