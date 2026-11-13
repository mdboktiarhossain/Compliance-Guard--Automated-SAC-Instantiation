"""
sac/extract_context.py — Hybrid LLM + LPG Context Extractor
=============================================================
Implements the hybrid context extraction approach:

  Step 1 (LLM): Read the NIST control statement and identify
                WHAT type of context parameter is needed
                (e.g., "accessControlPolicy")

  Step 2 (LPG): Scan the service's properties in
                system_architecture_graph.json to find
                THE ACTUAL VALUE for that parameter
                (e.g., "role-based+attribute-based")

  Step 3:       Build the full tailoring string:
                'accessControlPolicy = "role-based+attribute-based"'

This replaces the manual paramList.txt input used in the original Java-based SAC tool, moving toward full automation.

Scope: AC-3 proof-of-concept. Designed to be extensible.
"""

import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

# ── Mapping: LLM-identified context parameter name → LPG service property key ─
# This table translates between NIST parameter vocabulary and LPG property names.
# Normalized keys: lowercase, no underscores or hyphens.
PARAM_TO_PROPERTY = {
    # Access control — all common LLM phrasings for AC-3 context
    "accesscontrolpolicy":       "access_control",
    "accesspolicy":              "access_control",
    "accesscontrol":             "access_control",
    "authorizationpolicy":       "access_control",   # LLM may say this for AC-3
    "authorizationmodel":        "access_control",
    "authorizationtype":         "access_control",
    "accessenforcement":         "access_control",
    "logicalaccesspolicy":       "access_control",
    "rbacpolicy":                "access_control",
    "accesscontrolmodel":        "access_control",
    # Encryption
    "encryptionalgorithm":       "encryption",
    "encryption":                "encryption",
    "cryptoalgorithm":           "encryption",
    "encryptionmethod":          "encryption",
    # Authentication / MFA
    "mfapolicy":                 "mfa_support",
    "mfarequired":               "mfa_support",
    "authenticationmethod":      "mfa_support",
    "multifactorauthentication": "mfa_support",
    # Privilege
    "privilegeseparation":       "privilege_separation",
    "leastprivilege":            "least_privilege",
    "leastprivilegepolicy":      "least_privilege",
    "privilegedlogging":         "privileged_function_logging",
    # Audit
    "auditpolicy":               "audit_logging",
    "auditlogging":              "audit_logging",
    "auditretention":            "audit_logging",
    "auditlogpolicy":            "audit_logging",
}

# ── Fallback context values per control ──────────────────────────────────────
# From reference paramList_AC-3.txt: "accessControlPolicy = identity-based policy"
FALLBACK_CONTEXTS = {
    "AC-3": {
        "param_name":  "accessControlPolicy",
        "param_value": "identity-based policy",
    },
    "AC-4": {
        "param_name":  "informationFlowPolicy",
        "param_value": "approved flow control policy",
    },
    "AC-6": {
        "param_name":  "leastPrivilege",
        "param_value": "minimum necessary privilege",
    },
}

# ── LLM prompt ────────────────────────────────────────────────────────────────
CONTEXT_PROMPT = """\
You are a NIST SP 800-53 security engineer specializing in Security Assurance Cases (SAC).

Given the following NIST SP 800-53 security control:

Control ID: {control_id}
Control Statement: "{control_statement}"

Your task: Identify the single most important organization-defined parameter \
that must be configured as CONTEXT for this control in a Security Assurance Case.

Rules:
- Return ONLY a single camelCase parameter name (e.g., "accessControlPolicy").
- This should be the type of access control POLICY the organization uses \
  (role-based, identity-based, attribute-based, mandatory, etc.).
- Do NOT return a sentence, encryption method, or authentication mechanism.
- Do NOT return a sentence. Return only the parameter name.

Exact examples (use these as reference):
- AC-3 (Access Enforcement) → accessControlPolicy
- AC-4 (Information Flow Enforcement) → informationFlowPolicy
- AC-6 (Least Privilege) → leastPrivilegePolicy
- AC-17 (Remote Access) → remoteAccessPolicy

Now identify the context parameter name for {control_id}:"""


def extract(control_id: str, control_statement: str,
            service_id: str, graph: dict) -> dict:
    """
    Hybrid LLM + LPG context extraction.

    Args:
        control_id:        e.g. "AC-3"
        control_statement: NIST control text
        service_id:        e.g. "auth-service-v2"
        graph:             loaded system_architecture_graph dict

    Returns:
        {
          "identifier":  "AC-3 [1]",
          "param_name":  "accessControlPolicy",
          "param_value": "role-based+attribute-based",
          "tailoring":   'accessControlPolicy = "role-based+attribute-based"',
          "statement":   "Context: AC-3 [1]: Assignment: accessControlPolicy = ...",
          "param_source": "llm" | "fallback",
          "value_source": "lpg" | "fallback"
        }
    """
    # Step 1: LLM identifies the context parameter name
    param_name, param_source = _extract_param_name(control_id, control_statement)

    # Step 2: LPG scanner finds the actual value from service properties
    param_value, value_source = _find_value_in_lpg(param_name, service_id, graph)

    # Step 3: Build the tailoring string
    ctx_id   = f"{control_id} [1]"
    tailoring = f'{param_name} = "{param_value}"'
    statement = f"Context: {ctx_id}: Assignment: {tailoring}"

    print(f"[extract_context] {control_id} Context: {tailoring} "
          f"(param={param_source}, value={value_source})")

    return {
        "identifier":   ctx_id,
        "param_name":   param_name,
        "param_value":  param_value,
        "tailoring":    tailoring,
        "statement":    statement,
        "param_source": param_source,
        "value_source": value_source,
    }


def _extract_param_name(control_id: str, control_statement: str) -> tuple:
    """Use LLM to identify the context parameter name from the control text."""
    api_key = os.getenv("OPENAI_API_KEY", "")

    if not api_key:
        return _fallback_param(control_id)

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)

        prompt = CONTEXT_PROMPT.format(
            control_id=control_id,
            control_statement=control_statement.strip(),
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a NIST SP 800-53 expert. You identify organization-defined "
                        "parameter names for Security Assurance Case context nodes. "
                        "Always respond with only the camelCase parameter name."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=20,
        )

        raw = response.choices[0].message.content.strip().strip('"\'').strip()

        # Validate: must look like a camelCase identifier
        if not raw or len(raw) < 3 or " " in raw:
            return _fallback_param(control_id)

        # Normalize first char to lowercase
        param_name = raw[0].lower() + raw[1:] if raw else raw

        print(f"[extract_context] LLM identified context param for {control_id}: '{param_name}'")
        return param_name, "llm"

    except Exception as e:
        print(f"[extract_context] LLM param extraction failed: {e}. Using fallback.")
        return _fallback_param(control_id)


def _fallback_param(control_id: str) -> tuple:
    parent = control_id.split("(")[0].strip()
    fb = FALLBACK_CONTEXTS.get(parent, {})
    return fb.get("param_name", "accessControlPolicy"), "fallback"


def _find_value_in_lpg(param_name: str, service_id: str, graph: dict) -> tuple:
    """
    Scan the LPG graph to find the actual value for the given parameter
    in the specified service's properties.
    """
    # Find the service node
    service_node = None
    for node in graph.get("nodes", []):
        if node.get("id") == service_id:
            service_node = node
            break

    if not service_node:
        return "organization-defined", "fallback"

    props = service_node.get("properties", {})

    # Normalize param name for lookup
    param_key = param_name.lower().replace("_", "").replace("-", "")
    prop_key   = PARAM_TO_PROPERTY.get(param_key)

    if prop_key and prop_key in props:
        val = props[prop_key]
        if isinstance(val, bool):
            val = "enabled" if val else "disabled"
        return str(val), "lpg"

    # Fuzzy fallback: try partial match on known property keys
    for normalized_param, lpg_key in PARAM_TO_PROPERTY.items():
        if normalized_param in param_key or param_key in normalized_param:
            if lpg_key in props:
                val = props[lpg_key]
                if isinstance(val, bool):
                    val = "enabled" if val else "disabled"
                return str(val), "lpg"

    # Safe fallback: if param sounds like access control, return access_control property
    access_keywords = {"access", "control", "authorization", "policy", "rbac", "abac", "mac"}
    param_words = set(param_key)  # character set is too coarse — use word splitting
    param_words = set(
        w for w in __import__('re').split(r'(?=[A-Z])|_|-', param_name) if w
    )
    param_words_lower = {w.lower() for w in param_words}
    if access_keywords & param_words_lower:
        if "access_control" in props:
            val = props["access_control"]
            return str(val), "lpg"

    # Final fallback: return organization-defined (do NOT blindly pick any property)
    return "organization-defined", "fallback"


# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from graph_builder import load_graph

    schema_path = Path(__file__).parent.parent / "extracted_schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    ac3_statement = ""
    for rule in schema.get("rules", []):
        if rule.get("source_citation") == "AC-3":
            ac3_statement = rule.get("requirement", "")
            break
    if not ac3_statement:
        ac3_statement = (
            "The information system enforces approved authorizations for logical "
            "access to information and system resources in accordance with applicable "
            "access control policies."
        )

    graph = load_graph()

    print("\n=== Hybrid Context Extraction Test ===")
    print(f"Control   : AC-3")
    print(f"Service   : auth-service-v2")
    print()

    result = extract("AC-3", ac3_statement, "auth-service-v2", graph)
    print(f"\nResult:")
    for k, v in result.items():
        print(f"  {k:20s}: {v}")
