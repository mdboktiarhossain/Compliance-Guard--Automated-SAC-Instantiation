"""
extract_schema.py — Step 1: NIST SP 800-53 Policy Extraction
============================================================
Calls OpenAI GPT-4o-mini with constrained decoding (Pydantic structured output)
to extract unstructured regulatory text into atomic compliance rules (Object 1).
"""

import json
import os
import shutil
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv(Path(__file__).parent / ".env")

API_KEY = os.getenv("OPENAI_API_KEY", "")
if not API_KEY:
    raise ValueError("OPENAI_API_KEY is not set in .env or environment!")

client = OpenAI(api_key=API_KEY)

# ── Pydantic Schema Definitions (Strict Output Enforcement) ─────────────────
class Scope(BaseModel):
    actor: List[str] = Field(description="Actor(s) who must implement or follow this control")
    action: List[str] = Field(default_factory=list, description="Verbs the actor must perform")
    data_domain: List[str] = Field(default_factory=list, description="Resource/data domain involved")
    context: List[str] = Field(default_factory=list, description="Context in which this rule applies")

class ODPAssignment(BaseModel):
    placeholder: str = Field(description="Original bracketed [Assignment: ...] text")
    suggested_value: str = Field(default="", description="Suggested value for K8s/microservice environment")

class ProvisionSet(BaseModel):
    provides_to: List[str] = Field(default_factory=list, description="Control IDs this control provides to")
    requires_from: List[str] = Field(default_factory=list, description="Control IDs this control requires from")
    provided_values: List[str] = Field(default_factory=list, description="Parameters flowing between controls")

class Testability(BaseModel):
    evidence_signals: List[str] = Field(default_factory=list, description="Evidence check signals (e.g. access_check, log_check)")
    reason: str = Field(default="", description="Explanation of testability status")

class ComplianceRule(BaseModel):
    rule_id: str = Field(description="Unique ID e.g., 'NIST-AC-3-a', 'NIST-AC-3-7'")
    source_citation: str = Field(description="Exact reference e.g., 'AC-3', 'AC-3(7)'")
    control_family: str = Field(description="Family code e.g., 'AC'")
    control_title: str = Field(description="Title e.g., 'ACCESS ENFORCEMENT'")
    
    implemented_by: str = Field(description="'system' | 'organization' | 'both'")
    odp_assignments: List[ODPAssignment] = Field(default_factory=list)
    related_controls: List[str] = Field(default_factory=list)
    provision_set: ProvisionSet = Field(default_factory=ProvisionSet)
    baseline_allocation: str = Field(default="Moderate")
    impact_factor: float = Field(default=0.5, description="Weight from 0.1 to 1.0")
    
    scope: Scope = Field(description="Scope of actor, action, data_domain, and context")
    hazard: str = Field(description="Harm if control is violated")
    requirement: str = Field(description="Core obligation statement")
    conditions: List[str] = Field(default_factory=list)
    exceptions: List[str] = Field(default_factory=list)
    severity: str = Field(default="high", description="'high' | 'medium' | 'low'")
    is_testable: bool = Field(default=True)
    testability: Testability = Field(default_factory=Testability)
    authorized_personnel: List[str] = Field(default_factory=list)

class ComplianceSchema(BaseModel):
    policy_name: str = Field(description="Name of source policy")
    policy_version: str = Field(default="Rev. 5")
    framework: str = Field(default="NIST SP 800-53")
    total_rules: int = Field(description="Total count of extracted rules")
    rules: List[ComplianceRule] = Field(description="Extracted rule instances")


SYSTEM_PROMPT = """\
You are a compliance policy analyst specializing in NIST SP 800-53 security controls.
Your task is to read a NIST SP 800-53 policy document and extract EVERY atomic compliance rule into a structured JSON schema.

You must align your extraction with the Security Assurance Case (SAC) framework for runtime security compliance for self-adaptive systems.

For EACH atomic rule, extract:

=== IDENTIFICATION ===
1. rule_id: Unique ID like "NIST-AC-1-a", "NIST-AC-2-a", "NIST-AC-3-a", "NIST-AC-3-7", "NIST-AC-6-5"
2. source_citation: Exact control reference like "AC-1(a)", "AC-2(a)", "AC-3", "AC-3(7)", "AC-6(5)"
3. control_family: The 2-letter family code (AC)
4. control_title: The control title in UPPERCASE

=== SAC FRAMEWORK FIELDS ===
5. implemented_by: "system" | "organization" | "both"
   - "system" = automated technical enforcement (e.g., access enforcement, logging)
   - "organization" = policy/procedure/human action (e.g., policy development, account review)
   - "both" = requires both technical and organizational implementation
6. odp_assignments: Extract EVERY [Assignment: ...] and [Selection: ...] from the control.
7. related_controls: List of other NIST control IDs mentioned or logically related
8. provision_set: What does this control PROVIDE to others, and what does it REQUIRE from others?
9. baseline_allocation: "Low" | "Moderate" | "High"
10. impact_factor: Float [0.0-1.0] — compliance confidence weight
    - 1.0 = critical technical control (e.g., AC-3 access enforcement, AC-6(5) privileged connections)
    - 0.8 = high impact
    - 0.5 = moderate impact (e.g., AC-1 policy review)
    - 0.3 = low impact

=== SCOPE FIELDS ===
11. scope.actor: WHO must implement this (organization, system, account_manager, etc.)
12. scope.action: WHAT must they do (enforce, log, restrict, authorize, monitor, etc.)
13. scope.data_domain: WHAT resource/data is affected
14. scope.context: WHAT operational context applies

=== CONTENT FIELDS ===
15. hazard: What goes wrong if this is violated
16. requirement: The core obligation in one clear sentence
17. conditions: When this applies
18. exceptions: When this does NOT apply
19. severity: "low" | "medium" | "high"
20. is_testable: Can a microservice proxy/sidecar automatically check this?
21. testability.evidence_signals: ["access_check", "log_check", "config_check", "io_check", "process_check"]
22. authorized_personnel: Roles explicitly authorized by this control

CRITICAL RULES:
- Extract EVERY sub-part (a, b, c, etc.) of each control as a SEPARATE rule
- Extract EVERY control enhancement (e.g., AC-3(7), AC-6(5)) as a SEPARATE rule
- For odp_assignments, extract ALL [Assignment: ...] brackets — never skip them
- impact_factor must be a valid float between 0.0 and 1.0
- baseline_allocation must be exactly "Low", "Moderate", or "High"
- implemented_by must be exactly "system", "organization", or "both"
"""

USER_PROMPT_TEMPLATE = """\
Extract all atomic compliance rules from the following NIST SP 800-53 Access Control policy text.
Apply the SAC framework fields carefully — especially implemented_by, odp_assignments, related_controls, provision_set, baseline_allocation, and impact_factor.

POLICY TEXT:
{text}
"""

def extract_nist_rules(
    source_file: Path = Path(__file__).parent / "nist_sp800_53_sample.txt",
    output_file: Path = Path(__file__).parent / "extracted_schema.json",
    backup_existing: bool = True
):
    print("=" * 65)
    print("  STEP 1: LLM-POWERED NIST RULE EXTRACTION (FROM SCRATCH)")
    print("=" * 65)
    print(f"  Model       : gpt-4o-mini (temperature=0.1)")
    print(f"  Input File  : {source_file.name}")
    print(f"  Output File : {output_file.name}")

    if not source_file.exists():
        raise FileNotFoundError(f"Source file not found: {source_file}")

    raw_text = source_file.read_text(encoding="utf-8")
    print(f"  Source size : {len(raw_text):,} characters ({len(raw_text.splitlines())} lines)")

    print("\n[1/3] Calling OpenAI API with structured decoding (ComplianceSchema)...")
    prompt = USER_PROMPT_TEMPLATE.format(text=raw_text)

    response = client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        response_format=ComplianceSchema,
        temperature=0.1,
    )

    parsed_data = response.choices[0].message.parsed
    data_dict = parsed_data.model_dump()
    data_dict["total_rules"] = len(data_dict["rules"])

    print(f"[2/3] Extraction completed: {len(data_dict['rules'])} atomic rules extracted!")

    # Backup if requested
    if backup_existing and output_file.exists():
        backup_path = output_file.with_suffix(".json.bak")
        shutil.copy2(output_file, backup_path)
        print(f"  [Backup] Preserved previous schema at: {backup_path.name}")

    # Save to disk
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data_dict, f, indent=2)
    print(f"[3/3] Successfully saved Object 1 to: {output_file.name}")

    print("\n" + "=" * 65)
    print(f"  SUMMARY: {data_dict['policy_name']}")
    print("=" * 65)
    print(f"  Declared Rules : {data_dict['total_rules']}")
    
    controls = set(r["source_citation"].split("(")[0].strip() for r in data_dict["rules"])
    print(f"  NIST Controls  : {sorted(list(controls))}")
    return output_file

if __name__ == "__main__":
    extract_nist_rules()
