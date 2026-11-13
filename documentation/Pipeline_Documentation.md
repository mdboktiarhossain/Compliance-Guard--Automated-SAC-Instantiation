# Compliance Guard: Extraction Pipeline Documentation

This document provides a detailed description of the LLM-based compliance policy extraction pipeline for NIST SP 800-53.

---

## 1. Pipeline Architecture Overview

Our extraction pipeline follows a three-layer architecture:

```
Layer 1: Policy Ingestion     - Read raw NIST SP 800-53 text
Layer 2: LLM Schema Extraction - GPT-4o-mini extracts structured JSON rules
Layer 3: Schema Enforcement    - Deploy rules in Istio/Kubernetes service mesh
```

The pipeline converts unstructured compliance text into machine-readable JSON rules that can be automatically enforced by microservice proxies.

---

## 2. Layer 1: Policy Ingestion

### 2.1 Source Document

- **Document**: NIST Special Publication 800-53, Revision 5
- **Title**: Security and Privacy Controls for Information Systems and Organizations
- **Focus Area**: Access Control (AC) Family - Controls AC-1 through AC-24
- **Format**: Plain text (UTF-8 encoded)
- **Character Count**: ~9,633 characters

### 2.2 Preprocessing

The raw NIST text is loaded directly without chunking or splitting because:
1. NIST controls are self-contained
2. Full context allows the LLM to understand cross-references between controls
3. The total text fits within GPT-4o-mini's 128K token context window

```python
policy_file = Path(__file__).parent / "nist_sp800_53_sample.txt"
policy_text = policy_file.read_text(encoding="utf-8")
```

---

## 3. Layer 2: LLM Schema Extraction

### 3.1 Schema Definition (Pydantic Models)

We define a strict, typed schema using Python's Pydantic library. The LLM is forced to output JSON that exactly matches this schema. The schema is extended to align with the formal Security Assurance Case (SAC) framework.

#### ComplianceRule Schema Fields (v2 - Extended with SAC)

| Field | Type | Description |
|---|---|---|
| `rule_id` | string | Unique identifier based on control number (e.g., `NIST-AC-2-a`, `NIST-AC-3-7`) |
| `source_citation` | string | The exact control reference (e.g., `AC-2(a)`, `AC-3(7)`) |
| `control_family` | string | NIST control family code (e.g., `AC` for Access Control) |
| `control_title` | string | Full uppercase title of the control (e.g., `ACCOUNT MANAGEMENT`) |
| `implemented_by` | string | Who is responsible (`system`, `organization`, or `both`) |
| `odp_assignments` | list[object] | Extracted Organization-Defined Parameters with placeholders and suggested values |
| `related_controls` | list[string] | Interdependent NIST control IDs forming the Security Control Network (SCN) |
| `provision_set` | object | Models the provides/requires parameter flows between controls |
| `baseline_allocation` | string | FIPS baseline impact allocation (`Low`, `Moderate`, `High`) |
| `impact_factor` | float | Compliance confidence weight (0.0 to 1.0) mapping to the formal SAC achievement weight |
| `scope.actor` | list[string] | Specific actor(s) who must follow the control |
| `scope.action` | list[string] | Actions/verbs the actor must perform (enforce, log, monitor, etc.) |
| `scope.data_domain` | list[string] | Resources or data domains involved |
| `scope.context` | list[string] | Operational context under which this applies |
| `hazard` | string | Harm if control is not implemented |
| `requirement` | string | Core obligation in one clear sentence |
| `conditions` | list[string] | Operational conditions when this applies |
| `exceptions` | list[string] | Exceptional contexts where the rule does not apply |
| `severity` | string | Severity if violated (`low`, `medium`, `high`) |
| `is_testable` | boolean | Whether the rule can be automatically verified in a microservice proxy |
| `testability.evidence_signals` | list[string] | Signals to check (`io_check`, `log_check`, `access_check`, `config_check`, `process_check`) |
| `testability.reason` | string | Brief explanation of testability status |
| `authorized_personnel` | list[string] | Explicitly authorized roles |

#### Pydantic Implementation (extract_schema.py)

```python
class Scope(BaseModel):
    actor: list[str] = Field(description="Actor(s) who must implement/follow this control")
    action: list[str] = Field(default_factory=list, description="Verbs the actor must perform")
    data_domain: list[str] = Field(default_factory=list, description="Resource/data domain involved")
    context: list[str] = Field(default_factory=list, description="Context in which this rule applies")

class ODPAssignment(BaseModel):
    placeholder: str = Field(description="Original bracketed [Assignment: ...] text")
    suggested_value: str = Field(default="", description="Suggested value for K8s/microservice")

class ProvisionSet(BaseModel):
    provides_to: list[str] = Field(default_factory=list, description="Control IDs this control provides to")
    requires_from: list[str] = Field(default_factory=list, description="Control IDs this control requires from")
    provided_values: list[str] = Field(default_factory=list, description="Parameters flowing between controls")

class Testability(BaseModel):
    evidence_signals: list[str] = Field(default_factory=list, description="Evidence check signals")
    reason: str = Field(default="", description="Explanation of testability status")

class ComplianceRule(BaseModel):
    rule_id: str = Field(description="Unique ID e.g., 'NIST-AC-3-7'")
    source_citation: str = Field(description="Exact reference e.g., 'AC-3(7)'")
    control_family: str = Field(description="Family code e.g., 'AC'")
    control_title: str = Field(description="Title e.g., 'LEAST PRIVILEGE'")
    
    implemented_by: str = Field(description="'system' | 'organization' | 'both'")
    odp_assignments: list[ODPAssignment] = Field(default_factory=list)
    related_controls: list[str] = Field(default_factory=list)
    provision_set: ProvisionSet = Field(default_factory=ProvisionSet)
    baseline_allocation: str = Field(default="Moderate")
    impact_factor: float = Field(default=0.5)
    
    scope: Scope = Field(description="Who this applies to, actions, data, and context")
    hazard: str = Field(description="Harm if control is violated")
    requirement: str = Field(description="Core obligation statement")
    conditions: list[str] = Field(default_factory=list)
    exceptions: list[str] = Field(default_factory=list)
    severity: str = Field(default="high")
    is_testable: bool = Field(default=True)
    testability: Testability = Field(default_factory=Testability)
    authorized_personnel: list[str] = Field(default_factory=list)

class ComplianceSchema(BaseModel):
    policy_name: str = Field(description="Name of source policy")
    policy_version: str = Field(default="Rev. 5")
    framework: str = Field(default="NIST SP 800-53")
    total_rules: int = Field(description="Total count of extracted rules")
    rules: list[ComplianceRule] = Field(description="Extracted rule instances")
```

### 3.2 Prompt Engineering

#### System Prompt

```
You are a compliance policy analyst specializing in NIST SP 800-53 security controls.
Your task is to read a NIST SP 800-53 policy document and extract EVERY atomic compliance rule into a structured JSON schema.

You must align your extraction with the Security Assurance Case (SAC) framework from formal research on runtime security compliance for self-adaptive systems.

For EACH atomic rule, extract:

=== IDENTIFICATION ===
1. rule_id: Unique ID like "NIST-AC-2-a", "NIST-AC-3-7", "NIST-AC-6-9"
2. source_citation: Exact control reference like "AC-2(a)", "AC-3(7)", "AC-6(9)"
3. control_family: The 2-letter family code (AC, AU, SI, etc.)
4. control_title: The control title in UPPERCASE

=== SAC FRAMEWORK FIELDS (Formal SAC model) ===
5. implemented_by: "system" | "organization" | "both"
   - "system" = automated technical enforcement (e.g., access enforcement, logging)
   - "organization" = policy/procedure/human action (e.g., policy development, account review)
   - "both" = requires both technical and organizational implementation
6. odp_assignments: Extract EVERY [Assignment: ...] and [Selection: ...] from the control.
   For each, provide the placeholder text AND a suggested_value for a microservice/Kubernetes environment.
7. related_controls: List of other NIST control IDs mentioned or logically related
8. provision_set: What does this control PROVIDE to others, and what does it REQUIRE from others?
   Think of this as the parameter flow between controls.
9. baseline_allocation: "Low" | "Moderate" | "High"
   - Access enforcement (AC-3, AC-6) = High
   - Account management (AC-2) = Moderate-High
   - Policy/procedures (AC-1) = Low-Moderate
10. impact_factor: Float [0.0-1.0] — compliance confidence weight
    - 1.0 = critical control, total violation if not met
    - 0.8 = high impact
    - 0.5 = moderate impact
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
- Extract EVERY control enhancement (e.g., AC-3(7), AC-6(9)) as a SEPARATE rule
- For odp_assignments, extract ALL [Assignment: ...] brackets — never skip them
- impact_factor must be a valid float between 0.0 and 1.0
- baseline_allocation must be exactly "Low", "Moderate", or "High"
- implemented_by must be exactly "system", "organization", or "both"
```

#### User Prompt

```
Extract all compliance rules from the following NIST SP 800-53 policy text. Apply the SAC framework fields carefully — especially implemented_by, odp_assignments, related_controls, provision_set, baseline_allocation, and impact_factor.

[Full policy text appended here]
```

### 3.3 Constrained Decoding (Structured Output)

We use OpenAI's Structured Output API to force valid JSON output:

```python
response = client.beta.chat.completions.parse(
    model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Extract all compliance rules...\n\n{policy_text}"}
    ],
    response_format=ComplianceSchema,  # Enforces strict JSON schema matching Pydantic
    temperature=0.1,  # Low temperature for near-deterministic extraction
)
schema = response.choices[0].message.parsed
```

#### Key LLM Run Parameters

| Parameter | Value | Rationale |
|---|---|---|
| `model` | gpt-4o-mini | Cost-effective, outstanding instruction-following and schema parsing |
| `response_format` | ComplianceSchema (Pydantic) | Enforces 100% compliance with strict JSON schema definitions |
| `temperature` | 0.1 | Near-deterministic, ensuring consistent and reproducible research extractions |

---

## 4. Extraction Results

### 4.1 Summary Statistics

| Metric | Value |
|---|---|
| Source Document | NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations |
| Controls Processed | AC-1 through AC-24 (including enhancements) |
| Total Rules Extracted | 42 |
| Rules Marked Testable | 42 (100%) |
| Model Used | GPT-4o-mini |
| Temperature | 0.1 |
| Estimated Cost | < $0.01 |

### 4.2 Rules by NIST Control

| Control | Description | Rules Extracted | Primary Evidence |
|---|---|---|---|
| AC-1 | Policy and Procedures | 5 | config_check |
| AC-2 | Account Management | 18 | access_check, config_check, log_check |
| AC-3 | Access Enforcement | 3 | access_check |
| AC-4 | Information Flow Enforcement | 3 | access_check |
| AC-5 | Separation of Duties | 2 | config_check |
| AC-6 | Least Privilege | 6 | access_check, log_check |
| AC-17 | Remote Access | 4 | access_check, config_check, log_check |
| AC-24 | Access Control Decisions | 1 | config_check |

### 4.3 Severity Distribution

| Severity | Count | Percentage |
|---|---|---|
| High | 37 | 88% |
| Medium | 5 | 11% |
| Low | 0 | 0% |

### 4.4 Evidence Signal Distribution

| Evidence Signal | Count | Description |
|---|---|---|
| `config_check` | 18 | Verify system/policy configuration |
| `access_check` | 15 | Validate access control enforcement |
| `log_check` | 9 | Check audit/event logs |
| `io_check` | 0 | Input/output inspection |

### 4.5 Complete Extracted Rules

#### Rule 1: NIST-AC-1-a-1

```json
{
  "rule_id": "NIST-AC-1-a-1",
  "source_citation": "AC-1(a)(1)",
  "scope": {
    "actor": [
      "organization-defined personnel or roles"
    ],
    "data_domain": [
      "access control policy"
    ],
    "context": [
      "policy development",
      "policy dissemination"
    ]
  },
  "hazard": "Inconsistent access control leading to unauthorized access.",
  "requirement": "Develop, document, and disseminate an access control policy.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "The existence of documented policies can be verified."
  },
  "authorized_personnel": []
}
```

#### Rule 2: NIST-AC-1-a-2

```json
{
  "rule_id": "NIST-AC-1-a-2",
  "source_citation": "AC-1(a)(2)",
  "scope": {
    "actor": [
      "organization-defined personnel or roles"
    ],
    "data_domain": [
      "access control procedures"
    ],
    "context": [
      "policy implementation"
    ]
  },
  "hazard": "Failure to implement access controls could lead to security breaches.",
  "requirement": "Create procedures to facilitate the implementation of the access control policy.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Procedures can be documented and verified."
  },
  "authorized_personnel": []
}
```

#### Rule 3: NIST-AC-1-b

```json
{
  "rule_id": "NIST-AC-1-b",
  "source_citation": "AC-1(b)",
  "scope": {
    "actor": [
      "organization-defined official"
    ],
    "data_domain": [
      "access control policy"
    ],
    "context": [
      "policy management"
    ]
  },
  "hazard": "Lack of oversight may lead to outdated or ineffective policies.",
  "requirement": "Designate an official to manage the access control policy and procedures.",
  "conditions": [],
  "exceptions": [],
  "severity": "medium",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "The designation of an official can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 4: NIST-AC-1-c-1

```json
{
  "rule_id": "NIST-AC-1-c-1",
  "source_citation": "AC-1(c)(1)",
  "scope": {
    "actor": [
      "organization-defined personnel or roles"
    ],
    "data_domain": [
      "access control policy"
    ],
    "context": [
      "policy review"
    ]
  },
  "hazard": "Outdated policies may not address current threats.",
  "requirement": "Review and update the access control policy at defined frequency.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Review logs can indicate policy updates."
  },
  "authorized_personnel": []
}
```

#### Rule 5: NIST-AC-1-c-2

```json
{
  "rule_id": "NIST-AC-1-c-2",
  "source_citation": "AC-1(c)(2)",
  "scope": {
    "actor": [
      "organization-defined personnel or roles"
    ],
    "data_domain": [
      "access control procedures"
    ],
    "context": [
      "procedure review"
    ]
  },
  "hazard": "Procedures may become ineffective if not updated.",
  "requirement": "Review and update access control procedures at defined frequency.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Review logs can indicate procedure updates."
  },
  "authorized_personnel": []
}
```

#### Rule 6: NIST-AC-2-a

```json
{
  "rule_id": "NIST-AC-2-a",
  "source_citation": "AC-2(a)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Unauthorized accounts may lead to security breaches.",
  "requirement": "Define and document the types of accounts allowed and prohibited.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Account types can be documented and verified."
  },
  "authorized_personnel": []
}
```

#### Rule 7: NIST-AC-2-b

```json
{
  "rule_id": "NIST-AC-2-b",
  "source_citation": "AC-2(b)",
  "scope": {
    "actor": [
      "organization-defined personnel or roles"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Lack of account oversight may lead to unauthorized access.",
  "requirement": "Assign account managers.",
  "conditions": [],
  "exceptions": [],
  "severity": "medium",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Account managers can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 8: NIST-AC-2-c

```json
{
  "rule_id": "NIST-AC-2-c",
  "source_citation": "AC-2(c)",
  "scope": {
    "actor": [
      "organization-defined personnel or roles"
    ],
    "data_domain": [
      "group and role membership"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Improper group membership may lead to unauthorized access.",
  "requirement": "Require prerequisites and criteria for group and role membership.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Membership criteria can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 9: NIST-AC-2-d-1

```json
{
  "rule_id": "NIST-AC-2-d-1",
  "source_citation": "AC-2(d)(1)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Unauthorized users may gain access to sensitive information.",
  "requirement": "Specify authorized users of the system.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Authorized users can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 10: NIST-AC-2-d-2

```json
{
  "rule_id": "NIST-AC-2-d-2",
  "source_citation": "AC-2(d)(2)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Improper role assignments may lead to unauthorized access.",
  "requirement": "Specify group and role membership.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Group and role memberships can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 11: NIST-AC-2-d-3

```json
{
  "rule_id": "NIST-AC-2-d-3",
  "source_citation": "AC-2(d)(3)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Unauthorized access may occur if privileges are not properly assigned.",
  "requirement": "Specify access authorizations and attributes for each account.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Access authorizations can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 12: NIST-AC-2-e

```json
{
  "rule_id": "NIST-AC-2-e",
  "source_citation": "AC-2(e)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Unauthorized account creation may lead to security breaches.",
  "requirement": "Require approvals for requests to create accounts.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Approval logs can be checked."
  },
  "authorized_personnel": []
}
```

#### Rule 13: NIST-AC-2-f

```json
{
  "rule_id": "NIST-AC-2-f",
  "source_citation": "AC-2(f)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Failure to manage accounts may lead to unauthorized access.",
  "requirement": "Create, enable, modify, disable, and remove accounts as per defined policies.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Account management actions can be logged."
  },
  "authorized_personnel": []
}
```

#### Rule 14: NIST-AC-2-g

```json
{
  "rule_id": "NIST-AC-2-g",
  "source_citation": "AC-2(g)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Unauthorized access may occur if account usage is not monitored.",
  "requirement": "Monitor the use of accounts.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Account usage can be monitored through logs."
  },
  "authorized_personnel": []
}
```

#### Rule 15: NIST-AC-2-h-1

```json
{
  "rule_id": "NIST-AC-2-h-1",
  "source_citation": "AC-2(h)(1)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Failure to notify may lead to unauthorized access.",
  "requirement": "Notify account managers when accounts are no longer required.",
  "conditions": [],
  "exceptions": [],
  "severity": "medium",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Notification logs can be checked."
  },
  "authorized_personnel": []
}
```

#### Rule 16: NIST-AC-2-h-2

```json
{
  "rule_id": "NIST-AC-2-h-2",
  "source_citation": "AC-2(h)(2)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Failure to notify may lead to unauthorized access.",
  "requirement": "Notify account managers when users are terminated or transferred.",
  "conditions": [],
  "exceptions": [],
  "severity": "medium",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Notification logs can be checked."
  },
  "authorized_personnel": []
}
```

#### Rule 17: NIST-AC-2-h-3

```json
{
  "rule_id": "NIST-AC-2-h-3",
  "source_citation": "AC-2(h)(3)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Failure to notify may lead to unauthorized access.",
  "requirement": "Notify account managers when system usage or need-to-know changes.",
  "conditions": [],
  "exceptions": [],
  "severity": "medium",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Notification logs can be checked."
  },
  "authorized_personnel": []
}
```

#### Rule 18: NIST-AC-2-i-1

```json
{
  "rule_id": "NIST-AC-2-i-1",
  "source_citation": "AC-2(i)(1)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system access"
    ],
    "context": [
      "access authorization"
    ]
  },
  "hazard": "Unauthorized access may occur if access is not properly authorized.",
  "requirement": "Authorize access based on valid access authorization.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Access authorizations can be verified."
  },
  "authorized_personnel": []
}
```

#### Rule 19: NIST-AC-2-i-2

```json
{
  "rule_id": "NIST-AC-2-i-2",
  "source_citation": "AC-2(i)(2)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system access"
    ],
    "context": [
      "access authorization"
    ]
  },
  "hazard": "Unauthorized access may occur if access is not properly authorized.",
  "requirement": "Authorize access based on intended system usage.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Access authorizations can be verified."
  },
  "authorized_personnel": []
}
```

#### Rule 20: NIST-AC-2-i-3

```json
{
  "rule_id": "NIST-AC-2-i-3",
  "source_citation": "AC-2(i)(3)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system access"
    ],
    "context": [
      "access authorization"
    ]
  },
  "hazard": "Unauthorized access may occur if access is not properly authorized.",
  "requirement": "Authorize access based on defined attributes.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Access authorizations can be verified."
  },
  "authorized_personnel": []
}
```

#### Rule 21: NIST-AC-2-j

```json
{
  "rule_id": "NIST-AC-2-j",
  "source_citation": "AC-2(j)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Non-compliance may lead to unauthorized access.",
  "requirement": "Review accounts for compliance with account management requirements.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Account reviews can be logged."
  },
  "authorized_personnel": []
}
```

#### Rule 22: NIST-AC-2-k

```json
{
  "rule_id": "NIST-AC-2-k",
  "source_citation": "AC-2(k)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "shared accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Failure to change shared account authenticators may lead to unauthorized access.",
  "requirement": "Establish a process for changing shared account authenticators.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Processes can be documented and verified."
  },
  "authorized_personnel": []
}
```

#### Rule 23: NIST-AC-2-l

```json
{
  "rule_id": "NIST-AC-2-l",
  "source_citation": "AC-2(l)",
  "scope": {
    "actor": [
      "account managers"
    ],
    "data_domain": [
      "system accounts"
    ],
    "context": [
      "account management"
    ]
  },
  "hazard": "Failure to align processes may lead to unauthorized access.",
  "requirement": "Align account management processes with personnel termination and transfer processes.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Alignment can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 24: NIST-AC-3

```json
{
  "rule_id": "NIST-AC-3",
  "source_citation": "AC-3",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "information and system resources"
    ],
    "context": [
      "access enforcement"
    ]
  },
  "hazard": "Unauthorized access may occur if access is not enforced.",
  "requirement": "Enforce approved authorizations for logical access.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Access enforcement can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 25: NIST-AC-3-7

```json
{
  "rule_id": "NIST-AC-3-7",
  "source_citation": "AC-3(7)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "information and system resources"
    ],
    "context": [
      "access enforcement"
    ]
  },
  "hazard": "Unauthorized access may occur if role-based access is not enforced.",
  "requirement": "Enforce a role-based access control policy.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Role-based access can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 26: NIST-AC-3-8

```json
{
  "rule_id": "NIST-AC-3-8",
  "source_citation": "AC-3(8)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "information and system resources"
    ],
    "context": [
      "access enforcement"
    ]
  },
  "hazard": "Unauthorized access may occur if revocation of access is not enforced.",
  "requirement": "Enforce the revocation of access authorizations.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Revocation processes can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 27: NIST-AC-4

```json
{
  "rule_id": "NIST-AC-4",
  "source_citation": "AC-4",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "information flow"
    ],
    "context": [
      "information flow enforcement"
    ]
  },
  "hazard": "Unauthorized information flow may lead to data breaches.",
  "requirement": "Enforce approved authorizations for controlling information flow.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Information flow can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 28: NIST-AC-4-1

```json
{
  "rule_id": "NIST-AC-4-1",
  "source_citation": "AC-4(1)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "information flow"
    ],
    "context": [
      "information flow enforcement"
    ]
  },
  "hazard": "Unauthorized information flow may lead to data breaches.",
  "requirement": "Use security and privacy attributes to enforce information flow control policies.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Attributes can be documented and verified."
  },
  "authorized_personnel": []
}
```

#### Rule 29: NIST-AC-4-4

```json
{
  "rule_id": "NIST-AC-4-4",
  "source_citation": "AC-4(4)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "encrypted information"
    ],
    "context": [
      "information flow enforcement"
    ]
  },
  "hazard": "Bypassing flow control may lead to data breaches.",
  "requirement": "Prevent encrypted information from bypassing flow control mechanisms.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Flow control mechanisms can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 30: NIST-AC-5-a

```json
{
  "rule_id": "NIST-AC-5-a",
  "source_citation": "AC-5(a)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "system access"
    ],
    "context": [
      "separation of duties"
    ]
  },
  "hazard": "Concentration of power may lead to abuse of privileges.",
  "requirement": "Identify and document duties requiring separation.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Duties can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 31: NIST-AC-5-b

```json
{
  "rule_id": "NIST-AC-5-b",
  "source_citation": "AC-5(b)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "system access"
    ],
    "context": [
      "separation of duties"
    ]
  },
  "hazard": "Failure to separate duties may lead to unauthorized actions.",
  "requirement": "Define system access authorizations to support separation of duties.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Access authorizations can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 32: NIST-AC-6

```json
{
  "rule_id": "NIST-AC-6",
  "source_citation": "AC-6",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "system access"
    ],
    "context": [
      "least privilege"
    ]
  },
  "hazard": "Excessive privileges may lead to unauthorized access.",
  "requirement": "Employ the principle of least privilege.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Access privileges can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 33: NIST-AC-6-1

```json
{
  "rule_id": "NIST-AC-6-1",
  "source_citation": "AC-6(1)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "security functions"
    ],
    "context": [
      "least privilege"
    ]
  },
  "hazard": "Unauthorized access to security functions may lead to security breaches.",
  "requirement": "Authorize access to security functions only for authorized personnel.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Access to security functions can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 34: NIST-AC-6-2

```json
{
  "rule_id": "NIST-AC-6-2",
  "source_citation": "AC-6(2)",
  "scope": {
    "actor": [
      "system users"
    ],
    "data_domain": [
      "security functions"
    ],
    "context": [
      "least privilege"
    ]
  },
  "hazard": "Unauthorized access to security functions may lead to security breaches.",
  "requirement": "Require non-privileged accounts for nonsecurity functions.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Account types can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 35: NIST-AC-6-5

```json
{
  "rule_id": "NIST-AC-6-5",
  "source_citation": "AC-6(5)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "privileged accounts"
    ],
    "context": [
      "least privilege"
    ]
  },
  "hazard": "Unauthorized access may occur if privileged accounts are not restricted.",
  "requirement": "Restrict privileged accounts to authorized personnel.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Privileged accounts can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 36: NIST-AC-6-9

```json
{
  "rule_id": "NIST-AC-6-9",
  "source_citation": "AC-6(9)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "privileged functions"
    ],
    "context": [
      "least privilege"
    ]
  },
  "hazard": "Lack of logging may lead to undetected misuse of privileges.",
  "requirement": "Log the execution of privileged functions.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Logs of privileged function executions can be checked."
  },
  "authorized_personnel": []
}
```

#### Rule 37: NIST-AC-6-10

```json
{
  "rule_id": "NIST-AC-6-10",
  "source_citation": "AC-6(10)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "privileged functions"
    ],
    "context": [
      "least privilege"
    ]
  },
  "hazard": "Unauthorized execution of privileged functions may lead to security breaches.",
  "requirement": "Prevent non-privileged users from executing privileged functions.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Access to privileged functions can be monitored."
  },
  "authorized_personnel": []
}
```

#### Rule 38: NIST-AC-17-a

```json
{
  "rule_id": "NIST-AC-17-a",
  "source_citation": "AC-17(a)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "remote access"
    ],
    "context": [
      "remote access management"
    ]
  },
  "hazard": "Uncontrolled remote access may lead to unauthorized access.",
  "requirement": "Establish usage restrictions and requirements for remote access.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Remote access policies can be documented."
  },
  "authorized_personnel": []
}
```

#### Rule 39: NIST-AC-17-b

```json
{
  "rule_id": "NIST-AC-17-b",
  "source_citation": "AC-17(b)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "remote access"
    ],
    "context": [
      "remote access management"
    ]
  },
  "hazard": "Unauthorized remote access may lead to security breaches.",
  "requirement": "Authorize each type of remote access prior to allowing connections.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "access_check"
    ],
    "reason": "Remote access authorizations can be verified."
  },
  "authorized_personnel": []
}
```

#### Rule 40: NIST-AC-17-1

```json
{
  "rule_id": "NIST-AC-17-1",
  "source_citation": "AC-17(1)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "remote access"
    ],
    "context": [
      "remote access monitoring"
    ]
  },
  "hazard": "Unmonitored remote access may lead to unauthorized access.",
  "requirement": "Employ automated mechanisms to monitor remote access methods.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "log_check"
    ],
    "reason": "Monitoring logs can be checked."
  },
  "authorized_personnel": []
}
```

#### Rule 41: NIST-AC-17-2

```json
{
  "rule_id": "NIST-AC-17-2",
  "source_citation": "AC-17(2)",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "remote access"
    ],
    "context": [
      "remote access security"
    ]
  },
  "hazard": "Unencrypted remote access may lead to data breaches.",
  "requirement": "Implement cryptographic mechanisms to protect remote access sessions.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Encryption mechanisms can be verified."
  },
  "authorized_personnel": []
}
```

#### Rule 42: NIST-AC-24

```json
{
  "rule_id": "NIST-AC-24",
  "source_citation": "AC-24",
  "scope": {
    "actor": [
      "system administrators"
    ],
    "data_domain": [
      "access requests"
    ],
    "context": [
      "access control decisions"
    ]
  },
  "hazard": "Unauthorized access may occur if access control decisions are not applied.",
  "requirement": "Establish procedures to ensure access control decisions are applied.",
  "conditions": [],
  "exceptions": [],
  "severity": "high",
  "is_testable": true,
  "testability": {
    "evidence_signals": [
      "config_check"
    ],
    "reason": "Procedures can be documented and verified."
  },
  "authorized_personnel": []
}
```

---

## 5. Phase 2: Runtime Autonomic Compliance Enforcement (MAPE-K & SAC)

In Phase 2, we have realized the theoretical framework described in the formal Security Assurance Case (SAC) research framework by building a fully functional **MAPE-K self-adaptive architecture** combined with a runtime **Security Assurance Case (SAC) decision engine**.

The system dynamically monitors compliance metrics and self-heals by substituting failed components with compliant alternative services, automatically instantiating and scoring the security posture.

### 5.1 Architectural Components

The Phase 2 system is structured across four primary directories:

```
compliance_guard/
├── mapek/               - Autonomic loop execution (Monitor, Analyze, Plan, Execute, Knowledge)
├── sac/                 - Security Assurance Case engine (LLM Instantiation + Completeness Scorer)
├── microservices/       - 13 Python/Flask microservice stubs (simulating active & alternative nodes)
└── server.py & UI       - Main background coordinator and a 5-panel interactive dashboard
```

### 5.2 The Autonomic MAPE-K Loop Flow

1. **Monitor (M)**: Every 15 seconds, the loop polls the `/health` and `/metrics` endpoints of all active microservices. Metrics include request count, error rates, average latency, and endpoint availability.
2. **Analyze (A)**: Determines if any service is down or degraded. A service is classified as down if it is unreachable or returns a sustained error rate exceeding 10%.
3. **Plan (P)**: If a service is down or degraded, the Plan phase uses LLM-based SAC instantiation to evaluate all alternative services registered in `system_architecture.json`. It computes the weighted satisficing completeness score for each candidate.
4. **Execute (E)**: The candidate service with the highest completeness score is selected. The Executor deactivates the failed service, activates the selected alternative, and updates the routing paths in `knowledge_base.json`.
5. **Knowledge (K)**: The persistent knowledge base (`knowledge_base.json`) records the running system configuration, metric history, active SAC schemas, and historical adaptation events.

### 5.3 SAC Instantiation & Completeness Evaluation

*   **LLM Mapping (`sac/instantiate_sac.py`)**: Harnesses GPT-4o-mini structured outputs to inspect a microservice's capabilities (e.g., token verification, RBAC, MFA, session encryption) and map them against the 38 rules in the extracted NIST SP 800-53 schema.
*   **Completeness Scorer (`sac/score_completeness.py`)**: Evaluates the overall compliance status. The completeness metric is computed as:
    $$\text{Completeness} = \frac{\sum (W_i \times C_i)}{\sum W_i}$$
    where $W_i$ is the `impact_factor` of the NIST control, and $C_i$ is the confidence coefficient assigned to the mapping (1.0 for satisfied, 0.5 for partial, 0.0 for missing).

### 5.4 Visualizing Compliance Evolution

We provide a **5-panel interactive web dashboard** served from `server.py` at `http://localhost:5000`:
- **System Topology Graph**: Live visualization showing active services (green), failed services (red), and backup alternatives (yellow).
- **MAPE-K Loop Monitor**: Real-time status display showing loop iteration, latency, and current autonomic execution state.
- **SAC Tree View**: Expandable tree detailing goals, controls, satisfying service functions, and active evidence signals.
- **Confidence Gauge**: Tracks security case completeness in real-time, instantly degrading if a service is marked down.
- **Adaptation History**: Tracks previous failures, showing what failed, which alternative was selected, and how the SAC score changed post-adaptation.
