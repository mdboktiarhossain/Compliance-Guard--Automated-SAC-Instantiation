# Prompt Engineering Guidelines for Security Assurance Case (SAC) Instantiation
*Compliance Guard Project — Contribution 3 Document*

---

## 1. Introduction

This guideline provides a formal, repeatable methodology for structuring and optimizing Large Language Model (LLM) prompts to support:
1. **Compliance Rule Extraction**: Extracting structured, atomic compliance rules from raw security standards (e.g., NIST SP 800-53).
2. **Automated SAC Instantiation**: Mapping extracted compliance rules to runtime system capabilities and properties to generate active Security Assurance Cases.

By following these structured guidelines, security engineers and researchers can ensure near-deterministic, high-confidence compliance reasoning and documentation.

---

## 2. Guidelines for Layer 2: Compliance Rule Extraction

The goal of rule extraction is to turn unstructured, complex prose in security standards into clear, atomic, machine-readable JSON rules.

### 2.1 The Prompt Structure Template

When prompting an LLM to extract compliance rules, structure the prompt into four distinct sections:

1. **Role and Domain Context**: Define the LLM as an expert security analyst familiar with the source standard.
2. **Reference to the Theoretical Framework**: Ground the extraction in the formal Security Assurance Case (SAC) framework.
3. **Atomic Rule Definitions**: Explicitly instruct the LLM to split nested clauses (e.g., control sub-parts AC-2(a), AC-2(b)) into separate, single-sentence requirements.
4. **Constrained Schema Definition**: Instruct the LLM to output details conforming to the target schema fields.

### 2.2 Reusable Prompt Template

```markdown
You are a compliance policy analyst specializing in [Standard name, e.g., NIST SP 800-53] security controls.
Your task is to read the attached policy text and extract EVERY atomic compliance rule.

Ground your analysis in the formal Security Assurance Case (SAC) framework:
- Focus on technical enforcement vs. organizational action (`implemented_by`).
- Specify the exact operational boundaries (`scope.actor`, `scope.action`, `scope.data_domain`, `scope.context`).
- Map baseline criticality to weights (`impact_factor` from 0.0 to 1.0).
- Identify testability and evidence requirements (`testability.evidence_signals`).

CRITICAL RULES:
- Extract EVERY sub-part (a, b, c, etc.) and control enhancement as a SEPARATE rule.
- Do not skip bracketed [Assignment: ...] parameters. Suggest realistic values for a microservice environment.
- Use low temperature (0.1) and constrained decoding (Pydantic schemas) to enforce a valid JSON structure.
```

---

## 3. Guidelines for Layer 3: Automated SAC Instantiation

The goal of SAC instantiation is to determine if a specific service's functions and properties satisfy the compliance rules extracted in Layer 2, outputting an active SAC instance.

### 3.1 The Input Profiles

To achieve accurate mapping, you must feed the LLM two precise JSON objects:
1. **The System Architecture Profile**: Detailing the candidate service's functions, properties, configurations, and target NIST controls.
2. **The Compliance Rule Set**: The JSON array of extracted compliance rules.

### 3.2 The Mapping Strategy (How the LLM reasons)

The LLM must map rule requirements against service profiles using the following decision matrix:

| Rule Requirement | Service Capabilities | Status | Confidence |
|---|---|---|---|
| Demands encryption (e.g., TLS) | Service has `encrypt_session` function with `TLSv1.3` enabled | `satisfied` | 1.0 |
| Demands audit logs of access | Service has a database logger but no token-level access check | `partial` | 0.5 |
| Demands dual-approval (Separation of Duties) | Service has only a single admin role with no approval flow | `missing` | 0.0 |

### 3.3 Reusable Instantiation Prompt

```markdown
You are a Security Assurance Case (SAC) instantiation engine.

Given:
1. A microservice's capabilities, properties, and operational parameters.
2. A set of NIST SP 800-53 compliance rules.

For EACH rule, assess if the microservice satisfies it. Your response must contain:
- `satisfaction_status`: "satisfied" | "partial" | "missing"
- `implementing_function`: The ID of the function performing the control (or empty if missing)
- `evidence_source`: The exact runtime signal (e.g., log entries, configuration parameters) proving compliance
- `confidence`: A float from 0.0 to 1.0 representing assurance strength

Be highly conservative and realistic. Only mark a rule as "satisfied" if the service's capabilities directly match the requirement.
```

---

## 4. Best Practices for Determinism and Quality

To guarantee high-quality research outputs:

1. **Use Constrained Decoding**: Always use Pydantic models with Structured Outputs (such as OpenAI's `.parse()` or Gemini's Schema enforcement) to avoid hallucinated fields or invalid JSON.
2. **Minimize Temperature**: Set `temperature = 0.1` or lower. Higher temperature leads to erratic mappings, which is unacceptable for compliance auditing.
3. **Explicitly Include Gaps**: Always require the LLM to output a `gap_description` when a rule is marked `partial` or `missing`. This forces the model to justify its reasoning and provides valuable debugging data for system administrators.
4. **Link to Evidence Signals**: Ensure that the `evidence_source` proposed by the LLM maps to active, queryable endpoints (e.g., `/metrics` or `/health` data) so the MAPE-K loop can dynamically monitor compliance health.
