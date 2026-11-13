"""
sac/extract_req_goals.py — LLM-Based Functional Requirement Extractor
=======================================================================
Uses the OpenAI API (configured with existing OPENAI_API_KEY in .env)
to automatically extract the functional_requirement for a NIST control's
ReqGoal node using prompt engineering.

This is the main research novelty of the SAC instantiation system:
instead of hardcoding functional requirements, the LLM reads the NIST
control statement and derives what the system must DO to comply.

Scope: AC-3 proof-of-concept.
       The module is designed to be extensible to other controls.

Based on architecture review feedback:
  "The main novelty is: if we can pick this requirement, then we match
   it with system architecture."
  "The requirement goal of LLM is that you have to do prompt engineering
   so that it can say which requirement to achieve in our specific
   security control."
"""

import os
import sys
from pathlib import Path

# Load .env from project root
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass  # dotenv optional — env vars may be set externally

# ── Fallback values (hardcoded from reference AC-3.xml example) ────────────
# Used if LLM call fails or returns empty
FALLBACK_REQ_GOALS = {
    "AC-3": {
        "functional_requirement": "check connection request and enforce authorization approval",
    },
    "AC-4": {
        "functional_requirement": "check information flow against approved policy",
    },
    "AC-5": {
        "functional_requirement": "identify and document separation of duties requirements",
    },
    "AC-6": {
        "functional_requirement": "restrict privileged accounts to security functions",
    },
}

# ── LLM prompt template ───────────────────────────────────────────────────────
EXTRACTION_PROMPT = """\
You are a security requirements engineer specializing in NIST SP 800-53 controls.

Given the following NIST SP 800-53 security control:

Control ID: {control_id}
Control Statement: "{control_statement}"

Your task: Extract the single most important functional requirement that an \
information system must satisfy to comply with this control.

Rules:
- Express it as a short imperative phrase (10-20 words) describing what the \
system must DO.
- Focus on the technical action, not the policy or organizational process.
- Do NOT include phrases like "The system should" or "It must" — start \
directly with the action verb.
- Return ONLY the requirement phrase, nothing else. No explanation, no \
punctuation at the end.

Example for AC-3 (Access Enforcement):
check connection request and enforce authorization approval

Now extract the functional requirement for {control_id}:"""


def extract(control_id: str, control_statement: str) -> dict:
    """
    Use LLM to extract the functional_requirement for a NIST control's ReqGoal.

    Args:
        control_id:         e.g. "AC-3"
        control_statement:  The NIST control text from extracted_schema.json

    Returns:
        {
          "functional_requirement": str,
          "source": "llm" | "fallback"
        }
    """
    api_key = os.getenv("OPENAI_API_KEY", "")

    if not api_key:
        print(f"[extract_req_goals] WARNING: OPENAI_API_KEY not set. Using fallback for {control_id}.")
        return _fallback(control_id)

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)

        prompt = EXTRACTION_PROMPT.format(
            control_id=control_id,
            control_statement=control_statement.strip(),
        )

        print(f"[extract_req_goals] Calling LLM to extract ReqGoal for {control_id}...")

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a NIST SP 800-53 security requirements engineer. "
                        "You extract concise functional requirements from NIST control statements. "
                        "Always respond with only the requirement phrase, nothing else."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.1,   # Low temperature for deterministic, precise output
            max_tokens=80,
        )

        raw = response.choices[0].message.content.strip()

        # Clean up: remove quotes, trailing punctuation if any
        raw = raw.strip('"\'').rstrip(".").strip()

        if not raw or len(raw) < 5:
            print(f"[extract_req_goals] LLM returned empty/too-short response. Using fallback.")
            return _fallback(control_id)

        print(f"[extract_req_goals] LLM extracted for {control_id}: '{raw}'")
        return {
            "functional_requirement": raw,
            "source": "llm",
        }

    except Exception as e:
        print(f"[extract_req_goals] LLM call failed for {control_id}: {e}. Using fallback.")
        return _fallback(control_id)


def _fallback(control_id: str) -> dict:
    """Return the hardcoded fallback functional requirement."""
    parent = control_id.split("(")[0].strip()  # e.g. "AC-3(7)" -> "AC-3"
    fb = FALLBACK_REQ_GOALS.get(parent, {})
    return {
        "functional_requirement": fb.get(
            "functional_requirement",
            f"satisfy {control_id} security control requirement"
        ),
        "source": "fallback",
    }


# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    # Load AC-3 statement from extracted_schema.json
    schema_path = Path(__file__).parent.parent / "extracted_schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    # Find the main AC-3 rule
    ac3_statement = None
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

    print(f"\n=== LLM ReqGoal Extraction Test ===")
    print(f"Control    : AC-3")
    print(f"Statement  : {ac3_statement[:100]}...")
    print()

    result = extract("AC-3", ac3_statement)
    print(f"\nResult:")
    print(f"  functional_requirement : {result['functional_requirement']}")
    print(f"  source                 : {result['source']}")
