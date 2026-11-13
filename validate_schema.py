"""Quick validation of extracted_schema.json"""
import json
from pathlib import Path

schema_path = Path(__file__).parent / "extracted_schema.json"
source_path = Path(__file__).parent / "nist_sp800_53_sample.txt"

with open(schema_path, "r", encoding="utf-8") as f:
    data = json.load(f)

print("=" * 60)
print("JSON VALIDATION REPORT")
print("=" * 60)
print(f"Valid JSON:         YES")
print(f"Policy Name:        {data['policy_name']}")
print(f"Policy Version:     {data['policy_version']}")
print(f"Declared rules:     {data['total_rules']}")
print(f"Actual rules:       {len(data['rules'])}")
match = data['total_rules'] == len(data['rules'])
print(f"Count matches:      {'YES' if match else 'NO - MISMATCH!'}")

# Check all required fields
required = ['rule_id', 'source_citation', 'scope', 'hazard', 'requirement',
            'conditions', 'exceptions', 'severity', 'is_testable',
            'testability', 'authorized_personnel']
missing = []
for i, rule in enumerate(data['rules']):
    for field in required:
        if field not in rule:
            missing.append(f"Rule {i+1} missing: {field}")

print(f"All 11 fields OK:   {'YES' if not missing else 'NO'}")
if missing:
    for m in missing:
        print(f"  {m}")

# Check sub-fields
scope_ok = all('actor' in r['scope'] and 'data_domain' in r['scope'] and 'context' in r['scope'] for r in data['rules'])
test_ok = all('evidence_signals' in r['testability'] and 'reason' in r['testability'] for r in data['rules'])
print(f"Scope sub-fields:   {'YES' if scope_ok else 'NO'}")
print(f"Test sub-fields:    {'YES' if test_ok else 'NO'}")

# Empty checks
empty_hazard = sum(1 for r in data['rules'] if not r['hazard'])
empty_req = sum(1 for r in data['rules'] if not r['requirement'])
print(f"Empty hazards:      {empty_hazard}")
print(f"Empty requirements: {empty_req}")
print(f"All testable:       {all(r['is_testable'] for r in data['rules'])}")

# Rules by NIST control
print("\n" + "=" * 60)
print("RULES BY NIST CONTROL")
print("=" * 60)
controls = {}
for rule in data['rules']:
    ctrl = rule['source_citation'].split('(')[0].strip()
    if ctrl not in controls:
        controls[ctrl] = []
    controls[ctrl].append(rule['rule_id'])

for ctrl in sorted(controls.keys()):
    print(f"  {ctrl}: {len(controls[ctrl])} rules")
    for rid in controls[ctrl]:
        print(f"    - {rid}")

# Severity
print("\n" + "=" * 60)
print("SEVERITY DISTRIBUTION")
print("=" * 60)
sev = {}
for rule in data['rules']:
    s = rule['severity']
    sev[s] = sev.get(s, 0) + 1
for s, c in sorted(sev.items()):
    print(f"  {s}: {c} ({c*100//len(data['rules'])}%)")

# Evidence signals
print("\n" + "=" * 60)
print("EVIDENCE SIGNALS")
print("=" * 60)
ev = {}
for rule in data['rules']:
    for e in rule['testability']['evidence_signals']:
        ev[e] = ev.get(e, 0) + 1
for e, c in sorted(ev.items()):
    print(f"  {e}: {c}")

# Cross-check with source NIST document
print("\n" + "=" * 60)
print("CROSS-CHECK WITH SOURCE DOCUMENT")
print("=" * 60)
source_text = source_path.read_text(encoding="utf-8")
expected_controls = ['AC-1', 'AC-2', 'AC-3', 'AC-3(7)', 'AC-3(8)',
                     'AC-4', 'AC-4(1)', 'AC-4(4)', 'AC-5', 'AC-6',
                     'AC-6(1)', 'AC-6(2)', 'AC-6(5)', 'AC-6(9)', 'AC-6(10)',
                     'AC-17', 'AC-17(1)', 'AC-17(2)', 'AC-24']

extracted_citations = set(r['source_citation'] for r in data['rules'])
for ctrl in expected_controls:
    # Check if any rule covers this control
    found = any(ctrl in c for c in extracted_citations)
    status = "COVERED" if found else "MISSING"
    print(f"  {ctrl}: {status}")

print("\n" + "=" * 60)
print("VERDICT: READY TO SHARE" if not missing and match and empty_hazard == 0 else "ISSUES FOUND")
print("=" * 60)
