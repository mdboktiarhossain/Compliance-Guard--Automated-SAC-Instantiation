import json

data = json.load(open(r"C:\Users\mdbohos\Desktop\compliance_guard\extracted_schema.json", encoding="utf-8"))
rules = data["rules"]

provision_empty = [r["rule_id"] for r in rules if not r["provision_set"]["provides_to"] and not r["provision_set"]["requires_from"] and not r["provision_set"]["provided_values"]]
related_empty   = [r["rule_id"] for r in rules if not r["related_controls"]]
action_empty    = [r["rule_id"] for r in rules if not r["scope"].get("action")]
odp_filled      = [(r["rule_id"], len(r["odp_assignments"])) for r in rules if r["odp_assignments"]]

print(f"Total rules: {len(rules)}")
print(f"provision_set EMPTY: {len(provision_empty)}/{len(rules)}")
print(f"related_controls EMPTY: {len(related_empty)}/{len(rules)}")
print(f"scope.action EMPTY: {len(action_empty)}/{len(rules)}")
print(f"Rules with ODPs: {len(odp_filled)}")
print()

print("=== Rules WHERE provision_set IS populated ===")
filled = 0
for r in rules:
    ps = r["provision_set"]
    if ps["provides_to"] or ps["requires_from"] or ps["provided_values"]:
        filled += 1
        print(f"  {r['rule_id']}: provides={ps['provides_to']}, requires={ps['requires_from']}, vals={ps['provided_values']}")
if filled == 0:
    print("  NONE - all provision_set fields are empty!")

print()
print("=== Rules WHERE related_controls IS populated ===")
rc_filled = 0
for r in rules:
    if r["related_controls"]:
        rc_filled += 1
        print(f"  {r['rule_id']}: {r['related_controls']}")
if rc_filled == 0:
    print("  NONE - all related_controls are empty!")

print()
print("=== actor + action for first 8 rules ===")
for r in rules[:8]:
    print(f"  {r['rule_id']}: actor={r['scope']['actor']}, action={r['scope'].get('action', [])}")

print()
print("=== impact_factor values (all rules) ===")
for r in rules:
    print(f"  {r['rule_id']}: impact_factor={r['impact_factor']}, baseline={r['baseline_allocation']}, implemented_by={r['implemented_by']}")
