import json
import sys
from pathlib import Path

from rules import analyze_alert
from analyzer import analyze_with_ai
from decision import compare_results
from audit import log_investigation, log_analyst_decision

if len(sys.argv) != 2:
    print("Usage: python3 app.py <alert_file>")
    sys.exit(1)

alert_path = Path("sample_alerts") / sys.argv[1]

if not alert_path.exists():
    print(f"Error: {alert_path} does not exist.")
    sys.exit(1)

with open(alert_path, "r") as file:
    alert = json.load(file)


rule_result = analyze_alert(alert)

ai_result = analyze_with_ai(alert)

decision = compare_results(rule_result, ai_result)

investigation_id = log_investigation(
    alert,
    rule_result,
    ai_result,
    decision
)

print("\n=== ALERT ===")
print("Alert ID:", alert["alert_id"])


print("\n=== RULE-BASED ANALYSIS ===")
print("Risk Score:", rule_result["score"])

for reason in rule_result["reasons"]:
    print("-", reason)


print("\n=== AI ANALYSIS ===")

print("Severity:", ai_result["severity"])
print("Confidence:", ai_result["confidence"])

print("\nMITRE ATT&CK Techniques:")
for technique in ai_result["mitre_techniques"]:
    print("-", technique)

print("\nEvidence:")
for item in ai_result["evidence"]:
    print("-", item)

print("\nExplanation:")
print(ai_result["explanation"])

print("\nRecommended Investigation Steps:")
for step in ai_result["recommended_steps"]:
    print("-", step)

print("\n=== HUMAN REVIEW ===")

print("Rule Severity:", decision["rule_severity"])
print("AI Severity:", decision["ai_severity"])
print("AI Confidence:", decision["ai_confidence"])

if decision["review_required"]:
    print("\nSTATUS: REVIEW REQUIRED")

    for reason in decision["review_reasons"]:
        print("-", reason)
else:
    print("\nSTATUS: ANALYSES AGREE")

print("\n=== ANALYST DECISION ===")

while True:
    analyst_choice = input(
        "Choose Approve, Reject, or Escalate: "
    ).strip().lower()

    if analyst_choice in ["approve", "reject", "escalate"]:
        break

    print("Invalid choice. Please enter Approve, Reject, or Escalate.")


log_analyst_decision(
    investigation_id,
    analyst_choice.capitalize()
)

print(
    f"Analyst decision '{analyst_choice.capitalize()}' "
    "saved to audit log."
)