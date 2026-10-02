import json
from pathlib import Path

from rules import analyze_alert
from analyzer import analyze_with_ai
from decision import score_to_severity


PROJECT_FOLDER = Path(__file__).resolve().parent


def main():
    cases_path = PROJECT_FOLDER / "evaluation" / "cases.json"

    with cases_path.open("r", encoding="utf-8") as file:
        cases = json.load(file)

    rule_passes = 0
    ai_passes = 0
    errors = 0

    for case in cases:
        filename = case["alert_file"]
        print(f"\n=== {filename} ===")

        try:
            alert_path = PROJECT_FOLDER / "sample_alerts" / filename

            with alert_path.open("r", encoding="utf-8") as file:
                alert = json.load(file)

            # Check the deterministic rules.
            rule_result = analyze_alert(alert)
            rule_severity = score_to_severity(rule_result["score"])

            rule_passed = (
                rule_severity == case["expected_rule_severity"]
            )
            rule_passes += int(rule_passed)

            print(
                f"Rules: {'PASS' if rule_passed else 'FAIL'}"
                f" | Expected: {case['expected_rule_severity']}"
                f" | Actual: {rule_severity}"
            )

            # Check the AI against the accepted ratings.
            ai_result = analyze_with_ai(alert)
            ai_severity = ai_result["severity"]

            ai_passed = (
                ai_severity in case["acceptable_ai_severities"]
            )
            ai_passes += int(ai_passed)

            print(
                f"AI: {'PASS' if ai_passed else 'FAIL'}"
                f" | Accepted: {', '.join(case['acceptable_ai_severities'])}"
                f" | Actual: {ai_severity}"
            )

            print("Test rationale:", case["rationale"])
            print("AI explanation:", ai_result["explanation"])

        except Exception as error:
            errors += 1
            print(f"ERROR: {type(error).__name__}: {error}")

    total = len(cases)

    print("\n=== EVALUATION SUMMARY ===")
    print(f"Test cases: {total}")
    print(f"Rule checks passed: {rule_passes}/{total}")
    print(f"AI severity checks passed: {ai_passes}/{total}")
    print(f"Cases with execution errors: {errors}")


if __name__ == "__main__":
    main()