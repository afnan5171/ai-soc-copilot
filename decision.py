def score_to_severity(score):
    if score < 30:
        return "Low"
    elif score < 60:
        return "Medium"
    elif score < 85:
        return "High"
    else:
        return "Critical"


def compare_results(rule_result, ai_result):
    rule_severity = score_to_severity(rule_result["score"])
    ai_severity = ai_result["severity"]
    ai_confidence = ai_result["confidence"]

    review_reasons = []

    if rule_severity != ai_severity:
        review_reasons.append(
            f"Rule engine rated the alert {rule_severity}, "
            f"but AI rated it {ai_severity}."
        )

    if ai_confidence < 70:
        review_reasons.append(
            f"AI confidence is only {ai_confidence}%."
        )

    review_required = len(review_reasons) > 0

    return {
        "rule_severity": rule_severity,
        "ai_severity": ai_severity,
        "ai_confidence": ai_confidence,
        "review_required": review_required,
        "review_reasons": review_reasons
    }