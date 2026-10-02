def validate_alert(alert):
    errors = []

    if not isinstance(alert, dict):
        return ["The alert must be a JSON object."]

    alert_id = alert.get("alert_id")
    if not isinstance(alert_id, str) or not alert_id.strip():
        errors.append("alert_id must be a non-empty string.")

    event_id = alert.get("event_id")
    if type(event_id) is not int:
        errors.append("event_id must be a whole number, such as 4688.")

    # Check text fields when they are supplied.
    text_fields = [
        "timestamp",
        "hostname",
        "username",
        "process",
        "parent_process",
        "command_line",
        "source_ip",
    ]

    for field in text_fields:
        if field in alert and not isinstance(alert[field], str):
            errors.append(f"{field} must be text.")

    # Check the failed-login count when it is supplied.
    if "failed_login_count" in alert:
        count = alert["failed_login_count"]

        if type(count) is not int or count < 0:
            errors.append(
                "failed_login_count must be a non-negative whole number."
            )

    return errors