def analyze_alert(alert):
    score = 0
    reasons = []

    event_id = alert.get("event_id")
    process = alert.get("process", "").lower()
    parent_process = alert.get("parent_process", "").lower()
    command_line = alert.get("command_line", "").lower()

    failed_logins = alert.get("failed_login_count", 0)
    username = alert.get("username", "").lower()

    # -------------------------
    # PowerShell rules
    # -------------------------

    if process == "powershell.exe":
        score += 20
        reasons.append("PowerShell process detected")

    if parent_process == "winword.exe" and process == "powershell.exe":
        score += 30
        reasons.append("Microsoft Word launched PowerShell")

    if "-encodedcommand" in command_line:
        score += 30
        reasons.append("PowerShell used an encoded command")

    # -------------------------
    # Failed login rules
    # -------------------------

    if event_id == 4625 and failed_logins >= 10:
        score += 50
        reasons.append(
            f"{failed_logins} failed login attempts detected"
        )

    elif event_id == 4625 and failed_logins >= 5:
        score += 30
        reasons.append(
            f"{failed_logins} failed login attempts detected"
        )

    if event_id == 4625 and username in ["admin", "administrator"]:
        score += 20
        reasons.append(
            "Failed login activity targeted an administrative account"
        )

    # Prevent scores above 100
    score = min(score, 100)

    return {
        "score": score,
        "reasons": reasons
    }