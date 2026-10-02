import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = Path("logs/investigations.jsonl")


def write_log(record):
    # Create logs folder if it does not exist
    LOG_FILE.parent.mkdir(exist_ok=True)

    # Append one JSON record to the audit log
    with open(LOG_FILE, "a") as file:
        file.write(json.dumps(record) + "\n")


def log_investigation(alert, rule_result, ai_result, decision):
    # Give this investigation a unique ID
    investigation_id = str(uuid.uuid4())

    record = {
        "event_type": "investigation",
        "investigation_id": investigation_id,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert.get("alert_id"),
        "alert": alert,
        "rule_analysis": rule_result,
        "ai_analysis": ai_result,
        "decision": decision
    }

    write_log(record)

    return investigation_id


def log_analyst_decision(investigation_id, analyst_decision):
    record = {
        "event_type": "analyst_decision",
        "investigation_id": investigation_id,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "analyst_decision": analyst_decision
    }

    write_log(record)