import json
import traceback
from pathlib import Path

import streamlit as st

from rules import analyze_alert
from decision import compare_results
from audit import (
    LOG_FILE,
    log_investigation,
    log_analyst_decision,
)
from validation import validate_alert


PROJECT_FOLDER = Path(__file__).resolve().parent

st.set_page_config(
    page_title="AI SOC Copilot",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI SOC Copilot")
st.caption(
    "Investigate security alerts with rules, AI, and human review."
)


def read_history():
    """Read saved investigations and their latest analyst decisions."""
    investigations = {}
    analyst_decisions = {}
    skipped = 0

    if not LOG_FILE.exists():
        return investigations, analyst_decisions

    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                except ValueError:
                    skipped += 1
                    continue

                if not isinstance(record, dict):
                    skipped += 1
                    continue

                investigation_id = record.get("investigation_id")

                # Ignore older records without investigation IDs.
                if not isinstance(investigation_id, str):
                    continue

                event_type = record.get("event_type")

                if event_type == "investigation":
                    investigations[investigation_id] = record
                elif event_type == "analyst_decision":
                    analyst_decisions[investigation_id] = record

    except (OSError, UnicodeError):
        st.error("Could not read the audit log. Check the terminal.")
        traceback.print_exc()
        return None, None

    if skipped:
        st.warning(f"Skipped {skipped} unreadable audit records.")

    return investigations, analyst_decisions


def show_review_form(investigation_id, location):
    """Record a decision from either the active analysis or history."""
    st.caption(
        "Approve = accept the AI assessment and investigation plan. "
        "Reject = disagree with it. "
        "Escalate = request further review. "
        "These choices record your judgment; they do not execute actions."
    )

    with st.form(key=f"{location}_review_{investigation_id}"):
        choice = st.radio(
            "Choose your decision",
            ["Approve", "Reject", "Escalate"],
            index=None,
        )
        submitted = st.form_submit_button("Save decision")

    if not submitted:
        return

    if choice is None:
        st.warning("Choose a decision before saving.")
        return

    # Check the log again before saving a pending review.
    _, existing_decisions = read_history()

    if existing_decisions is None:
        return

    if investigation_id in existing_decisions:
        st.info("This investigation already has a saved decision.")
        return

    try:
        log_analyst_decision(investigation_id, choice)
    except OSError:
        st.error("Could not save your decision. Check the terminal.")
        traceback.print_exc()
        return

    active_analysis = st.session_state.get("analysis")

    if (
        active_analysis is not None
        and active_analysis.get("investigation_id") == investigation_id
    ):
        active_analysis["analyst_decision"] = choice

    st.rerun()


def show_analysis(analysis):
    rule_result = analysis["rules"]
    ai_result = analysis["ai"]
    decision = analysis["decision"]

    st.divider()
    rules_column, ai_column = st.columns(2)

    with rules_column:
        st.subheader("Rule engine")
        st.metric("Risk score", f"{rule_result['score']}/100")
        st.write("Severity:", decision["rule_severity"])

        st.write("**Reasons**")
        for reason in rule_result["reasons"]:
            st.write("•", reason)

    with ai_column:
        st.subheader("AI analysis")
        st.metric("Severity", ai_result["severity"])
        st.write(
            "Model-reported confidence:",
            f"{ai_result['confidence']}%",
        )
        st.caption(
            "This is the model's own estimate, not measured accuracy."
        )

        st.write("**Explanation**")
        st.write(ai_result["explanation"])

        for heading, field in [
            ("Evidence", "evidence"),
            ("Suggested MITRE ATT&CK techniques", "mitre_techniques"),
            ("Recommended investigation steps", "recommended_steps"),
        ]:
            st.write(f"**{heading}**")
            for item in ai_result[field]:
                st.write("•", item)

    st.subheader("Review status")

    if decision["review_required"]:
        st.warning("Human review required")
        for reason in decision["review_reasons"]:
            st.write("•", reason)
    else:
        st.info(
            "No disagreement or low-confidence flag was triggered."
        )

    st.divider()
    st.subheader("Analyst decision")

    investigation_id = analysis["investigation_id"]
    st.caption(f"Investigation ID: {investigation_id}")

    # Use the audit log as the source of saved decisions.
    _, analyst_decisions = read_history()

    if analyst_decisions is None:
        return

    saved_review = analyst_decisions.get(investigation_id)

    if saved_review:
        st.success(
            f"Analyst decision saved: "
            f"{saved_review.get('analyst_decision')}"
        )
    else:
        st.info("An analyst decision is pending.")
        show_review_form(investigation_id, "active")


def show_alert_workspace():
    alerts_folder = PROJECT_FOLDER / "sample_alerts"
    alert_files = sorted(alerts_folder.glob("*.json"))

    alert_source = st.radio(
        "Alert source",
        ["Sample alert", "Upload JSON"],
        horizontal=True,
    )

    if alert_source == "Sample alert":
        if not alert_files:
            st.info(
                "No sample alerts found. Choose Upload JSON "
                "to load an alert."
            )
            return

        selected_file = st.selectbox(
            "Choose an alert",
            options=alert_files,
            format_func=lambda path: path.name,
        )
        alert_name = selected_file.name

        try:
            with selected_file.open("r", encoding="utf-8") as file:
                alert = json.load(file)
        except (OSError, ValueError):
            st.error("Could not load the alert. Check the terminal.")
            traceback.print_exc()
            return

    else:
        uploaded_file = st.file_uploader(
            "Upload a security alert",
            type=["json"],
        )

        if uploaded_file is None:
            st.info("Choose a JSON file to continue.")
            return

        alert_name = uploaded_file.name

        try:
            alert = json.loads(uploaded_file.getvalue())
        except (ValueError, UnicodeError):
            st.error("The file must contain valid JSON text.")
            return

    if not isinstance(alert, dict):
        st.error("The alert must be a JSON object.")
        return

    if not alert:
        st.error("The alert cannot be empty.")
        return

    st.subheader("Alert details")
    st.json(alert)

    alert_key = (
        alert_source,
        alert_name,
        json.dumps(alert, sort_keys=True),
    )

    if st.session_state.get("alert_key") != alert_key:
        st.session_state["alert_key"] = alert_key
        st.session_state["analysis"] = None

    validation_errors = validate_alert(alert)

    if validation_errors:
        st.error("Fix these alert fields before running analysis:")
        for error in validation_errors:
            st.write("•", error)

    st.caption(
        "Analyze alert sends the selected alert to your configured "
        "AI service. Each click starts a new investigation."
    )

    if st.button(
        "Analyze alert",
        type="primary",
        disabled=bool(validation_errors),
    ):
        st.session_state["analysis"] = None

        try:
            with st.spinner("Running rules and AI analysis..."):
                # Import here so AI configuration errors do not
                # prevent access to saved investigation history.
                from analyzer import analyze_with_ai

                rule_result = analyze_alert(alert)
                ai_result = analyze_with_ai(alert)
                decision = compare_results(rule_result, ai_result)

                investigation_id = log_investigation(
                    alert,
                    rule_result,
                    ai_result,
                    decision,
                )

                st.session_state["analysis"] = {
                    "rules": rule_result,
                    "ai": ai_result,
                    "decision": decision,
                    "investigation_id": investigation_id,
                    "analyst_decision": None,
                }

        except Exception:
            st.error(
                "Could not complete and save the investigation. "
                "Check the terminal for details."
            )
            traceback.print_exc()

    analysis = st.session_state.get("analysis")

    if analysis is not None and not validation_errors:
        show_analysis(analysis)


def show_metrics(investigations, analyst_decisions):
    comparable_count = 0
    disagreement_count = 0
    review_required_count = 0
    valid_severities = ("Low", "Medium", "High", "Critical")

    for record in investigations.values():
        decision = record.get("decision", {})

        if not isinstance(decision, dict):
            continue

        rule_severity = decision.get("rule_severity")
        ai_severity = decision.get("ai_severity")

        if (
            rule_severity in valid_severities
            and ai_severity in valid_severities
        ):
            comparable_count += 1
            disagreement_count += int(rule_severity != ai_severity)

        if decision.get("review_required") is True:
            review_required_count += 1

    pending_count = sum(
        investigation_id not in analyst_decisions
        for investigation_id in investigations
    )

    disagreement_rate = (
        f"{disagreement_count / comparable_count:.1%}"
        if comparable_count
        else "N/A"
    )

    st.subheader("Investigation metrics")
    total_col, disagreement_col, flagged_col, pending_col = st.columns(4)

    total_col.metric("Saved investigations", len(investigations))
    disagreement_col.metric("Severity disagreement", disagreement_rate)
    flagged_col.metric("Flagged for review", review_required_count)
    pending_col.metric("Pending decisions", pending_count)

    st.caption(
        f"Rules and AI assigned different severities in "
        f"{disagreement_count} of {comparable_count} comparable investigations. "
        "Each analysis run counts separately, including repeated alerts."
    )
    st.caption(
        "Disagreement measures consistency, not accuracy. "
        "Flagged for review includes investigations already reviewed."
    )


def show_history():
    st.divider()
    st.header("Investigation history")

    if st.button("Refresh history"):
        st.rerun()

    investigations, analyst_decisions = read_history()

    if investigations is None:
        return

    if not investigations:
        st.info(
            "No saved investigations yet. Analyze an alert to create one."
        )
        return

    show_metrics(investigations, analyst_decisions)

    investigation_ids = list(reversed(investigations))
    rows = []

    for investigation_id in investigation_ids:
        record = investigations[investigation_id]
        review = analyst_decisions.get(investigation_id, {})

        rows.append({
            "Recorded at": record.get("recorded_at"),
            "Alert ID": record.get("alert_id"),
            "Analyst decision": review.get(
                "analyst_decision", "Pending"
            ),
            "Investigation ID": investigation_id,
        })

    st.dataframe(rows, hide_index=True)

    selected_id = st.selectbox(
        "Open a saved investigation",
        options=investigation_ids,
        format_func=lambda investigation_id: (
            f"{investigations[investigation_id].get('alert_id', 'Unknown')} "
            f"— {investigations[investigation_id].get('recorded_at', '')} "
            f"— {investigation_id[:8]}"
        ),
    )

    record = investigations[selected_id]
    saved_review = analyst_decisions.get(selected_id)

    with st.expander("Saved alert"):
        st.json(record.get("alert", {}))

    saved_rules, saved_ai = st.columns(2)

    with saved_rules:
        st.subheader("Saved rule analysis")
        st.json(record.get("rule_analysis", {}))

    with saved_ai:
        st.subheader("Saved AI analysis")
        st.json(record.get("ai_analysis", {}))

    with st.expander("Saved review assessment"):
        st.json(record.get("decision", {}))

    if saved_review:
        st.success(
            f"Analyst decision: {saved_review.get('analyst_decision')}"
        )
        st.caption(
            f"Decision recorded at: {saved_review.get('recorded_at', '')}"
        )
    else:
        st.info("This investigation is waiting for analyst review.")
        show_review_form(selected_id, "history")

    st.divider()
    st.subheader("Export investigation")

    report = {
        "investigation": record,
        "analyst_review": saved_review,
    }

    st.download_button(
        label="Download investigation report (JSON)",
        data=json.dumps(report, indent=2, ensure_ascii=False),
        file_name=f"investigation_{selected_id}.json",
        mime="application/json",
        key=f"download_{selected_id}",
    )

    st.caption(
        "Includes the original alert, rule analysis, AI analysis, "
        "review assessment, and recorded analyst decision. "
        "Pending investigations have analyst_review set to null."
    )


show_alert_workspace()
show_history()