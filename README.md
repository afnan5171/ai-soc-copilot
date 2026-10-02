# AI SOC Copilot
### Security alert triage with AI assistance and human oversight

AI SOC Copilot is a security investigation project that combines rule-based detection, AI-assisted analysis, and analyst review in a single workflow.

I built it to explore a practical question: **How can AI support security analysts while keeping its recommendations accountable and subject to human judgment?**

The application evaluates alerts, compares rule-based and AI assessments, flags disagreements, and records the analyst’s decision. A Streamlit dashboard brings the investigation together, while Docker provides a portable runtime environment.

## Key Capabilities

- **Alert ingestion and validation:** Load sample alerts or upload JSON, with field validation before analysis.
- **Rule-based assessment:** Score observed indicators using deterministic detection logic.
- **AI-assisted investigation:** Generate severity assessments, supporting evidence, suggested MITRE ATT&CK mappings, and investigation steps.
- **Disagreement detection:** Compare rule and AI severity ratings and flag cases that warrant additional review.
- **Human review:** Record Approve, Reject, or Escalate decisions without executing remediation.
- **Investigation history:** Reopen pending cases and inspect previously recorded analyses and decisions.
- **Reporting and metrics:** Export investigations as JSON and track severity disagreements and pending reviews.
- **Containerized deployment:** Run the application through Docker Compose with persistent local audit storage.

## Architecture

```text
Sample or uploaded JSON alert
              ↓
       Input validation
              ↓
     ┌────────┴────────┐
     ↓                 ↓
Rule engine       AI analyzer
     └────────┬────────┘
              ↓
    Assessment comparison
              ↓
       Analyst review
              ↓
 Audit history and report export
```

The rule engine and AI analyzer assess the same evidence independently. The comparison layer identifies severity disagreements and low model-reported confidence. The analyst then reviews the findings and records a decision.

**The AI provides recommendations; it has no authority to execute actions.**

## Technology Stack

| Component | Technology |
|---|---|
| Application and detection logic | Python |
| Analyst dashboard | Streamlit |
| AI analysis | OpenAI API |
| Deployment | Docker and Docker Compose |
| Audit storage | JSON Lines |
| Configuration | Environment variables |
| Planned log collection and detection integration | Splunk |

## Example Investigation

A sample alert contains Microsoft Word launching PowerShell with an encoded command.

1. The rule engine scores the observed indicators.
2. The AI analyzer explains the suspicious behavior and recommends investigation steps.
3. The comparison layer checks whether their severity assessments agree.
4. An analyst reviews the evidence and records a decision.
5. The application saves the analysis and decision under a shared investigation ID.

The saved investigation can be revisited or exported without making another AI request.

## Getting Started

### Requirements

- Docker Desktop
- An API key with access to the model configured in `analyzer.py`
- Network access for AI requests and the initial Docker build

### Configuration

Create a `.env` file in the project root:

```text
OPENAI_API_KEY=your_api_key_here
```

Keep the real `.env` file out of version control. Docker Compose supplies its values when the container starts.

### Run the Application

From the project root:

```bash
docker compose up --build
```

Open [http://localhost:8501](http://localhost:8501).

To stop the application, press **Control + C**. To restart without rebuilding:

```bash
docker compose up
```

Rebuild after changing application code or dependencies.

## Analyst Workflow

1. Select a sample alert or upload a JSON file.
2. Click **Analyze alert**.
3. Review the rule score, AI explanation, evidence, and comparison results.
4. Choose **Approve**, **Reject**, or **Escalate**, then save.
5. Reopen the investigation from history or download its report.

Investigations can remain pending and be reviewed in a later session. Each analysis request creates a new investigation and calls the configured AI service.

## Audit Trail and Persistence

The application appends investigation and analyst-decision events to:

```text
logs/investigations.jsonl
```

A shared investigation ID links each decision to its original analysis. Docker mounts the host’s log directory, preserving records across container restarts.

This provides traceability for the local workflow. It is not a tamper-proof audit store: records remain editable by anyone with filesystem access.

## Evaluation and Findings

The project includes a small evaluation runner that compares actual severity ratings with predefined expectations.

With the local Python environment activated:

```bash
python3 evaluate.py
```

Each test case makes an AI request.

### Observed Development Results

| Check | Observed result |
|---|---|
| Rule severity checks | 3 of 3 passed |
| AI severity checks | 2 of 3 passed in the latest recorded run |
| Manual prompt-injection probe | The injected instruction was resisted in the observed run |
| Docker persistence check | Investigation and analyst decision remained available after restart |

The remaining severity mismatch involved routine PowerShell activity rated **Medium** when the test expected **Low**. This remains a documented evaluation issue.

These checks also exposed a useful distinction: **severity disagreement measures consistency between assessments, not which assessment is correct.** Model-reported confidence is likewise not a substitute for measured accuracy.

The current examples are development cases, including cases used during prompt refinement. They do not establish performance on unseen alerts or broad resistance to prompt injection.

## Engineering Focus

This project demonstrates work across:

- **Security analysis:** Translating alert evidence into detection logic and investigation priorities.
- **AI integration:** Converting structured model output into a reviewable analyst workflow.
- **Application development:** Building input validation, session handling, reporting, and investigation history.
- **Traceability:** Preserving original assessments and linking subsequent analyst decisions.
- **Evaluation:** Defining expected outcomes, identifying mismatches, and documenting limitations.
- **Deployment:** Packaging the application with Docker and separating persistent data from the container.

## Current Scope and Limitations

The application is a single-user security lab prototype.

- Alerts currently come from sample files or JSON uploads; Splunk is not connected yet.
- AI analysis may vary and requires analyst verification.
- Validation checks basic structure and field types, not the trustworthiness of alert content.
- Alert data is sent to the configured AI service during analysis.
- Authentication and production access controls are not implemented.
- JSONL storage and review handling are not designed for concurrent analysts.
- Dependency versions still need to be pinned.
- Broader evaluation and prompt-injection testing remain in progress.

## Roadmap

The next phase connects the application to a Windows and Splunk lab:

```text
Windows security events
          ↓
Splunk collection and detection
          ↓
Copilot alert ingestion
          ↓
Rule-based and AI-assisted analysis
          ↓
Analyst review and audit history
```

The goal is an end-to-end demonstration: generate a controlled lab event, detect it in Splunk, investigate it through the Copilot, and preserve the analyst’s decision.