# Automated Ransomware Containment & Incident Response Orchestrator

[![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Pytest](https://img.shields.io/badge/pytest-451%20passed-brightgreen.svg)](https://pytest.org)
[![Jira Cloud](https://img.shields.io/badge/Jira-REST%20API%20v3-0052CC.svg)](https://www.atlassian.com/software/jira)
[![Slack](https://img.shields.io/badge/Slack-Block%20Kit-4A154B.svg)](https://api.slack.com)
[![Status](https://img.shields.io/badge/Week%204-Day%205%20Completed-success.svg)](#22-conclusion)

An enterprise-grade, automated incident response orchestration platform designed to intake endpoint security alerts, validate and enrich threat indicators, store security incidents, coordinate containment workflows against simulated ransomware attacks, create tracked tickets in **Atlassian Jira Cloud**, assign tickets via severity-based SOC routing, and broadcast real-time alerts to **Slack** channels.

---

## Table of Contents

1. [Project Introduction](#1-project-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Project Objectives](#3-project-objectives)
4. [Proposed Solution](#4-proposed-solution)
5. [System Architecture](#5-system-architecture)
6. [Technologies Used](#6-technologies-used)
7. [Features Implemented](#7-features-implemented)
8. [Complete Incident Response Workflow](#8-complete-incident-response-workflow)
9. [Jira Integration](#9-jira-integration)
10. [Severity-Based SOC Analyst Assignment](#10-severity-based-soc-analyst-assignment)
11. [Slack Notification Integration](#11-slack-notification-integration)
12. [Safe Ransomware Simulation](#12-safe-ransomware-simulation)
13. [Performance Evaluation](#13-performance-evaluation)
14. [Testing Results](#14-testing-results)
15. [Installation and Setup](#15-installation-and-setup)
16. [Environment Configuration](#16-environment-configuration)
17. [Commands to Run the Project](#17-commands-to-run-the-project)
18. [Project Folder Structure](#18-project-folder-structure)
19. [Security Considerations](#19-security-considerations)
20. [Limitations](#20-limitations)
21. [Future Enhancements](#21-future-enhancements)
22. [Conclusion](#22-conclusion)

---

## 1. Project Introduction

The **Automated Ransomware Containment & Incident Response Orchestrator** is an end-to-end SecOps automation system that unifies threat detection, indicator validation, host containment, identity isolation, forensic acquisition, ticketing, and communications.

By bridging Endpoint Detection & Response (EDR) solutions (CrowdStrike Falcon, Microsoft Defender for Endpoint) with enterprise service management (**Atlassian Jira Cloud**) and team communication (**Slack**), the orchestrator replaces slow, manual escalation processes with sub-second, deterministic response workflows.

---

## 2. Problem Statement

Ransomware attacks are characterized by extreme velocity. Once a malicious binary achieves code execution, attackers initiate privilege escalation, delete volume shadow copies, tamper with backups, and begin encrypting thousands of files within minutes.

Manual incident response workflows introduce fatal latency:
- **Alert Triage Delays:** Security analysts spend critical minutes copying indicators between EDR consoles, threat databases, and ticketing software.
- **Inconsistent Assignment:** High-severity incidents can languish in unassigned queues during shift handoffs.
- **Fragmented Communication:** Incident responders, IT managers, and executives lack a synchronized real-time view of active containment actions.
- **Safety Hazards in Playbook Testing:** Security teams lack a safe, non-destructive method to rehearse and benchmark automated playbooks without endangering production endpoints.

---

## 3. Project Objectives

1. **Sub-Second Containment & Telemetry Validation:** Ingest, parse, and sanitize threat telemetry (IPv4/IPv6, hostnames, SHA-256 process hashes) using RFC-compliant sanitization rules.
2. **Automated Incident Ticketing:** Connect to Atlassian Jira Cloud via HTTPS REST API to instantiate standardized security tickets with zero manual effort.
3. **Deterministic SOC Routing:** Route incidents automatically to designated SOC roles based on alert severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
4. **Real-Time Team Broadcasting:** Deliver rich Slack Block Kit notification cards with visual indicators (🔴, 🟠, 🟡, 🟢) and direct ticket browse URLs.
5. **Zero-Risk Simulation:** Provide safe ransomware emulation that exercises the complete response pipeline without encrypting files, modifying live accounts, or altering endpoints.
6. **Fault Isolation:** Ensure operational disruptions in communication channels (e.g. Slack webhook timeouts) never interrupt or corrupt core containment or Jira ticket creation.
7. **Empirical Performance Benchmarking:** Measure precise execution timings using Python's `time.perf_counter()` to provide verifiable performance and reliability metrics.

---

## 4. Proposed Solution

The orchestrator implements an event-driven, pipeline-based architecture:
1. **Intake Layer:** FastAPI webhook endpoints receive structured alert payloads over TLS, authenticated using constant-time shared secrets.
2. **Sanitization Engine:** Validates network indicators against strict regular expressions and standard library validators (`ipaddress`, RFC 1123 DNS rules) to reject command injections.
3. **Coordination Store:** An atomic SQLite coordination table (`action_deduplication`) utilizes database-level primary keys to prevent race conditions and deduplicate repeated alerts.
4. **Integration Bridge:** A modular REST client connects to Jira Cloud for ticket generation and analyst assignment, coupled with an asynchronous Slack notification service.
5. **Safety Harness:** The simulator models realistic threat behaviors (canary trips, shadow copy deletions, mass file renames) purely in synthetic telemetry.

---

## 5. System Architecture

The following diagram illustrates the interaction between threat telemetry sources, the core orchestration pipeline, and external cloud integrations:

```mermaid
flowchart TD
    subgraph Sources["Threat Telemetry Sources"]
        CS["CrowdStrike Falcon API"] -->|Alert Telemetry| Intake["FastAPI Ingestion Engine"]
        MDE["Microsoft Defender API"] -->|Alert Telemetry| Intake
        SIM["Safe Ransomware Simulator"] -->|Synthetic Telemetry| Intake
    end

    subgraph CoreEngine["Core Orchestrator Pipeline"]
        Intake --> Val["Strict Indicator Validation\n(RFC 1123, IP, SHA-256)"]
        Val --> Dedup["SQLite Atomic Deduplication\n(Engine-Level Lock)"]
        Dedup --> Decision["Containment & Triage Coordinator"]
    end

    subgraph ExternalIntegrations["Enterprise Integrations"]
        Decision --> Jira["Atlassian Jira Cloud REST API\n(POST /rest/api/3/issue)"]
        Jira --> Route["Severity-Based Analyst Routing\n(PUT /issue/{key}/assignee)"]
        Route --> Slack["Slack Incoming Webhooks\n(Block Kit Rich Cards)"]
    end

    subgraph AuditReports["Audit & Analytics"]
        Decision --> SimRep["JSON Audit Reports\n(reports/simulations/)"]
        Decision --> PerfRep["Performance & Reliability Reports\n(reports/performance/)"]
    end
```

---

## 6. Technologies Used

- **Language:** Python 3.13 (Standard Library + AsyncIO)
- **Web Framework:** FastAPI, Uvicorn, Starlette
- **Data Persistence:** SQLite 3 with Write-Ahead Logging (WAL) and primary key locks
- **HTTP Clients:** Requests, HTTPX, Respx
- **Enterprise Integrations:** Atlassian Jira Cloud REST API v3, Slack Incoming Webhooks (Block Kit)
- **Data Visualization:** Matplotlib 3.10
- **Testing Framework:** Pytest 9.1 with AnyIO and Respx
- **Security & Hashing:** Python `hashlib` (SHA-256), `secrets.compare_digest` (constant-time verification)

---

## 7. Features Implemented

- [x] **Secure Webhook Ingestion:** Timing-attack resistant shared secret verification (`secrets.compare_digest`).
- [x] **Strict Indicator Sanitization:** IPv4/IPv6 validation, RFC 1123 DNS hostname filtering, lowercase SHA-256 normalization.
- [x] **Atomic Multi-Worker Deduplication:** SQLite database-level locks preventing redundant isolation actions across multiple processes.
- [x] **Network Containment Verification:** EDR integration supporting CrowdStrike, Defender, and simulated isolation modes.
- [x] **Identity Containment:** Microsoft Entra ID (Azure AD) account suspension and session revocation with protected break-glass safeguards.
- [x] **Forensic Acquisition Pipeline:** Volatile memory acquisition, KAPE triage artifacts, and AWS S3 forensic vault archiving with cryptographic SHA-256 ledgers.
- [x] **Jira Cloud Ticketing Integration:** Automated creation of standardized incident tickets with browse URLs and deduplication.
- [x] **Severity-Based SOC Routing:** Dynamic assignment of incidents to specific SOC tiers (Commander, Tier 2, Tier 1, Monitoring).
- [x] **Interactive Slack Alerts:** Color-coded severity dots, markdown bullet points, and browse buttons delivered to SOC channels.
- [x] **Safe Ransomware Emulation:** Synthetic multi-severity telemetry generation with 100% safety guarantees.
- [x] **Fault-Tolerant Slack Isolation:** Confirmed guarantee that Slack failures do not halt Jira ticket creation.
- [x] **High-Resolution Performance Engine:** Nanosecond/microsecond-accurate execution profiling with automated CSV, JSON, and chart generation.

---

## 8. Complete Incident Response Workflow

The complete end-to-end incident lifecycle progresses through eight deterministic stages:

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Threat Activity
    participant Endpoint as Endpoint / EDR
    participant Orchestrator as ZAALIMA Orchestrator
    participant Jira as Jira Cloud API
    participant Slack as Slack Channel
    participant Reports as Audit Store

    Attacker->>Endpoint: Canary File Tripwire / Process Execution
    Endpoint->>Orchestrator: Ingest Telemetry (POST /webhook/edr)
    Orchestrator->>Orchestrator: Stage 1: Validate Telemetry (RFC 1123, IP, Hash)
    Orchestrator->>Orchestrator: Stage 2: Deduplication Check (SQLite Lock)
    Orchestrator->>Jira: Stage 3: Create Incident Ticket (POST /issue)
    Jira-->>Orchestrator: Return Ticket Key (e.g., RR-101)
    Orchestrator->>Jira: Stage 4: Assign SOC Analyst (PUT /assignee)
    Jira-->>Orchestrator: Acknowledge Assignment
    Orchestrator->>Slack: Stage 5: Dispatch SOC Alert (POST Webhook)
    Slack-->>Orchestrator: HTTP 200 OK
    Orchestrator->>Reports: Stage 6: Write JSON Audit Trail (reports/)
    Orchestrator->>Reports: Stage 7: Measure Stage Timings (time.perf_counter)
```

---

## 9. Jira Integration

The orchestrator connects to Atlassian Jira Cloud REST API v3 using HTTP Basic Authentication (email + API token) strictly over TLS 1.3:

```mermaid
flowchart LR
    A["Validated Threat Telemetry"] --> B["Build Standardized Summary\n[SEC-INCIDENT] Ransomware on Host"]
    B --> C["Format Markdown Description\n(IP, User, Hashes, Timestamps)"]
    C --> D["Check Existing Tickets\n(JQL Query Deduplication)"]
    D --> E["POST /rest/api/3/issue\nCreate Jira Ticket"]
    E --> F["Return Ticket Key & Browse URL\nhttps://domain.atlassian.net/browse/SEC-101"]
```

### Ticket Description Format:
Tickets include standardized SOC forensic tables:
- **Incident ID & Severity:** Unique identifier and threat tier.
- **Affected Endpoint:** Hostname, IP address, and logged-in user.
- **Threat Artifacts:** Process names, process IDs, and SHA-256 binary hashes.
- **Containment Status:** Real-time containment verification state.

---

## 10. Severity-Based SOC Analyst Assignment

To ensure prompt and appropriately skilled handling, incident tickets are automatically assigned using a severity-to-role routing matrix:

| Severity | Target Role | Primary Responsibility | SLA Target |
|---|---|---|---|
| **CRITICAL** | **Senior SOC Lead / Incident Commander** | Host isolation verification, executive escalation, enterprise triage | < 15 minutes |
| **HIGH** | **SOC Analyst (Tier 2)** | Network artifact investigation, lateral movement assessment | < 30 minutes |
| **MEDIUM** | **Junior SOC Analyst (Tier 1)** | Telemetry validation, indicator correlation, initial containment | < 60 minutes |
| **LOW** | **Monitoring Analyst** | Observational triage, threshold tuning, false-positive filtering | < 4 hours |

---

## 11. Slack Notification Integration

Alerts are formatted using Slack Block Kit cards featuring color-coded visual indicators:

```mermaid
flowchart TD
    A["Ticket Created & Analyst Assigned"] --> B["Select Severity Indicator\n🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low"]
    B --> C["Generate Slack Block Kit Payload\n(Header, Details, Description, Action Button)"]
    C --> D["Send HTTPS POST to Slack Webhook"]
    D --> E{Webhook Succeeded?}
    E -->|Yes| F["Log Delivery Success"]
    E -->|No / Timeout| G["Log Warning; Jira Incident Remains 100% Intact"]
```

- **Interactive Buttons:** Contains direct links to open the Jira ticket in a browser.
- **Fault Isolation Guarantee:** Network outages, HTTP 500 errors, or missing Slack webhook URLs do **not** abort Jira ticket creation or SOC assignment.

---

## 12. Safe Ransomware Simulation

The simulator (`backend/ransomware_simulator.py`) provides safe, repeatable validation:
- **Mode A: Fully Mocked Simulation (Default):** Evaluates validation, ticketing, routing, and notifications in-memory with zero outbound network calls (< 1ms).
- **Mode B: Controlled Live Integration Test (`--live-simulation`):** Dispatches 1 real test ticket to Jira Cloud and 1 notification to Slack (prompts for confirmation).
- **Safety Guarantee:** Never executes malicious binaries, alters files, deletes volume shadow copies, isolates real endpoints, or suspends active user accounts.

---

## 13. Performance Evaluation

A high-resolution benchmarking evaluation was executed across **80 test iterations** (20 per severity tier) and **9 failure resilience scenarios** using `time.perf_counter()`:

### Empirical Benchmark Results

| Severity Level | Iterations | Min Time | Average Time | Median Time | P95 Time | Max Time | Success Rate |
|---|---|---|---|---|---|---|---|
| **CRITICAL** | 20 | 0.144 ms | 0.223 ms | 0.187 ms | 0.452 ms | 0.652 ms | 100.0% |
| **HIGH** | 20 | 0.107 ms | 0.153 ms | 0.134 ms | 0.255 ms | 0.324 ms | 100.0% |
| **MEDIUM** | 20 | 0.096 ms | 0.103 ms | 0.101 ms | 0.114 ms | 0.153 ms | 100.0% |
| **LOW** | 20 | 0.090 ms | 0.099 ms | 0.095 ms | 0.123 ms | 0.164 ms | 100.0% |
| **OVERALL** | **80** | **0.090 ms** | **0.145 ms** | **0.120 ms** | **0.255 ms** | **0.652 ms** | **100.0%** |

### Mocked vs Live Performance Distinction:
- **In-Memory Benchmark (Above):** Measures internal CPU operations: parsing, regex matching, payload generation, and dispatch (< 0.7ms).
- **Live Production Integration:** Governed by cloud API roundtrip latency:
  - Jira Cloud REST API: **250ms – 800ms**.
  - Slack Webhook POST: **100ms – 400ms**.
  - Expected real-world end-to-end response: **400ms – 1,500ms (0.4s – 1.5s)**.

### Generated Performance Artifacts:
- `reports/performance/performance_summary.json`: Aggregated metrics.
- `reports/performance/performance_results.csv`: 80 raw iteration records.
- `reports/performance/reliability_analysis.json`: 9 resilience test records (100% pass rate).
- `reports/performance/performance_report.md`: Full evaluation report.
- `reports/performance/performance_charts/`: 4 Matplotlib graphical charts.

---

## 14. Testing Results

The comprehensive test suite covers all unit, integration, and security layers:

```
============================= test session starts =============================
platform win32 -- Python 3.13.0, pytest-9.1.1
collected 451 items

tests\test_alert_parser.py .......................................       [  8%]
tests\test_api_security.py ..........................                    [ 14%]
tests\test_day6_sandbox_validation.py .............................      [ 20%]
tests\test_e2e_workflow.py ..................                            [ 24%]
tests\test_edr_adapters.py ............                                  [ 27%]
tests\test_edr_client.py .........................                       [ 33%]
tests\test_identity_client.py ....................                       [ 37%]
tests\test_identity_response_workflow.py .........                       [ 39%]
tests\test_incident_notifications.py ................                    [ 43%]
tests\test_incidents.py .............                                    [ 45%]
tests\test_jira.py ..................................                    [ 53%]
tests\test_network_containment.py ..................................     [ 60%]
tests\test_network_containment_edr.py .................................. [ 68%]
tests\test_performance_evaluator.py .......                              [ 70%]
tests\test_persistent_coordination.py .......                            [ 72%]
tests\test_ransomware_simulator.py ......................                [ 76%]
tests\test_session_revocation.py ...........                             [ 79%]
tests\test_slack.py ..................                                   [ 83%]
tests\test_validators.py ............................................... [ 93%]
tests\test_webhook.py ...........                                        [100%]

============================ 451 passed in 31.73s =============================
```

---

## 15. Installation and Setup

### Prerequisites:
- Python 3.10+ (tested on Python 3.13)
- Git
- Virtual environment (`venv`)

### Setup Instructions:
```bash
# 1. Clone the repository
git clone <repo-url>
cd "ransomware response"

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate      # Windows
# source venv/bin/activate     # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt
pip install matplotlib pytest respx
```

---

## 16. Environment Configuration

Create a local `.env` file based on `.env.example`:

```bash
copy .env.example .env     # Windows
# cp .env.example .env       # Linux / macOS
```

Configure your environment settings:

```ini
# Jira Cloud Integration
JIRA_BASE_URL=https://your-domain.atlassian.net
JIRA_EMAIL=soc-admin@your-domain.com
JIRA_API_TOKEN=your_jira_api_token_here
JIRA_PROJECT_KEY=SEC
JIRA_ISSUE_TYPE=Task
JIRA_TIMEOUT_SECONDS=10

# SOC Assignee Account IDs (Obtain via python -m backend.main --list-users)
JIRA_ASSIGNEE_CRITICAL=712020:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
JIRA_ASSIGNEE_HIGH=712020:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
JIRA_ASSIGNEE_MEDIUM=712020:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
JIRA_ASSIGNEE_LOW=712020:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Slack Incoming Webhook
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
SLACK_TIMEOUT_SECONDS=10
```

---

## 17. Commands to Run the Project

### Safe Ransomware Simulations:
```bash
# Run default CRITICAL ransomware simulation (mocked mode)
python -m backend.main --simulate-ransomware

# Run simulation with specific severity tier
python -m backend.main --simulate-ransomware --severity HIGH
python -m backend.main --simulate-ransomware --severity MEDIUM
python -m backend.main --simulate-ransomware --severity LOW

# Run controlled live integration simulation (prompts for confirmation)
python -m backend.main --live-simulation
```

### Performance Evaluation & Benchmarking:
```bash
# Run 80-iteration benchmark, 9 resilience scenarios, and generate charts
python -m backend.main --evaluate-performance --iterations 20
```

### Slack Connectivity Testing:
```bash
# Test Slack webhook delivery
python -m backend.main --slack-test

# Test complete simulated notification workflow
python -m backend.main --test-notification-workflow
```

### Test Suite Execution:
```bash
# Run all 451 regression tests
pytest

# Run Day 5 performance evaluator tests
pytest tests/test_performance_evaluator.py -v
```

---

## 18. Project Folder Structure

```
ransomware-response/
├── backend/
│   ├── config.py                       # Configuration bridge
│   ├── incident_notifications.py       # Notification bridge
│   ├── jira_integration.py             # Jira bridge
│   ├── main.py                         # Root CLI orchestrator
│   ├── performance_evaluator.py        # Performance evaluator bridge
│   ├── ransomware_simulator.py         # Simulator bridge
│   └── slack_integration.py            # Slack bridge
│
├── ransomware-orchestrator/            # Week 4 Core Module
│   ├── backend/
│   │   ├── config.py                   # Settings loader & secret masking
│   │   ├── incident_notifications.py   # Block Kit notification formatter
│   │   ├── jira_integration.py         # Jira Cloud API client
│   │   ├── main.py                     # Primary CLI execution runner
│   │   ├── performance_evaluator.py    # Benchmarking engine & Matplotlib charts
│   │   ├── ransomware_simulator.py     # Safe ransomware threat emulator
│   │   └── slack_integration.py        # Slack webhook dispatcher
│   └── tests/                          # Week 4 test suite
│
├── docs/
│   ├── final_demo_guide.md             # 9-step demonstration walkthrough
│   └── final_project_report.md         # Comprehensive project summary
│
├── reports/
│   ├── performance/                    # Generated Day 5 evaluation reports
│   │   ├── performance_summary.json    # Aggregated metrics JSON
│   │   ├── performance_results.csv     # 80 iteration rows
│   │   ├── reliability_analysis.json   # 9 failure scenario records
│   │   ├── performance_report.md       # Markdown evaluation report
│   │   └── performance_charts/         # 4 Matplotlib PNG graphs
│   └── simulations/                    # Serialized JSON audit reports
│
├── tests/                              # Global test suite (451 tests)
├── .env.example                        # Template credentials
├── .gitignore                          # Excludes .env, *.db, and cache files
├── pytest.ini                          # Pytest configuration
└── README.md                           # Main project documentation
```

---

## 19. Security Considerations

- **Zero Secret Exposure:** Credentials, API tokens, and webhook URLs are strictly managed via environment variables and never printed or committed.
- **Git Exclusions:** `.env` and SQLite database files (`*.db`) are ignored in `.gitignore`.
- **Constant-Time Verification:** Webhook authentication uses `secrets.compare_digest` to prevent timing attacks.
- **Strict Input Validation:** RFC 1123 hostnames, IPv4/IPv6 syntax, and SHA-256 process hashes prevent command injection.
- **Report Sanitization:** All reports written to `reports/` are scrubbed using `mask_report_secrets()`.
- **Non-Destructive Simulation:** Simulation logic executes zero destructive actions and isolates zero production workstations.

---

## 20. Limitations

- **Synchronous In-Process Execution:** The standard runner processes tasks synchronously. High-volume SOCs should incorporate Celery or Redis task queues.
- **SQLite Storage:** Local SQLite engine is ideal for single-instance deployments; distributed enterprise clusters should migrate to PostgreSQL.
- **One-Way Slack Alerts:** Currently notifies analysts; interactive response actions in Slack require an active bot server.

---

## 21. Future Enhancements

- **Interactive Slack Buttons:** Allow analysts to acknowledge tickets or initiate containment directly from Slack.
- **LLM-Driven Threat Intelligence:** Generate plain-English incident summaries and remediation recommendations via Gemini API.
- **Forensic Package Attachment:** Automatically upload Week 3 RAM dumps and KAPE triage files directly to Jira tickets.
- **Multi-Tenant Routing:** Route incidents to disparate Jira projects and Slack channels based on organizational business units.

---

## 22. Conclusion

The **Automated Ransomware Containment & Incident Response Orchestrator** successfully demonstrates how automated detection, verification, Jira ticketing, SOC analyst routing, and Slack alerting can operate synchronously with sub-millisecond computational overhead. By bridging EDR detection with collaborative response tools, the platform eliminates manual delays, enforces strict security safeguards, and provides an auditable foundation for modern enterprise SecOps.
