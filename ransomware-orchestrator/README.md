# Automated Ransomware Containment & Incident Response Orchestrator
## Day 1: Jira Cloud REST API Incident Response Ticketing Integration

An automated incident response orchestration module written in Python that automatically receives ransomware detection telemetry from security monitoring systems, validates and sanitizes threat indicators, and creates standardized, high-priority security incident tickets in **Atlassian Jira Cloud** via the **Jira REST API**.

---

## Table of Contents

1. [Day 1 Objectives & Overview](#1-day-1-objectives--overview)
2. [Project Architecture & Directory Layout](#2-project-architecture--directory-layout)
3. [Jira Cloud Free Account Setup](#3-jira-cloud-free-account-setup)
4. [Step-by-Step Jira API Token Generation](#4-step-by-step-jira-api-token-generation)
5. [Installation & Dependencies](#5-installation--dependencies)
6. [Environment Configuration (.env)](#6-environment-configuration-env)
7. [Running the Application](#7-running-the-application)
8. [Running the Automated Test Suite](#8-running-the-automated-test-suite)
9. [Incident Ticket Format Specification](#9-incident-ticket-format-specification)
10. [Security & SOC Best Practices](#10-security--soc-best-practices)
11. [Day 2: Severity-Based SOC Analyst Auto-Assignment](#11-day-2-severity-based-soc-analyst-auto-assignment)
12. [Week 4 Day 3: Slack Webhook Integration (Task 1)](#12-week-4-day-3-slack-webhook-integration-task-1)

---

## 1. Day 1 Objectives & Overview

In a production Security Operations Center (SOC), when a ransomware outbreak occurs, every second counts. Automated ticketing ensures:
- **Instant Escalation**: Threat indicators are registered in the ticketing system immediately without human delay.
- **Auditability & Traceability**: Critical forensic artifacts (hostnames, hashes, IP addresses, timestamps) are preserved in the ticket description.
- **Standardized Triage**: Responders receive consistent alert layouts tagged with severity, host, and attack type.

### Day 1 Deliverables:
- **Jira Cloud REST API Connection**: Authenticates via HTTP Basic Auth (email + API token) strictly over TLS/HTTPS.
- **Authentication Verification**: Pre-flight verification endpoint (`GET /rest/api/2/myself`) validating user identity.
- **Project Discovery & Validation**: Project listing (`GET /rest/api/2/project`) and project key validation (`SEC`).
- **Telemetry Validation**: Rigorous checks on IP addresses, cryptographic hashes (MD5, SHA-1, SHA-256), and required fields.
- **Automated Ticket Creation**: `create_incident_ticket()` creating issues with standardized summary and formatted description.
- **Error Handling**: Graceful handling of network drops, bad credentials, and API rejections without application crashes.
- **Automated Unit Testing**: 19 automated unit tests verifying all success paths, error states, and security boundaries.

---

## 2. Project Architecture & Directory Layout

```
ransomware-orchestrator/
│
├── backend/
│   ├── __init__.py           # Package exports and interfaces
│   ├── config.py             # Secure configuration loader and secret masker
│   ├── jira_integration.py   # JiraClient class and create_incident_ticket()
│   └── main.py               # SOC CLI orchestrator and runner
│
├── tests/
│   ├── __init__.py
│   └── test_jira.py          # 19 pytest unit & integration tests
│
├── .env                      # Local credentials (excluded by .gitignore)
├── .env.example              # Documented credentials template
├── .gitignore                # Git exclusions ensuring no secret leakage
├── pytest.ini                # Pytest discovery configuration
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 3. Jira Cloud Free Account Setup

If you do not already have a Jira Cloud instance:

1. **Sign Up for Jira Cloud Free**:
   - Navigate to [https://www.atlassian.com/software/jira/free](https://www.atlassian.com/software/jira/free).
   - Select **Jira Software (Free)** and click **Get it free**.
   - Sign up using your institutional or personal email address.
   - Choose a unique workspace domain name (e.g. `your-subdomain.atlassian.net`).
2. **Create a Project for Security Incidents**:
   - Once inside your Jira dashboard, click **Projects** > **Create Project**.
   - Choose template: **Kanban** or **Scrum** (Software development) or **Task Tracking**.
   - Name the project: `Security Incident Response`.
   - Set the Project Key: `SEC`.
   - Click **Create Project**.
3. **Verify Issue Types**:
   - In standard Jira projects, the default issue type is `Task` or `Bug` or `Incident`.
   - The orchestrator defaults to `Task` (configurable via `JIRA_ISSUE_TYPE=Task` in `.env`).

---

## 4. Step-by-Step Jira API Token Generation

Atlassian Jira Cloud uses **API Tokens** for REST API authentication (passwords are deprecated for API calls):

1. Log in to your Atlassian account.
2. Go to Atlassian API Token Management:
   **[https://id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)**
3. Click the **Create API token** button.
4. Enter a descriptive label (e.g., `Ransomware-Orchestrator-Day1`).
5. Click **Create**.
6. **Copy the generated API token immediately** and store it securely. (Atlassian will not display it again once the dialog is closed).
7. Paste this token into your local `.env` file under `JIRA_API_TOKEN`.

---

## 5. Installation & Dependencies

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13.
- Windows, macOS, or Linux.

### Setup Instructions

1. **Navigate to the project directory**:
   ```bash
   cd ransomware-orchestrator
   ```

2. **Create a Python Virtual Environment**:
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

The `requirements.txt` file installs:
- `requests>=2.31.0`: Secure HTTP client for REST API communication.
- `python-dotenv>=1.0.0`: Environment variable loading from `.env`.
- `pytest>=7.4.0`: Automated unit testing framework.
- `pytest-mock>=3.11.0`: Mocking utilities for simulating Jira API responses.

---

## 6. Environment Configuration (.env)

1. Create your `.env` file from `.env.example`:
   ```bash
   # Windows (PowerShell)
   Copy-Item .env.example .env

   # Linux / macOS
   cp .env.example .env
   ```

2. Open `.env` and fill in your details:
   ```env
   # Jira Cloud HTTPS Domain
   JIRA_BASE_URL=https://your-domain.atlassian.net

   # Your Atlassian Account Email
   JIRA_EMAIL=your-email@example.com

   # The API Token generated from id.atlassian.com
   JIRA_API_TOKEN=ATATT3xFfGF0...your_token_here...

   # Project Key where incident tickets will be logged
   JIRA_PROJECT_KEY=SEC

   # Issue Type in your Jira Project (Task, Incident, Bug)
   JIRA_ISSUE_TYPE=Task

   # HTTP Timeout in seconds
   JIRA_TIMEOUT_SECONDS=10

   # Enforce SSL/TLS certificate verification
   JIRA_VERIFY_SSL=true

   # Log level
   LOG_LEVEL=INFO
   ```

> **SECURITY NOTE**: `.env` is listed in `.gitignore` and must **NEVER** be committed to GitHub or any public version control system.

---

## 7. Running the Application

### Option A: Safe Simulation / Demo Mode (No Live Jira Required)
If you are presenting this project, running in offline mode, or grading in an isolated environment without a live Jira account, use the `--simulate` flag:

```bash
python backend/main.py --simulate
```
*Note: If credentials in `.env` contain default placeholders, the application automatically defaults to Simulation Mode to prevent crashes!*

### Option B: Live Jira Execution
Once your `.env` contains valid Jira Cloud credentials:

```bash
python backend/main.py
```

### Option C: Pre-Flight Connection & Project Verification Only
To test that your Jira credentials and project key are valid without generating an incident ticket:

```bash
python backend/main.py --check-auth
```

### Option D: Ingest Custom Ransomware Alert File
To test custom incident telemetry from a JSON file:

```bash
python backend/main.py --alert-file /path/to/alert.json
```

---

## 8. Running the Automated Test Suite

The test suite runs entirely offline using mocks and does not make external network calls or require live Jira credentials:

```bash
# Run all tests
pytest -v

# Run tests with detailed output
pytest tests/test_jira.py -v
```

### Test Coverage Highlights (19 Tests):
- **Authentication**: Successful login (`GET /rest/api/2/myself`), 401 Unauthorized handling, 403 Forbidden handling.
- **Projects**: Project retrieval (`GET /rest/api/2/project`), project key confirmation, missing project error handling.
- **Ticket Creation**: `create_incident_ticket()` parameter verification, summary format, multiline description formatting.
- **Resilience**: Network timeouts (`Timeout`), connection drops (`ConnectionError`), HTTP 500 server errors, HTTP 400 Bad Request error extraction.
- **Validation**: Rejection of invalid IP addresses, rejection of invalid process hashes, missing field detection.
- **Security**: Strict HTTPS protocol enforcement, masking of API tokens in logs and dictionaries.

---

## 9. Incident Ticket Format Specification

When a ransomware detection occurs, the orchestrator formats the ticket precisely according to SOC incident response specifications:

### Ticket Summary:
```text
[CRITICAL] Ransomware Detected - WKSTN-FIN-04.corp.local
```

### Ticket Description:
```text
Incident ID: INC-20261031-8842
Incident Type: Ransomware (LockBit 3.0)
Severity: CRITICAL
Affected Host: WKSTN-FIN-04.corp.local
IP Address: 10.0.4.15
Compromised User: finance_analyst_01
Process Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Detection Time: 2026-10-31T16:26:37Z
Incident Description: High-frequency unauthorized file renames with .lockbit extension detected in C:\Users\finance_analyst_01\Documents. Canary tripwire activated. Volume Shadow Copies deletion attempted via vssadmin.exe delete shadows /all.
```

---

## 10. Security & SOC Best Practices

1. **Credential Hygiene**:
   - API tokens are read exclusively from environment variables (`.env`).
   - `mask_secret()` automatically masks tokens in console and log streams (e.g., `ATAT...****`).
2. **Encrypted Transport (TLS/HTTPS)**:
   - Plain HTTP endpoints (`http://`) are rejected at configuration time with a `ValueError`.
   - Strict SSL/TLS certificate verification is enabled by default (`verify_ssl=True`).
3. **Telemetry Sanitization**:
   - IP addresses are strictly validated against IPv4/IPv6 standards via Python's built-in `ipaddress` module.
   - Process hashes are validated using regular expressions to ensure authentic MD5, SHA-1, or SHA-256 hex strings, preventing prompt or format injection.
4. **Crash-Resistant Design**:
   - All network exceptions (`Timeout`, `ConnectionError`, `RequestException`) are caught and translated into custom exceptions, ensuring the orchestrator exits cleanly with actionable triage diagnostics.

---

## 11. Day 2: Severity-Based SOC Analyst Auto-Assignment

Day 2 extends the orchestrator with automated incident assignment, routing newly created ransomware tickets to the appropriate incident response personnel according to alert severity.

### Severity-to-Analyst Routing Matrix

| Alert Severity | Target SOC Role | Assignment Mechanism |
|---|---|---|
| **CRITICAL** | Senior SOC Lead / Incident Commander | `PUT /rest/api/3/issue/{key}/assignee` |
| **HIGH** | SOC Analyst (Tier 2) | `PUT /rest/api/3/issue/{key}/assignee` |
| **MEDIUM** | Junior SOC Analyst (Tier 1) | `PUT /rest/api/3/issue/{key}/assignee` |
| **LOW** | Monitoring Analyst / Triage Queue | `PUT /rest/api/3/issue/{key}/assignee` |

### Key Methods Added to `JiraClient`:
- `get_assignable_users(project_key)`: Discovers all users permitted to be assigned issues in the project (`GET /rest/api/3/user/assignable/search?project={key}`).
- `assign_incident_ticket(issue_key, account_id)`: Assigns a ticket to a user using their Atlassian `accountId` (`PUT /rest/api/3/issue/{key}/assignee`). Jira returns HTTP 204 on success.
- `select_analyst_for_severity(severity, assignee_config)`: Maps severity level to corresponding analyst account ID from configuration.
- `auto_assign_incident(issue_key, severity, assignee_config)`: Orchestrates severity routing and ticket assignment with full error recovery.

### Listing Assignable Users via CLI:
```bash
python -m backend.main --list-users
```
Output:
```text
  #     Display Name                    Email Address                        Account ID
  ----  ------------------------------  -----------------------------------  ----------------------------------------
  1     pagoti dharmateja               pagotidharmateja000@gmail.com        712020:8104d0f4-4513-498e-a474-954999d59be2  [ACTIVE]
```

### Environment Configuration for Assignment:
```env
JIRA_CRITICAL_ASSIGNEE_ACCOUNT_ID=712020:8104d0f4-4513-498e-a474-954999d59be2
JIRA_HIGH_ASSIGNEE_ACCOUNT_ID=712020:8104d0f4-4513-498e-a474-954999d59be2
JIRA_MEDIUM_ASSIGNEE_ACCOUNT_ID=712020:8104d0f4-4513-498e-a474-954999d59be2
JIRA_LOW_ASSIGNEE_ACCOUNT_ID=712020:8104d0f4-4513-498e-a474-954999d59be2
```

### Running the Full 34-Test Suite:
```bash
pytest tests/test_jira.py -v
```
All 22 Day 1 tests and 12 Day 2 tests pass (34/34).

---

## 12. Week 4 Day 3: Slack Webhook Integration (Task 1)

Week 4 Day 3 Task 1 establishes a secure, TLS-enforced Slack communication channel for ZAALIMA using Slack Incoming Webhooks.

### 1. Slack App Creation Instructions
1. Navigate to the **[Slack API App Management Console](https://api.slack.com/apps)** in your browser.
2. Sign in to your target Slack workspace.
3. Click the **Create New App** button.
4. Select **From scratch** in the modal dialog.
5. In the **App Name** field, enter: `ZAALIMA Incident Orchestrator`.
6. Select your target Slack development or SOC workspace from the **Pick a workspace to develop your app in** dropdown.
7. Click **Create App**.

### 2. Incoming Webhook Configuration Steps
1. In the app settings sidebar under **Features**, select **Incoming Webhooks**.
2. Toggle the **Activate Incoming Webhooks** switch from `Off` to `On`.
3. Scroll down to the bottom of the page and click **Add New Webhook to Workspace**.
4. In the authorization dialog, choose the SOC notification channel (e.g., `#soc-alerts`, `#incidents`, or `#zaalima-notifications`) where incident notifications should be posted.
5. Click **Allow** to authorize the webhook.
6. Under **Webhook URLs for Your Workspace**, locate the generated webhook URL.
7. Click **Copy** to copy the complete HTTPS webhook URL.
   * Format: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`

### 3. Environment Variable Setup
Add the copied webhook URL to your local `.env` file (never commit `.env` to Git):

```env
# ── Slack Incoming Webhook Integration ─────────────────────────────────────────
# Slack Incoming Webhook URL (must use HTTPS):
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

# Optional channel override (if supported by your Slack app):
SLACK_CHANNEL=#soc-alerts

# Network timeout in seconds for Slack notifications (default: 10):
SLACK_TIMEOUT_SECONDS=10
```

### 4. How to Execute the Slack Test
Run the isolated test notification command:

```bash
python -m backend.main --slack-test
```

> **Note**: This command validates the webhook configuration, verifies HTTPS connectivity, and delivers a standardized test notification. It is strictly isolated and will NOT trigger ransomware containment or create Jira incident tickets.

### 5. Expected Successful Output
```text
================================================================================
      ZAALIMA - Automated Ransomware Containment & Incident Response Orchestrator
               Week 4 Day 3: Slack Webhook Integration Test                     
================================================================================

[+] Step 1: Validating Slack Webhook Configuration...
    Webhook Target: https://hooks.slack.com/services/...****
    Timeout:        10s
    SSL Verify:     True
  [OK] Slack Webhook configuration validated successfully.

[+] Step 2: Sending test notification to Slack channel...

================================================================================
                     SLACK NOTIFICATION TEST RESULT                            
================================================================================
  Status:       SUCCESS
  Target:       https://hooks.slack.com/services/...****
  HTTP Status:  200
  Message:      ZAALIMA is successfully connected to the SOC Slack channel.
  Response:     ok
================================================================================

[OK] Slack notification test completed successfully.
```

**Message Posted in Slack Channel:**
```text
ZAALIMA Slack Integration Test

Status: SUCCESS

Message: ZAALIMA is successfully connected to the SOC Slack channel.

Purpose: Verify that the orchestrator can send notifications to Slack.
```

### 6. Troubleshooting Instructions

| Error / Symptom | Possible Cause | Solution |
|---|---|---|
| `[FAIL] Slack Webhook is not properly configured. Reason: SLACK_WEBHOOK_URL is not set` | Missing variable in `.env` or system environment. | Open `.env` and add `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...`. |
| `Insecure protocol detected: 'http'` | Webhook URL starts with `http://` instead of `https://`. | Change the URL scheme to `https://`. Slack strictly requires TLS. |
| `Placeholder detected in SLACK_WEBHOOK_URL` | Placeholder value like `YOUR/WEBHOOK/URL` is still present. | Replace the placeholder with the real URL generated in the Slack console. |
| `HTTP 403: invalid_token` or `action_prohibited` | Webhook URL token was revoked, workspace app uninstalled, or permissions removed. | Re-generate the incoming webhook in your Slack App console. |
| `HTTP 404: channel_not_found` or `no_team` | Channel was deleted/archived, or team ID in webhook is invalid. | Verify channel exists and re-authorize the webhook for an active channel. |
| `Connection timed out after 10 seconds` | Corporate firewall or proxy blocking outbound HTTPS traffic to `hooks.slack.com`. | Check outbound HTTPS proxy settings or increase `SLACK_TIMEOUT_SECONDS=30`. |

### 7. Running Slack Unit Tests
Run the mocked test suite (no live messages sent):

```bash
pytest tests/test_slack.py -v
```
All 18 automated unit tests pass.



