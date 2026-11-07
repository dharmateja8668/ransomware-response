# Final Demonstration Guide

## Automated Ransomware Containment & Incident Response Orchestrator
**Week 4 Day 5: Final Demonstration & Verification Walkthrough**

---

## 1. Overview and Demonstration Purpose

This guide provides a step-by-step, reproducible walkthrough for demonstrating the **Automated Ransomware Containment & Incident Response Orchestrator** to SOC leads, security engineers, and stakeholders.

The demonstration walks through the complete end-to-end incident response lifecycle:
- Ingestion of suspicious telemetry.
- Telemetry validation and sanitization.
- Automated creation of Jira Cloud incident tickets.
- Severity-based SOC analyst assignment routing.
- Real-time Slack channel notification dispatch.
- Audit trail serialization and secret masking.
- Performance evaluation benchmarking.
- Comprehensive security controls.

### Mode Clarification: Mocked vs Live Integration

| Component | Default Mocked Mode (`--simulate-ransomware`) | Live Integration Mode (`--live-simulation`) |
|---|---|---|
| **Incident Telemetry** | Synthetic canary tripwire & process data | Synthetic canary tripwire & process data |
| **Telemetry Validation** | Real strict regex, hash, IP validation | Real strict regex, hash, IP validation |
| **Jira Cloud API** | Fast in-memory simulated adapter | Real HTTPS REST call to Jira Cloud instance |
| **Analyst Assignment** | Role mapped based on severity table | Real Jira API assignment (`PUT /assignee`) |
| **Slack Webhook API** | In-memory simulated webhook receiver | Real HTTPS POST to Slack Incoming Webhook |
| **Report Generation** | Real JSON written to `reports/simulations/` | Real JSON written to `reports/simulations/` |
| **Safety Guarantee** | 100% safe, non-destructive, zero API calls | 100% safe, non-destructive, creates 1 ticket & 1 Slack post |

---

## 2. Step-by-Step Demonstration Procedure

### Step 1: Start the Backend and Verify System Health

Before processing threat alerts, verify that the environment is configured and all services are responsive.

```bash
# 1. Activate the virtual environment
.\venv\Scripts\activate   # Windows PowerShell / CMD
# source venv/bin/activate  # Linux / macOS

# 2. Verify FastAPI web backend health (optional background server)
uvicorn main:app --host 127.0.0.1 --port 8000
```

Verify service connectivity in a separate terminal:
```bash
# Health check endpoint
curl -X GET http://127.0.0.1:8000/health
```

**Expected Output:**
```json
{"status": "healthy", "service": "ransomware-response-orchestrator", "version": "1.0.0"}
```

---

### Step 2: Run a Simulated CRITICAL Ransomware Incident

Execute the safe end-to-end incident response workflow for a `CRITICAL` severity threat:

```bash
python -m backend.main --simulate-ransomware --severity CRITICAL
```

**What Happens Under the Hood:**
1. Generates realistic, non-destructive canary alert telemetry (`INC-2026-001`).
2. Targets simulated workstation `TEST-WORKSTATION-01` (`192.168.56.101`).
3. Emulates ransomware indicators: tripwire activated, volume shadow copies deleted, encrypted file rename heuristics.
4. Executes pure in-memory simulation with zero outbound network calls.

---

### Step 3: Show Incident Telemetry Validation

Point out the validation step in the terminal output:

```
[INFO] Stage 3: Incident [INC-2026-001] validated successfully.
```

Explain the validation safeguards:
- **Hostname Sanitization:** Strict RFC 1123 hostname syntax; command injection characters (`;`, `|`, `&`, `$`) are rejected.
- **IP Address Validation:** Validates standard IPv4/IPv6 format using Python's `ipaddress` library.
- **Cryptographic Hash Validation:** Verifies hexadecimal SHA-256 character lengths (64 hex characters) and normalizes to lowercase.
- **Fail-Fast Defense:** If telemetry is malformed or invalid, the incident response workflow halts immediately to prevent corrupting Jira tickets or spamming Slack channels.

---

### Step 4: Show Jira Ticket Creation

Examine the Jira ticket creation section in the terminal output:

```
  Jira Ticket Details:
    Status:      Created
    Ticket ID:   10582
    Ticket Key:  RR-101
    Browse URL:  https://zaalima.atlassian.net/browse/RR-101
    Summary:     [SEC-INCIDENT] Ransomware on TEST-WORKSTATION-01 (CRITICAL)
```

Explain the ticketing features:
- **Standardized Nomenclature:** `[SEC-INCIDENT] <Threat> on <Host> (<Severity>)`.
- **Deduplication:** Repeated alerts for the same hostname check Jira and avoid creating duplicate tickets.
- **Forensic Context:** Ticket descriptions preserve timestamps, affected IPs, user accounts, and process hashes for forensic triage.

---

### Step 5: Show Severity-Based Analyst Auto-Assignment

Examine the SOC routing section in the terminal output:

```
  SOC Analyst Assignment:
    Status:      ASSIGNED
    Assigned:    True
    Role:        Senior SOC Lead / Incident Commander
    Account ID:  sim-...****
    Reason:      Assignment successful (simulated).
```

Explain the priority matrix:
- `CRITICAL` -> **Senior SOC Lead / Incident Commander** (Immediate response required).
- `HIGH` -> **SOC Analyst (Tier 2)** (Active investigation & containment).
- `MEDIUM` -> **Junior SOC Analyst (Tier 1)** (Triage & initial analysis).
- `LOW` -> **Monitoring Analyst** (Observation & telemetry tracking).

---

### Step 6: Show Slack Notification Status

Examine the Slack notification section in the terminal output:

```
  Slack Incident Notification:
    Status:      DELIVERED
    Delivered:   True
    Channel Alert: Alert posted to SOC channel: 🔴 Critical Alert
```

Explain the Slack integration features:
- **Visual Alert Indicators:**
  - 🔴 `Critical Alert` (CRITICAL)
  - 🟠 `High Alert` (HIGH)
  - 🟡 `Medium Alert` (MEDIUM)
  - 🟢 `Low Alert` (LOW)
- **Interactive Block Kit Format:** Formats Jira browse link, host information, assigned analyst, and threat description into rich Slack cards.
- **Fault Isolation Guarantee:** If Slack is misconfigured or encounters an HTTP 500 error, Jira ticket creation and analyst assignment **remain 100% intact**. Slack failures never disrupt core incident handling.

---

### Step 7: Show Generated Simulation Report

Inspect the serialized JSON audit report in `reports/simulations/`:

```bash
# View the most recent simulation report
Get-ChildItem reports/simulations/ | Sort-Object LastWriteTime -Descending | Select-Object -First 1
```

Examine the contents:
```json
{
  "simulation_id": "SIM-E2AB1D8D",
  "incident_id": "INC-2026-001",
  "threat_type": "Ransomware",
  "severity": "CRITICAL",
  "hostname": "TEST-WORKSTATION-01",
  "ip_address": "192.168.56.101",
  "username": "test_user",
  "mode": "MOCKED",
  "incident_validation": {
    "valid": true,
    "status": "VALID",
    "error": null
  },
  "jira_ticket": {
    "status": "Created",
    "ticket_key": "RR-101",
    "ticket_url": "https://zaalima.atlassian.net/browse/RR-101"
  },
  "analyst_assignment": {
    "status": "ASSIGNED",
    "assigned": true,
    "role": "Senior SOC Lead / Incident Commander"
  },
  "slack_notification": {
    "status": "DELIVERED",
    "delivered": true
  },
  "performance_metrics": {
    "detection_validation_seconds": 0.00014,
    "jira_ticket_creation_seconds": 0.00003,
    "analyst_assignment_seconds": 0.00002,
    "slack_notification_seconds": 0.00003,
    "total_response_time_seconds": 0.00022
  },
  "overall_workflow_status": "SUCCESS"
}
```

Point out:
- Secrets, tokens, and webhook URLs are masked using `mask_report_secrets()`.
- Complete timing audit trail is permanently recorded.

---

### Step 8: Show Performance Evaluation Results & Charts

Execute the performance evaluator to demonstrate system benchmarking:

```bash
python -m backend.main --evaluate-performance --iterations 20
```

Show the generated outputs in `reports/performance/`:
1. `performance_summary.json`: Aggregated metrics (Min, Max, Avg, Median, P95, Std Dev).
2. `performance_results.csv`: 80 measured iteration rows.
3. `reliability_analysis.json`: Results of 9 failure scenarios (100% passed).
4. `performance_report.md`: Comprehensive evaluation report.
5. `performance_charts/`: 4 Matplotlib graphical charts:
   - `average_response_time_by_severity.png`
   - `workflow_stage_execution_times.png`
   - `success_rate_vs_failure_rate.png`
   - `response_time_min_avg_max_comparison.png`

---

### Step 9: Explain Security Measures and Safety Guarantees

Conclude the demonstration by highlighting the system's security architecture:
1. **Non-Destructive Simulation:** No real ransomware binaries are executed; no real files are encrypted or altered; no real shadow copies are deleted.
2. **Endpoint Safety:** No production network isolation or Active Directory account suspension is performed during simulations.
3. **Zero Secret Leakage:** `.env` is strictly excluded from Git; API tokens and Slack webhook URLs are masked in console output and JSON reports.
4. **Resilience & Fault Isolation:** Slack downtime or network partitions do not halt ticket creation in Jira.
5. **Deterministic Performance:** In-memory execution completes in < 1 millisecond; production network workflows complete in 400ms – 1,500ms.

---

## 3. Demonstration Script Quick Reference

| Command | Purpose | Expected Result |
|---|---|---|
| `python -m backend.main --simulate-ransomware` | Run CRITICAL ransomware simulation | Full mocked incident response in < 1ms |
| `python -m backend.main --simulate-ransomware --severity HIGH` | Run HIGH severity simulation | Routes to Tier 2 Analyst, 🟠 Slack alert |
| `python -m backend.main --slack-test` | Test Slack webhook connectivity | Sends test message to Slack channel |
| `python -m backend.main --evaluate-performance` | Run 80-iteration benchmark & charts | Generates reports & Matplotlib graphs |
| `pytest` | Run complete regression test suite | 451 passed tests, 0 failures |

