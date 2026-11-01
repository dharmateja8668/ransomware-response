import requests
import time

BASE = "http://127.0.0.1:8000"

# 1. Login
r_auth = requests.post(f"{BASE}/api/auth/login", data={"username": "admin", "password": "Admin@123!"})
assert r_auth.status_code == 200, f"Login failed: {r_auth.text}"
token = r_auth.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

print("=== TEST 1: CrowdStrike Status API ===")
r_status = requests.get(f"{BASE}/api/crowdstrike/status", headers=headers)
print("HTTP Status:", r_status.status_code)
status_data = r_status.json()
print("Status:", status_data.get("status"))
print("Configured:", status_data.get("configured"))
print("Masked Client ID:", status_data.get("client_id"))
print("Base URL:", status_data.get("base_url"))
print("Enrolled Hosts Count:", status_data.get("enrolled_hosts_count"))
print("Alerts Count:", status_data.get("alerts_count"))
print("Permissions Verified:", status_data.get("permissions"))
assert status_data.get("status") == "CONNECTED"

print("\n=== TEST 2: Real CrowdStrike Devices API ===")
r_dev = requests.get(f"{BASE}/api/crowdstrike/devices", headers=headers)
print("HTTP Status:", r_dev.status_code)
dev_res = r_dev.json()
print("Source:", dev_res.get("source"), "| Total Devices:", dev_res.get("count"))
for d in dev_res.get("devices", []):
    print("  Hostname:", d.get("hostname"), "| Device ID:", d.get("device_id"), "| IP:", d.get("ip_address"), "| Status:", d.get("status"))
assert dev_res.get("count", 0) > 0

print("\n=== TEST 3: Real CrowdStrike Alerts API ===")
r_alt = requests.get(f"{BASE}/api/crowdstrike/alerts", headers=headers)
print("HTTP Status:", r_alt.status_code)
alt_res = r_alt.json()
print("Source:", alt_res.get("source"), "| Total Alerts:", alt_res.get("count"))
for a in alt_res.get("alerts", []):
    print("  ID:", str(a.get("threat_id"))[:45] + "...", "| Name:", a.get("threat_name"), "| Sev:", a.get("severity"), "| Host:", a.get("hostname"))
assert alt_res.get("count", 0) > 0

print("\n=== TEST 4: Threat Detection Table (CrowdStrike vs Simulated) ===")
r_cs_threats = requests.get(f"{BASE}/api/threats/?source=CROWDSTRIKE", headers=headers)
print("Real CrowdStrike threats in DB:", r_cs_threats.json().get("total"))
r_all_threats = requests.get(f"{BASE}/api/threats/", headers=headers)
print("All threats in DB (CrowdStrike + Simulated):", r_all_threats.json().get("total"))
assert r_cs_threats.json().get("total", 0) >= 4

print("\n=== TEST 5: Endpoint Management Table (Enrolled CrowdStrike Device) ===")
r_eps = requests.get(f"{BASE}/api/endpoints/", headers=headers)
cs_eps = [e for e in r_eps.json().get("items", []) if e.get("edr_provider") == "CROWDSTRIKE"]
print("CrowdStrike endpoints found in ZAALIMA inventory:", len(cs_eps))
for e in cs_eps:
    print("  Host:", e.get("hostname"), "| Device ID:", e.get("edr_agent_id"), "| Provider:", e.get("edr_provider"), "| Status:", e.get("status"))
assert len(cs_eps) >= 1

print("\n=== TEST 6: Playbook Execution with Enrolled CrowdStrike Host ===")
r_pb = requests.post(f"{BASE}/api/playbooks/execute", json={
    "incident_id": "INC-20261101-CROWDSTRIKE",
    "hostname": "DHARMATEJA",
    "triggered_by": "admin"
}, headers=headers)
print("Playbook execution status:", r_pb.status_code)
ex_id = r_pb.json()["execution_id"]
time.sleep(13)
r_ex = requests.get(f"{BASE}/api/playbooks/{ex_id}", headers=headers)
ex_data = r_ex.json()
print("Playbook final status:", ex_data.get("status"))
for s in ex_data.get("steps", []):
    print("  Step:", s.get("name"), f"[{s.get('status')}]", "->", s.get("result"))
assert ex_data.get("status") == "completed"

print("\n=== TEST 7: Audit Trail Verification ===")
r_aud = requests.get(f"{BASE}/api/audit/", headers=headers)
print("Total audit logs recorded:", r_aud.json().get("total"))
print("Most recent audit action:", r_aud.json().get("items", [])[0].get("action"))
print("Most recent audit detail:", r_aud.json().get("items", [])[0].get("details"))

print("\n>>> ALL REAL CROWDSTRIKE INTEGRATION TESTS PASSED 100% <<<")
