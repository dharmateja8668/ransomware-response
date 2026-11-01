import sys
sys.path.append("d:/ransomware response/zaalima/backend")
from app.core.config import get_settings
import requests
import base64

def check_jira():
    s = get_settings()
    auth = base64.b64encode(f"{s.jira_email}:{s.jira_api_token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    
    # 1. Projects
    resp = requests.get(f"{s.jira_base_url}/rest/api/3/project", headers=headers, timeout=10)
    print("Projects status:", resp.status_code)
    projects = resp.json()
    for p in projects:
        print(f"Project: Key={p.get('key')}, Name={p.get('name')}, Id={p.get('id')}")
        
    # 2. Issue types in SEC project
    sec_key = s.jira_project_key
    print(f"Checking project {sec_key} issue types...")
    resp_meta = requests.get(f"{s.jira_base_url}/rest/api/3/issue/createmeta?projectKeys={sec_key}", headers=headers, timeout=10)
    if resp_meta.status_code == 200:
        meta = resp_meta.json()
        for p in meta.get("projects", []):
            types = [t.get("name") for t in p.get("issuetypes", [])]
            print(f"Available Issue Types in {sec_key}: {types}")
    else:
        print("CreateMeta status:", resp_meta.status_code)

if __name__ == "__main__":
    check_jira()

