# main.py
"""
FastAPI backend for the “Automated Ransomware Containment & Incident Response Orchestrator”.

This file contains:
  1. A health‑check GET endpoint.
  2. A Pydantic model that describes the shape of an incoming alert.
  3. A POST endpoint that receives a simulated alert, validates it, and returns a JSON response.
"""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Automated Ransomware Containment & Incident Response Orchestrator"
)

@app.get("/health")
def health_check() -> dict:
    """Health‑check endpoint returning a simple JSON payload."""
    return {"status": "ok", "message": "Server is running"}

class Alert(BaseModel):
    alert_id: str
    threat_type: str
    severity: int
    description: str
    timestamp: str

@app.post("/alert")
def receive_alert(alert: Alert) -> dict:
    """Receive a simulated alert, validate it, and echo a confirmation JSON."""
    return {
        "status": "received",
        "alert_id": alert.alert_id,
        "message": f"Alert of type '{alert.threat_type}' recorded."
    }
