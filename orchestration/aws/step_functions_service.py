"""
step_functions_service.py - AWS Step Functions Execution Service.

Coordinates incident response workflows via AWS Step Functions when configured,
or executes via the local Python orchestrator as a seamless fallback.
"""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("orchestrator.aws.step_functions")


class StepFunctionsService:
    """Manages execution of the Ransomware Containment Step Functions State Machine."""

    def __init__(self):
        self.state_machine_arn = os.environ.get("AWS_STEP_FUNCTIONS_ARN", "").strip()
        self.aws_region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self._client = None

    @property
    def is_configured(self) -> bool:
        has_key = bool(os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"))
        return bool(has_key and self.state_machine_arn)

    def _get_boto3_client(self):
        if not self.is_configured:
            return None
        if self._client is None:
            import boto3
            self._client = boto3.client("stepfunctions", region_name=self.aws_region)
        return self._client

    def start_workflow_execution(self, alert_payload: Dict[str, Any], execution_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Triggers execution on AWS Step Functions if configured,
        or delegates to local Python orchestrator as fallback.
        """
        if self.is_configured:
            client = self._get_boto3_client()
            name = execution_name or f"IR-{alert_payload.get('alert_id', 'ALERT')}-{int(datetime.now(timezone.utc).timestamp())}"
            try:
                logger.info("Triggering AWS Step Functions execution '%s' on %s...", name, self.state_machine_arn)
                resp = client.start_execution(
                    stateMachineArn=self.state_machine_arn,
                    name=name,
                    input=json.dumps(alert_payload),
                )
                return {
                    "success": True,
                    "execution_mode": "AWS_STEP_FUNCTIONS",
                    "execution_arn": resp.get("executionArn"),
                    "start_date": resp.get("startDate", "").isoformat() if hasattr(resp.get("startDate"), "isoformat") else str(resp.get("startDate")),
                    "message": f"AWS Step Functions execution initiated: {name}",
                }
            except Exception as exc:
                logger.error("AWS Step Functions dispatch failed: %s. Falling back to local orchestrator.", exc)

        # Fallback to local Python orchestrator
        from containment.incident_orchestrator import execute_full_incident_response_workflow
        local_result = execute_full_incident_response_workflow(alert=alert_payload)
        return {
            "success": True,
            "execution_mode": "LOCAL_PYTHON_FALLBACK",
            "message": "Executed via local Python state machine orchestrator.",
            "workflow_result": local_result,
        }
