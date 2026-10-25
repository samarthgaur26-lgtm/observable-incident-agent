from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid

app = FastAPI(title="Observable Incident Agent", version="1.0.0")

# In-memory state is sufficient for a challenge/demo.
# Replace with PostgreSQL/Redis in production.
STATE = {
    "incidents": {},
    "checks_used": 0,
    "max_checks": 10,
    "last_save": None,
}

class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service: str
    symptom: str = ""
    severity: str = "unknown"
    scaling_limit: Optional[int] = None
    current_scale: Optional[int] = None
    requested_scale: Optional[int] = None
    approved: bool = False
    metadata: Dict[str, Any] = {}

class CheckRequest(BaseModel):
    incident: Incident
    diagnostic: Optional[str] = None

class SaveRequest(BaseModel):
    incident_id: str
    action: Dict[str, Any]
    telemetry: Dict[str, Any]
    diagnosis: Dict[str, Any]

def now():
    return datetime.now(timezone.utc).isoformat()

def diagnose(incident: Incident) -> Dict[str, Any]:
    text = f"{incident.symptom} {incident.metadata}".lower()

    # Run the minimum diagnostic implied by the observed symptom.
    if any(x in text for x in ["latency", "slow", "timeout", "5xx", "error"]):
        diagnostic = "service_health"
        cause = "service_health_degradation"
    elif any(x in text for x in ["cpu", "memory", "load", "capacity", "saturation"]):
        diagnostic = "resource_saturation"
        cause = "resource_saturation"
    elif any(x in text for x in ["deploy", "deployment", "release", "version"]):
        diagnostic = "deployment_regression"
        cause = "deployment_regression"
    else:
        diagnostic = "service_health"
        cause = "unknown"

    return {
        "diagnostic": diagnostic,
        "cause": cause,
        "confidence": 0.8 if cause != "unknown" else 0.3,
        "observed_at": now(),
    }

def choose_action(incident: Incident, diagnosis: Dict[str, Any]) -> Dict[str, Any]:
    # Safety rule: if already at the permitted scaling limit, do not scale.
    if (
        incident.scaling_limit is not None
        and incident.current_scale is not None
        and incident.current_scale >= incident.scaling_limit
    ):
        return {
            "type": "page_owner",
            "status": "selected",
            "reason": "service is already at permitted scaling limit",
            "requires_approval": False,
        }

    # Scale only when capacity/resource saturation is actually diagnosed.
    if diagnosis["cause"] == "resource_saturation":
        if not incident.approved:
            return {
                "type": "scale",
                "status": "approval_required",
                "reason": "scaling is a real action and approval has not been supplied",
                "requires_approval": True,
            }

        target = incident.requested_scale
        if target is None and incident.current_scale is not None:
            target = incident.current_scale + 1

        if (
            incident.scaling_limit is not None
            and target is not None
            and target > incident.scaling_limit
        ):
            return {
                "type": "page_owner",
                "status": "selected",
                "reason": "requested scale exceeds permitted scaling limit",
                "requires_approval": False,
            }

        return {
            "type": "scale",
            "status": "approved",
            "target_scale": target,
            "requires_approval": False,
        }

    # Unknown/ambiguous incidents should not trigger destructive actions.
    if diagnosis["cause"] == "unknown":
        return {
            "type": "page_owner",
            "status": "selected",
            "reason": "insufficient evidence for an automated remediation",
            "requires_approval": False,
        }

    return {
        "type": "no_action",
        "status": "selected",
        "reason": "diagnosed condition does not justify an automated remediation",
        "requires_approval": False,
    }

def consume_check():
    if STATE["checks_used"] >= STATE["max_checks"]:
        raise HTTPException(status_code=429, detail="diagnostic check limit exhausted")
    # Preserve one check for Save.
    if STATE["checks_used"] >= STATE["max_checks"] - 1:
        raise HTTPException(
            status_code=429,
            detail="last check is reserved for Save"
        )
    STATE["checks_used"] += 1

@app.get("/")
def root():
    return {
        "service": "observable-incident-agent",
        "status": "ok",
        "checks_remaining_before_save": max(
            0, STATE["max_checks"] - STATE["checks_used"] - 1
        ),
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/check")
def check(req: CheckRequest):
    consume_check()

    diagnosis = diagnose(req.incident)
    action = choose_action(req.incident, diagnosis)

    result = {
        "incident_id": req.incident.incident_id,
        "diagnosis": diagnosis,
        "permitted_response": action,
        "check_number": STATE["checks_used"],
        "timestamp": now(),
    }

    STATE["incidents"][req.incident.incident_id] = result
    return result

@app.post("/save")
def save(req: SaveRequest):
    # The final Save is intentionally not counted by consume_check().
    if STATE["checks_used"] >= STATE["max_checks"]:
        raise HTTPException(status_code=429, detail="no Save capacity remains")

    if req.incident_id not in STATE["incidents"]:
        raise HTTPException(
            status_code=400,
            detail="incident must be checked before it can be saved"
        )

    stored = {
        "incident_id": req.incident_id,
        "diagnosis": req.diagnosis,
        "action": req.action,
        "telemetry": req.telemetry,
        "saved_at": now(),
    }

    # Matching telemetry is stored together with the real action result.
    STATE["last_save"] = stored
    STATE["incidents"][req.incident_id]["saved"] = stored
    STATE["checks_used"] += 1

    return {
        "status": "saved",
        "incident_id": req.incident_id,
        "check_number": STATE["checks_used"],
        "record": stored,
    }

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    record = STATE["incidents"].get(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="incident not found")
    return record
