# Observable Incident Agent

A small HTTPS-ready FastAPI incident agent for the "Observable Incident Triage" challenge.

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

Health check:

```text
GET http://localhost:8000/health
```

## Challenge flow

1. Send an incident to `POST /check`.
2. The agent selects the minimum relevant diagnostic.
3. It diagnoses before selecting a response.
4. If resource saturation is diagnosed, scaling requires approval.
5. If the service is already at its permitted scaling limit, the agent pages the owner rather than scaling.
6. Unknown/ambiguous cases do not trigger automated remediation.
7. Send the observed diagnosis, actual action result, and matching telemetry to `POST /save`.
8. The last check is reserved for Save.

## Example check

```json
{
  "incident": {
    "service": "checkout-api",
    "symptom": "CPU saturation and rising latency",
    "severity": "high",
    "current_scale": 3,
    "scaling_limit": 5,
    "requested_scale": 4,
    "approved": true
  }
}
```

The response contains:

- diagnosis
- permitted response
- check number
- timestamp

## Important

The challenge screenshot does not expose the actual grader's API contract. Therefore this project uses a clean, conventional `/check` + `/save` contract. If the assignment page contains a more specific contract, its exact endpoint names and JSON fields must replace these generic ones before submission.
