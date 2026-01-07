"""
app.py - FastAPI adapter for PDP

This is a thin wrapper over pdp/core.py. All real logic lives in core.py.
FastAPI just handles HTTP transport.

Endpoints:
  Evaluation:
    - POST /v1/evaluate - Evaluate an HttpEvent, return PolicyDecision

  Task Policy:
    - PUT /v1/tasks/{task_id}/policy - Upsert task policy
    - GET /v1/tasks/{task_id}/policy - Get task policy
    - DELETE /v1/tasks/{task_id} - Delete task policy

  Baseline Policy:
    - GET /v1/baseline - Get current baseline policy
    - PUT /v1/baseline - Update baseline policy

  Credential Approvals:
    - POST /v1/approvals/credentials - Add credential approval

  Budgets:
    - GET /v1/budgets - Get budget usage statistics
    - POST /v1/budgets/reset - Reset budget counters

  Health/Stats:
    - GET /health - Health check
    - GET /stats - PDP statistics

Usage:
    uvicorn pdp.app:app --host 0.0.0.0 --port 8080

    # Or with Unix socket (for reduced latency):
    uvicorn pdp.app:app --uds /tmp/pdp.sock
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .core import _sanitize_for_log, get_pdp, reset_pdp
from .schemas import HttpEvent, PolicyDecision

log = logging.getLogger("safeyolo.pdp.app")


# =============================================================================
# Lifespan (startup/shutdown)
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage PDP lifecycle."""
    # Startup: Initialize PDPCore
    baseline_path = os.environ.get("PDP_BASELINE_PATH")
    budget_path = os.environ.get("PDP_BUDGET_STATE_PATH")

    get_pdp(
        baseline_path=Path(baseline_path) if baseline_path else None,
        budget_state_path=Path(budget_path) if budget_path else None,
    )
    log.info("PDP started", extra={"baseline_path": baseline_path})

    yield

    # Shutdown: Flush state
    log.info("PDP shutting down")
    reset_pdp()


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="SafeYolo PDP",
    description="Policy Decision Point for SafeYolo egress control",
    version="0.1.0",
    lifespan=lifespan,
)


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors with proper logging."""
    log.error(f"Unhandled exception: {type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "error_code": "INTERNAL_ERROR",
            "message": str(exc),
        },
    )


# =============================================================================
# Endpoints
# =============================================================================

@app.post("/v1/evaluate", response_model=PolicyDecision)
async def evaluate(event: HttpEvent) -> PolicyDecision:
    """
    Evaluate an HTTP event against policy.

    This is the primary endpoint. Sensors POST HttpEvent, receive PolicyDecision.

    The decision includes:
    - effect: allow, deny, require_approval, budget_exceeded, error
    - reason: Human-readable explanation
    - reason_codes: Stable codes for filtering/metrics
    - budget: Rate limit info (if applicable)
    - immediate_response: Pre-built HTTP response for non-allow decisions
    """
    pdp = get_pdp()
    try:
        decision = pdp.evaluate(event)
        log.debug(
            "Evaluated",
            extra={
                "event_id": _sanitize_for_log(event.event.event_id),
                "effect": decision.effect.value,
            }
        )
        return decision
    except Exception as e:
        log.error(f"Evaluation failed: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="Evaluation failed")


@app.put("/v1/tasks/{task_id}/policy")
async def upsert_task_policy(task_id: str, policy: dict[str, Any]) -> dict:
    """
    Upsert a task-scoped policy.

    Task policies extend the baseline for a specific task/session.
    They are stored in memory and applied when HttpEvent.context.task_id matches.

    Returns:
        Status with task_id and permission count
    """
    pdp = get_pdp()
    result = pdp.upsert_task_policy(task_id, policy)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/v1/tasks/{task_id}/policy")
async def get_task_policy(task_id: str) -> dict:
    """
    Get a task policy by ID.

    Returns:
        The policy data, or 404 if not found
    """
    pdp = get_pdp()
    policy = pdp.get_task_policy(task_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Task policy not found: {task_id}")
    return policy


@app.delete("/v1/tasks/{task_id}")
async def delete_task_policy(task_id: str) -> dict:
    """
    Delete a task policy.

    Returns:
        Status with task_id
    """
    pdp = get_pdp()
    result = pdp.delete_task_policy(task_id)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=f"Task policy not found: {task_id}")
    return result


@app.get("/health")
async def health() -> dict:
    """
    Health check endpoint.

    Returns 200 if PDP is operational.
    Used by load balancers and HttpPolicyClient.
    """
    return {"status": "healthy", "service": "pdp"}


@app.get("/stats")
async def stats() -> dict:
    """
    Get PDP statistics.

    Returns engine version, policy hash, evaluation counts, etc.
    Useful for debugging and monitoring.
    """
    pdp = get_pdp()
    return pdp.get_stats()


# =============================================================================
# Baseline Policy Endpoints
# =============================================================================

@app.get("/v1/baseline")
async def get_baseline() -> dict:
    """
    Get the current baseline policy.

    Returns:
        The baseline policy document, or 404 if not loaded.
    """
    pdp = get_pdp()
    baseline = pdp.get_baseline()
    if baseline is None:
        raise HTTPException(status_code=404, detail="No baseline policy loaded")
    return {
        "baseline": baseline,
        "path": pdp.get_baseline_path(),
    }


@app.put("/v1/baseline")
async def update_baseline(request: Request) -> dict:
    """
    Update the baseline policy.

    Accepts a policy document and updates the current baseline.
    This persists the policy if a baseline path is configured.

    Body:
        {"policy": { ... policy document ... }}

    Returns:
        Status with permission count
    """
    pdp = get_pdp()
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    policy_data = body.get("policy")
    if policy_data is None:
        raise HTTPException(status_code=400, detail="Missing 'policy' field in request body")

    result = pdp.update_baseline(policy_data)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


# =============================================================================
# Credential Approval Endpoints
# =============================================================================

@app.post("/v1/approvals/credentials")
async def add_credential_approval(request: Request) -> dict:
    """
    Add a credential approval to the baseline.

    This allows a credential (by type or HMAC fingerprint) to access
    a destination. Use this to unblock agents when they hit a
    credential-destination mismatch.

    Body:
        {
            "destination": "api.example.com/*",
            "credential": "openai:*" or "hmac:abc123",
            "tier": "explicit" (optional)
        }

    Returns:
        Status with approval details
    """
    pdp = get_pdp()
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    destination = body.get("destination")
    credential = body.get("credential")
    tier = body.get("tier", "explicit")

    if not destination:
        raise HTTPException(status_code=400, detail="Missing 'destination' field")
    if not credential:
        raise HTTPException(status_code=400, detail="Missing 'credential' field")

    result = pdp.add_credential_approval(
        destination=destination,
        credential=credential,
        tier=tier,
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


# =============================================================================
# Budget Endpoints
# =============================================================================

@app.get("/v1/budgets")
async def get_budgets() -> dict:
    """
    Get current budget usage statistics.

    Returns:
        Dict with tracked keys and their current states
    """
    pdp = get_pdp()
    return pdp.get_budget_stats()


@app.post("/v1/budgets/reset")
async def reset_budgets(request: Request) -> dict:
    """
    Reset budget counters.

    Body (optional):
        {"resource": "pattern"} - Reset specific resource
        {} or no body - Reset all budgets

    Returns:
        Status with reset count
    """
    pdp = get_pdp()
    try:
        body = await request.json()
    except Exception:
        body = {}

    resource = body.get("resource") if body else None
    result = pdp.reset_budgets(resource=resource)

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


# =============================================================================
# Development Server
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Run with uvicorn
    uvicorn.run(
        "pdp.app:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
    )
