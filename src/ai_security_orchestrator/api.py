"""
FastAPI Application for AI Security Orchestrator
Provides REST API for security checks with request timeout and optional cache.
"""
import asyncio
import logging
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .core.orchestrator import DynamicSecurityOrchestrator, DEFAULT_CHECK_TIMEOUT_MS
from .monitors.agent_monitor import AgentMonitor

logger = logging.getLogger(__name__)

DEFAULT_REQUEST_TIMEOUT_SEC = DEFAULT_CHECK_TIMEOUT_MS / 1000.0 + 1.0  # Slightly above orchestrator timeout


class SecurityCheckRequest(BaseModel):
    """Security check request model"""
    input: str
    agent_id: str = 'default'
    response: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class FeedbackRequest(BaseModel):
    """Learning feedback request"""
    input: str
    was_threat: bool
    threat_type: str


def create_app(
    redis_url: Optional[str] = None,
    enable_distributed: bool = False,
    enable_learning: bool = True,
    request_timeout_sec: float = DEFAULT_REQUEST_TIMEOUT_SEC,
) -> FastAPI:
    """Create FastAPI application with optional request timeout."""
    app = FastAPI(
        title="AI Security Orchestrator",
        version="2.0.0",
        description="Enterprise-grade dynamic AI security",
    )
    orchestrator = DynamicSecurityOrchestrator(
        redis_url=redis_url,
        enable_distributed=enable_distributed,
        enable_learning=enable_learning,
    )
    logger.info("AI Security Orchestrator initialized")

    @app.post("/check")
    async def check_security(request: SecurityCheckRequest):
        """Security check with bounded latency (timeout)."""
        try:
            result = await asyncio.wait_for(
                orchestrator.check_async(
                    input_text=request.input,
                    agent_id=request.agent_id,
                    response=request.response,
                    context=request.context,
                ),
                timeout=request_timeout_sec,
            )
            return JSONResponse(content=result)
        except asyncio.TimeoutError:
            logger.warning("Request timeout after %.1fs", request_timeout_sec)
            raise HTTPException(status_code=504, detail="Security check timeout")
        except Exception as e:
            logger.error("Error in security check: %s", e, exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/feedback")
    async def submit_feedback(request: FeedbackRequest):
        """
        Submit feedback for learning

        Helps the system learn from corrections and improve detection
        """
        if not orchestrator.enable_learning:
            return {"message": "Learning is disabled"}

        orchestrator._lazy_load_components()
        orchestrator._detectors.learn_from_feedback(
            input_text=request.input,
            was_threat=request.was_threat,
            threat_type=request.threat_type
        )

        return {"message": "Feedback received", "learning_enabled": True}

    @app.get("/metrics")
    async def get_metrics():
        """Get system metrics"""
        metrics = orchestrator.get_metrics()
        return metrics

    @app.get("/agent/{agent_id}/history")
    async def get_agent_history(agent_id: str, limit: int = 100):
        """Get action history for specific agent"""
        history = orchestrator.get_agent_history(agent_id, limit)
        return {"agent_id": agent_id, "history": history}

    @app.get("/agent/{agent_id}/status")
    async def get_agent_status(agent_id: str):
        """Get current agent status"""
        orchestrator._lazy_load_components()
        status = orchestrator._agent_monitor.get_agent_status(agent_id)
        return status

    @app.get("/agents/compromised")
    async def get_compromised_agents():
        """Get list of compromised agents"""
        orchestrator._lazy_load_components()
        compromised = orchestrator._agent_monitor.get_compromised_agents()
        return {"compromised_agents": compromised}

    @app.get("/failures")
    async def get_failures(limit: int = 50):
        """Get recent failures and recoveries"""
        failures = orchestrator.get_failure_history(limit)
        return {"failures": failures}

    @app.get("/routing/history")
    async def get_routing_history(limit: int = 50):
        """Get routing decisions"""
        orchestrator._lazy_load_components()
        history = orchestrator._router.get_routing_history(limit)
        return {"routing_history": history}

    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "version": "2.0.0",
            "distributed": orchestrator.enable_distributed,
            "learning": orchestrator.enable_learning
        }

    @app.on_event("shutdown")
    async def shutdown_event():
        """Graceful shutdown"""
        logger.info("Shutting down...")
        await orchestrator.shutdown()

    return app
