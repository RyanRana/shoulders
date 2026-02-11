"""
AI Security Orchestrator - Enterprise Edition
Dynamic, scalable security orchestration for AI systems of any size

Features:
- Dynamic threat pattern learning
- Real-time agent action monitoring
- Automatic rerouting on failure detection
- Distributed monitoring for large-scale systems
- Zero-hardcoding: adapts to new attack vectors
- Production-ready with observability
"""

__version__ = "2.0.0"
__author__ = "Security Team"

from .core.orchestrator import DynamicSecurityOrchestrator
from .monitors.agent_monitor import AgentMonitor, AgentActionLogger
from .detectors.dynamic_detector import DynamicThreatDetector
from .core.router import DynamicRouter, FailureRecovery

__all__ = [
    "DynamicSecurityOrchestrator",
    "AgentMonitor",
    "AgentActionLogger",
    "DynamicThreatDetector",
    "DynamicRouter",
    "FailureRecovery",
]
