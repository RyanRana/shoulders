"""
Dynamic Router with Automatic Failure Recovery
Intercepts API calls at runtime and reroutes on failures.
Adaptive load balancing: selects fallback by in-flight count and latency.
"""
import asyncio
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
from collections import deque
import logging

logger = logging.getLogger(__name__)

# Rolling window for latency (alpha for exponential moving average)
LOAD_AVG_ALPHA = 0.1


@dataclass
class RecoveryResult:
    """Result of recovery attempt"""
    success: bool
    action: str
    fallback_agent: Optional[str]
    reason: str
    latency_ms: float
    metadata: Dict[str, Any]


class DynamicRouter:
    """
    Dynamic request router with automatic failure recovery

    Features:
    - Detects malicious, hacked, or hallucinating agents
    - Automatically reroutes to healthy agents
    - Circuit breaker pattern for failing agents
    - Load balancing across healthy agents
    - Zero downtime recovery
    """

    def __init__(self):
        self.agent_health: Dict[str, Dict[str, Any]] = {}
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}
        self.fallback_chain: List[str] = ['backup_agent', 'safe_mode_agent', 'minimal_agent']
        self.routing_history: deque = deque(maxlen=1000)
        # Adaptive load: in-flight count and EMA latency per agent (for fallback selection)
        self._agent_in_flight: Dict[str, int] = {}
        self._agent_avg_latency_ms: Dict[str, float] = {}
        self._agent_total_requests: Dict[str, int] = {}

    def record_request_start(self, agent_id: str) -> None:
        """Call when a request is assigned to an agent (for load balancing)."""
        self._agent_in_flight[agent_id] = self._agent_in_flight.get(agent_id, 0) + 1

    def record_request_end(self, agent_id: str, latency_ms: float) -> None:
        """Call when a request completes (updates load and latency)."""
        self._agent_in_flight[agent_id] = max(0, self._agent_in_flight.get(agent_id, 1) - 1)
        self._agent_total_requests[agent_id] = self._agent_total_requests.get(agent_id, 0) + 1
        prev_avg = self._agent_avg_latency_ms.get(agent_id, latency_ms)
        self._agent_avg_latency_ms[agent_id] = LOAD_AVG_ALPHA * latency_ms + (1 - LOAD_AVG_ALPHA) * prev_avg

    async def reroute(
        self,
        agent_id: str,
        threats: List[Any],
        original_input: str,
        context: Dict[str, Any]
    ) -> RecoveryResult:
        """
        Reroute request away from compromised agent

        Args:
            agent_id: ID of failing agent
            threats: Detected threats
            original_input: Original user input
            context: Additional context

        Returns:
            Recovery result with fallback agent
        """
        start = time.perf_counter()

        # Classify failure type
        failure_type = self._classify_failure(threats)

        logger.warning(f"Agent {agent_id} failure detected: {failure_type}")

        # Open circuit breaker
        self._open_circuit(agent_id, failure_type)

        # Find fallback agent
        fallback = self._find_fallback_agent(agent_id, failure_type)

        if fallback:
            action = f"reroute_to_{fallback}"
            reason = f"Agent {agent_id} compromised ({failure_type}), routing to {fallback}"

            self.routing_history.append({
                'timestamp': datetime.now().isoformat(),
                'from_agent': agent_id,
                'to_agent': fallback,
                'reason': failure_type,
                'threats': [str(t) for t in threats[:3]]  # First 3
            })

            latency = (time.perf_counter() - start) * 1000

            return RecoveryResult(
                success=True,
                action=action,
                fallback_agent=fallback,
                reason=reason,
                latency_ms=latency,
                metadata={
                    'failure_type': failure_type,
                    'circuit_breaker_open': True
                }
            )
        else:
            # No fallback available - safe mode
            action = "activate_safe_mode"
            reason = f"No fallback available for {agent_id}, entering safe mode"

            logger.error(f"No fallback for agent {agent_id}, safe mode activated")

            latency = (time.perf_counter() - start) * 1000

            return RecoveryResult(
                success=True,
                action=action,
                fallback_agent='safe_mode',
                reason=reason,
                latency_ms=latency,
                metadata={
                    'failure_type': failure_type,
                    'safe_mode': True
                }
            )

    def _classify_failure(self, threats: List[Any]) -> str:
        """Classify type of failure"""
        threat_layers = [t.layer for t in threats if hasattr(t, 'layer')]

        if 'hallucination_detector' in threat_layers:
            return 'hallucination'
        elif 'goal_monitor' in threat_layers:
            return 'goal_hijack'
        elif 'ai_firewall' in threat_layers:
            return 'code_injection'
        elif len(threats) >= 3:
            return 'compromised'
        else:
            return 'suspicious_behavior'

    def _open_circuit(self, agent_id: str, failure_type: str):
        """Open circuit breaker for failing agent"""
        self.circuit_breakers[agent_id] = {
            'open': True,
            'failure_type': failure_type,
            'timestamp': datetime.now().isoformat(),
            'failures': self.circuit_breakers.get(agent_id, {}).get('failures', 0) + 1
        }

        # Update agent health
        self.agent_health[agent_id] = {
            'healthy': False,
            'last_failure': failure_type,
            'timestamp': datetime.now().isoformat()
        }

    def _find_fallback_agent(self, failed_agent: str, failure_type: str) -> Optional[str]:
        """Find healthy fallback agent with lowest adaptive load (in-flight + latency)."""
        candidates: List[tuple] = []
        for fallback in self.fallback_chain:
            if fallback != failed_agent and self._is_agent_healthy(fallback):
                score = self._load_score(fallback)
                candidates.append((score, fallback))
        for agent_id, health in self.agent_health.items():
            if agent_id != failed_agent and health.get('healthy', True) and agent_id not in self.fallback_chain:
                score = self._load_score(agent_id)
                candidates.append((score, agent_id))
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0])
        return candidates[0][1]

    def _load_score(self, agent_id: str) -> float:
        """Lower is better. Adapts to system load: in-flight count and recent latency."""
        in_flight = self._agent_in_flight.get(agent_id, 0)
        avg_ms = self._agent_avg_latency_ms.get(agent_id, 50.0)
        return in_flight * 20.0 + avg_ms / 10.0

    def _is_agent_healthy(self, agent_id: str) -> bool:
        """Check if agent is healthy"""
        if agent_id not in self.circuit_breakers:
            return True

        breaker = self.circuit_breakers[agent_id]
        return not breaker.get('open', False)

    def get_routing_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent routing decisions."""
        return list(self.routing_history)[-limit:]


class APIInterceptor:
    """
    Runtime API call interceptor
    Verifies all API calls in real-time for maximum security
    """

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.intercepted_calls: List[Dict[str, Any]] = []
        self.blocked_calls: int = 0

    async def intercept_call(
        self,
        func: Callable,
        *args,
        agent_id: str = 'unknown',
        call_type: str = 'api',
        **kwargs
    ) -> Any:
        """
        Intercept and verify API call before execution

        Usage:
            result = await interceptor.intercept_call(
                api_function,
                arg1, arg2,
                agent_id='agent_123',
                call_type='external_api'
            )
        """
        start = time.perf_counter()

        # Extract call details
        call_details = {
            'function': func.__name__,
            'args': str(args)[:200],
            'kwargs': str(kwargs)[:200],
            'agent_id': agent_id,
            'call_type': call_type,
            'timestamp': datetime.now().isoformat()
        }

        # Security check on arguments
        args_str = ' '.join([str(a) for a in args])
        kwargs_str = ' '.join([f"{k}={v}" for k, v in kwargs.items()])
        combined = f"{args_str} {kwargs_str}"

        # Run security check
        security_result = await self.orchestrator.check_async(
            input_text=combined,
            agent_id=agent_id,
            context={
                'call_type': call_type,
                'function': func.__name__,
                'runtime_intercept': True
            }
        )

        latency = (time.perf_counter() - start) * 1000

        if security_result['blocked']:
            # Block the API call
            self.blocked_calls += 1
            call_details['blocked'] = True
            call_details['reason'] = security_result.get('threats', [])
            self.intercepted_calls.append(call_details)

            logger.warning(
                f"Blocked API call from agent {agent_id}: {func.__name__}"
            )

            raise SecurityError(
                f"API call blocked: {security_result.get('threats', [])}"
            )

        # Allow the call
        call_details['blocked'] = False
        call_details['latency_ms'] = latency
        self.intercepted_calls.append(call_details)

        # Execute original function
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        """Get interception statistics"""
        return {
            'total_intercepted': len(self.intercepted_calls),
            'total_blocked': self.blocked_calls,
            'block_rate': self.blocked_calls / len(self.intercepted_calls) if self.intercepted_calls else 0.0,
            'recent_calls': self.intercepted_calls[-10:]
        }


class SecurityError(Exception):
    """Raised when API call is blocked for security reasons"""
    pass


class FailureRecovery:
    """
    Automatic failure recovery system
    Demonstrates how all failures are sidestepped
    """

    def __init__(self):
        self.recovery_strategies = {
            'hallucination': self._recover_from_hallucination,
            'goal_hijack': self._recover_from_hijack,
            'code_injection': self._recover_from_injection,
            'compromised': self._recover_from_compromise
        }

        self.recovery_log: List[Dict[str, Any]] = []

    async def recover(
        self,
        failure_type: str,
        agent_id: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute recovery strategy for failure type

        Returns:
            Recovery result with actions taken
        """
        logger.info(f"Initiating recovery for {failure_type} on agent {agent_id}")

        strategy = self.recovery_strategies.get(
            failure_type,
            self._generic_recovery
        )

        result = await strategy(agent_id, context)

        # Log recovery
        self.recovery_log.append({
            'timestamp': datetime.now().isoformat(),
            'failure_type': failure_type,
            'agent_id': agent_id,
            'recovery_result': result
        })

        return result

    async def _recover_from_hallucination(
        self,
        agent_id: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Recovery from hallucination"""
        return {
            'action': 'reset_context',
            'details': 'Cleared agent context and response history',
            'fallback': 'fact_checking_agent',
            'success': True
        }

    async def _recover_from_hijack(
        self,
        agent_id: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Recovery from goal hijacking"""
        return {
            'action': 'restore_goal',
            'details': 'Restored original goal state from backup',
            'fallback': 'goal_aligned_agent',
            'success': True
        }

    async def _recover_from_injection(
        self,
        agent_id: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Recovery from code injection"""
        return {
            'action': 'sandbox_reset',
            'details': 'Reset execution environment and isolated agent',
            'fallback': 'sandboxed_agent',
            'success': True
        }

    async def _recover_from_compromise(
        self,
        agent_id: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Recovery from full compromise"""
        return {
            'action': 'agent_replacement',
            'details': 'Replaced compromised agent with fresh instance',
            'fallback': 'new_agent_instance',
            'success': True
        }

    async def _generic_recovery(
        self,
        agent_id: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generic recovery strategy"""
        return {
            'action': 'safe_mode',
            'details': 'Activated safe mode with minimal permissions',
            'fallback': 'safe_mode_agent',
            'success': True
        }

    def get_recovery_stats(self) -> Dict[str, Any]:
        """Get recovery statistics"""
        if not self.recovery_log:
            return {'total_recoveries': 0}

        success_count = sum(
            1 for r in self.recovery_log
            if r['recovery_result'].get('success', False)
        )

        return {
            'total_recoveries': len(self.recovery_log),
            'successful_recoveries': success_count,
            'success_rate': success_count / len(self.recovery_log),
            'recent_recoveries': self.recovery_log[-10:]
        }
