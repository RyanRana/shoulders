"""
Dynamic Security Orchestrator
Zero-hardcoding approach: learns patterns dynamically from data
Scales to any system size with distributed architecture.
Optimized: overlapping monitor+detection, result cache, Redis pool, adaptive concurrency.
"""
import asyncio
import time
import json
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import deque, OrderedDict
import logging

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Default check timeout (ms) to avoid runaway latency
DEFAULT_CHECK_TIMEOUT_MS = 5000
# Result cache TTL (seconds) and max size for duplicate requests
CACHE_TTL_SEC = 2.0
CACHE_MAX_SIZE = 2048


@dataclass
class ThreatResult:
    """Result of security check"""
    is_threat: bool
    confidence: float
    layer: str
    reason: str
    latency_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AgentAction:
    """Logged agent action"""
    agent_id: str
    action_type: str
    input_text: str
    response_text: Optional[str]
    timestamp: str
    blocked: bool
    threats_detected: List[str]
    deviation_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureEvent:
    """System failure event"""
    failure_type: str
    agent_id: str
    timestamp: str
    context: Dict[str, Any]
    recovery_action: str
    recovery_success: bool


class DynamicSecurityOrchestrator:
    """
    Enterprise-grade dynamic security orchestrator

    Features:
    - Dynamic pattern learning (no hardcoded rules)
    - Distributed monitoring via Redis
    - Real-time agent action tracking
    - Automatic failure recovery and rerouting
    - Scales to millions of requests
    - Production observability (Prometheus, logging)
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        enable_distributed: bool = False,
        enable_learning: bool = True,
        confidence_threshold: float = 0.7,
        check_timeout_ms: float = DEFAULT_CHECK_TIMEOUT_MS,
        result_cache_ttl_sec: float = CACHE_TTL_SEC,
        result_cache_max_size: int = CACHE_MAX_SIZE,
        max_concurrent_checks: Optional[int] = None,
    ):
        """
        Initialize dynamic orchestrator.

        Args:
            redis_url: Redis connection URL for distributed monitoring
            enable_distributed: Enable distributed mode for large-scale deployments
            enable_learning: Enable online learning from feedback
            confidence_threshold: Minimum confidence for threat flagging
            check_timeout_ms: Max time (ms) per check before failing
            result_cache_ttl_sec: TTL for result cache (0 = disabled)
            result_cache_max_size: Max cached results (0 = disabled)
            max_concurrent_checks: Semaphore limit for adaptive load (None = unbounded)
        """
        self.enable_distributed = enable_distributed and REDIS_AVAILABLE
        self.enable_learning = enable_learning
        self.confidence_threshold = confidence_threshold
        self.check_timeout_ms = check_timeout_ms
        self.result_cache_ttl_sec = result_cache_ttl_sec
        self.result_cache_max_size = result_cache_max_size
        self._cache: OrderedDict[str, Tuple[float, Dict[str, Any]]] = OrderedDict() if result_cache_max_size and result_cache_ttl_sec else None
        self._semaphore = asyncio.Semaphore(max_concurrent_checks) if max_concurrent_checks else None

        if self.enable_distributed and redis_url and REDIS_AVAILABLE:
            self.redis_client = redis.from_url(redis_url, max_connections=32, decode_responses=True)
            logger.info("Connected to Redis (pool) at %s", redis_url)
        else:
            self.redis_client = None
            if enable_distributed:
                logger.warning("Redis not available, running in standalone mode")

        self.action_log: deque = deque(maxlen=10000)
        self.failure_log: deque = deque(maxlen=1000)
        self._detectors = None
        self._router = None
        self._agent_monitor = None
        self.metrics = {
            'total_checks': 0,
            'threats_blocked': 0,
            'false_positives': 0,
            'failures_recovered': 0,
            'avg_latency_ms': 0.0,
            'cache_hits': 0,
        }
        logger.info("DynamicSecurityOrchestrator initialized (distributed=%s, learning=%s)", self.enable_distributed, self.enable_learning)

    def _lazy_load_components(self):
        """Lazy load heavy components"""
        if self._detectors is None:
            from ..detectors.dynamic_detector import DynamicThreatDetector
            self._detectors = DynamicThreatDetector(enable_learning=self.enable_learning)
            logger.info("Loaded DynamicThreatDetector")

        if self._router is None:
            from .router import DynamicRouter
            self._router = DynamicRouter()
            logger.info("Loaded DynamicRouter")

        if self._agent_monitor is None:
            from ..monitors.agent_monitor import AgentMonitor
            self._agent_monitor = AgentMonitor(
                redis_client=self.redis_client,
                distributed=self.enable_distributed
            )
            logger.info("Loaded AgentMonitor")

    def _cache_key(self, input_text: str, agent_id: str, response: Optional[str]) -> str:
        """Stable cache key for request deduplication."""
        h = hashlib.sha256((input_text + "|" + agent_id + "|" + (response or "")).encode()).hexdigest()
        return h[:32]

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        if not self._cache:
            return None
        now = time.monotonic()
        if key in self._cache:
            ts, result = self._cache[key]
            if now - ts <= self.result_cache_ttl_sec:
                self.metrics['cache_hits'] = self.metrics.get('cache_hits', 0) + 1
                return result
            del self._cache[key]
        return None

    def _cache_set(self, key: str, result: Dict[str, Any]) -> None:
        if not self._cache or self.result_cache_max_size <= 0:
            return
        while len(self._cache) >= self.result_cache_max_size:
            self._cache.popitem(last=False)
        self._cache[key] = (time.monotonic(), result)

    async def check_async(
        self,
        input_text: str,
        agent_id: str = 'default',
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Dynamic security check with automatic rerouting.
        Overlaps monitoring with detection for lower latency; optional result cache.
        """
        start = time.perf_counter()
        cache_key = self._cache_key(input_text, agent_id, response)
        if cache_key:
            cached = self._cache_get(cache_key)
            if cached is not None:
                cached = dict(cached)
                cached['latency_ms'] = (time.perf_counter() - start) * 1000
                cached['from_cache'] = True
                return cached

        sem = self._semaphore
        if sem:
            await sem.acquire()
        try:
            return await self._check_async_impl(start, input_text, agent_id, response, context, cache_key)
        finally:
            if sem:
                sem.release()

    async def _check_async_impl(
        self,
        start: float,
        input_text: str,
        agent_id: str,
        response: Optional[str],
        context: Optional[Dict[str, Any]],
        cache_key: Optional[str],
    ) -> Dict[str, Any]:
        self._lazy_load_components()
        self.metrics['total_checks'] += 1
        timeout_sec = self.check_timeout_ms / 1000.0

        async def _run():
            self._router.record_request_start(agent_id)
            ts = datetime.now().isoformat()
            monitor_task = self._agent_monitor.log_action(
                agent_id=agent_id,
                action_type='user_input',
                input_text=input_text,
                response_text=response,
                context=context or {},
            )
            no_behavioral_task = self._detectors.detect_layers_without_behavioral_async(
                input_text=input_text,
                agent_id=agent_id,
                response=response,
                ts=ts,
            )
            action_result, no_beh_results = await asyncio.gather(monitor_task, no_behavioral_task)
            behavioral_result = await self._detectors.detect_behavioral_only_async(
                agent_id=agent_id,
                input_text=input_text,
                context=action_result,
                ts=ts,
            )
            threat_results = no_beh_results + [behavioral_result]

            recovery_result = None
            if self._needs_rerouting(threat_results):
                recovery_result = await self._router.reroute(
                    agent_id=agent_id,
                    threats=threat_results,
                    original_input=input_text,
                    context=action_result,
                )
                if recovery_result.success:
                    self.metrics['failures_recovered'] += 1
                    logger.info("Rerouted agent %s: %s", agent_id, recovery_result.action)

            total_latency = (time.perf_counter() - start) * 1000
            self._update_avg_latency(total_latency)
            high_confidence_threats = [t for t in threat_results if t.is_threat and t.confidence >= self.confidence_threshold]
            is_blocked = len(high_confidence_threats) > 0
            if is_blocked:
                self.metrics['threats_blocked'] += 1

            result = {
                'blocked': is_blocked,
                'agent_id': agent_id,
                'latency_ms': total_latency,
                'timestamp': datetime.now().isoformat(),
                'dynamic_detection': True,
                'distributed_mode': self.enable_distributed,
                'threats': [self._serialize_threat(t) for t in high_confidence_threats],
                'all_detections': [self._serialize_threat(t) for t in threat_results if t.is_threat],
                'monitoring': {
                    'action_logged': action_result.get('logged', False),
                    'agent_history_size': action_result.get('history_size', 0),
                    'behavioral_score': action_result.get('behavioral_score', 0.0),
                },
            }
            if recovery_result:
                result['recovery'] = {
                    'triggered': True,
                    'action': recovery_result.action,
                    'success': recovery_result.success,
                    'fallback_agent': recovery_result.fallback_agent,
                    'reason': recovery_result.reason,
                }
            self._log_action(agent_id, input_text, response, is_blocked, threat_results, result)
            self._router.record_request_end(agent_id, total_latency)
            if self.enable_distributed and self.redis_client:
                asyncio.create_task(self._publish_result(agent_id, result))
            if cache_key:
                self._cache_set(cache_key, result)
            return result

        try:
            return await asyncio.wait_for(_run(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            total_latency = (time.perf_counter() - start) * 1000
            self._router.record_request_end(agent_id, total_latency)
            logger.warning("Check timed out after %.0fms for agent %s", total_latency, agent_id)
            return self._timeout_result(agent_id, total_latency)

        except Exception as e:
            self._router.record_request_end(agent_id, (time.perf_counter() - start) * 1000)
            logger.error("Error in security check for agent %s: %s", agent_id, e, exc_info=True)
            self.failure_log.append(FailureEvent(
                failure_type='check_exception',
                agent_id=agent_id,
                timestamp=datetime.now().isoformat(),
                context={'error': str(e), 'input': input_text[:100]},
                recovery_action='fail_safe_block',
                recovery_success=True,
            ))
            return self._fail_safe_result(agent_id, str(e), (time.perf_counter() - start) * 1000)

    def _timeout_result(self, agent_id: str, latency_ms: float) -> Dict[str, Any]:
        return {
            'blocked': True, 'agent_id': agent_id, 'latency_ms': latency_ms,
            'timestamp': datetime.now().isoformat(), 'error': 'check_timeout', 'fail_safe': True,
            'recovery': {'triggered': True, 'action': 'fail_safe_block', 'success': True, 'reason': 'Check timed out'},
        }

    def _fail_safe_result(self, agent_id: str, error: str, latency_ms: float) -> Dict[str, Any]:
        return {
            'blocked': True, 'agent_id': agent_id, 'latency_ms': latency_ms,
            'timestamp': datetime.now().isoformat(), 'error': error, 'fail_safe': True,
            'recovery': {'triggered': True, 'action': 'fail_safe_block', 'success': True, 'reason': 'Exception during security check'},
        }

    def _needs_rerouting(self, threat_results: List[ThreatResult]) -> bool:
        """Determine if rerouting is needed"""
        # Reroute if high-confidence threats detected
        high_conf_threats = [t for t in threat_results if t.is_threat and t.confidence > 0.8]

        # Or if multiple threats detected (potential compromised agent)
        return len(high_conf_threats) > 0 or len([t for t in threat_results if t.is_threat]) >= 3

    def _serialize_threat(self, threat: ThreatResult) -> Dict[str, Any]:
        """Convert ThreatResult to dict"""
        return {
            'layer': threat.layer,
            'reason': threat.reason,
            'confidence': threat.confidence,
            'latency_ms': threat.latency_ms,
            'metadata': threat.metadata,
            'timestamp': threat.timestamp
        }

    def _log_action(
        self,
        agent_id: str,
        input_text: str,
        response: Optional[str],
        blocked: bool,
        threats: List[ThreatResult],
        full_result: Dict[str, Any]
    ):
        """Log agent action"""
        action = AgentAction(
            agent_id=agent_id,
            action_type='security_check',
            input_text=input_text[:500],  # Truncate
            response_text=response[:500] if response else None,
            timestamp=datetime.now().isoformat(),
            blocked=blocked,
            threats_detected=[t.layer for t in threats if t.is_threat],
            deviation_score=full_result.get('monitoring', {}).get('behavioral_score', 0.0),
            metadata={'full_result': full_result}
        )

        self.action_log.append(action)

    def _update_avg_latency(self, latency: float):
        """Update rolling average latency"""
        alpha = 0.1  # Smoothing factor
        self.metrics['avg_latency_ms'] = (
            alpha * latency + (1 - alpha) * self.metrics['avg_latency_ms']
        )

    async def _publish_result(self, agent_id: str, result: Dict[str, Any]):
        """Publish result to Redis for distributed monitoring"""
        try:
            channel = f"security:agent:{agent_id}"
            message = json.dumps(result)
            await asyncio.to_thread(self.redis_client.publish, channel, message)
        except Exception as e:
            logger.error(f"Failed to publish to Redis: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        return {
            **self.metrics,
            'action_log_size': len(self.action_log),
            'failure_log_size': len(self.failure_log),
            'distributed_mode': self.enable_distributed,
            'learning_enabled': self.enable_learning
        }

    def get_agent_history(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get action history for specific agent"""
        actions = [
            asdict(a) for a in self.action_log
            if a.agent_id == agent_id
        ]
        return actions[-limit:]

    def get_failure_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent failures and recoveries"""
        return [asdict(f) for f in list(self.failure_log)[-limit:]]

    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down DynamicSecurityOrchestrator")

        if self.redis_client:
            self.redis_client.close()

        logger.info("Shutdown complete")
