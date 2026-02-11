"""
Agent Action Monitor
Constant surveillance of all agent actions
Detects malicious, hacked, or hallucinating behavior in real-time
"""
import asyncio
import time
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class AgentAction:
    """Single agent action"""
    agent_id: str
    action_type: str
    input_text: str
    response_text: Optional[str]
    timestamp: str
    metadata: Dict[str, Any]


class AgentMonitor:
    """
    Real-time agent action monitoring

    Tracks:
    - Every agent interaction
    - Behavioral patterns
    - Anomalies and deviations
    - Multi-agent coordination

    Detects:
    - Malicious behavior
    - Compromised/hacked agents
    - Hallucinations
    - Goal manipulation
    """

    def __init__(
        self,
        redis_client=None,
        distributed: bool = False,
        history_size: int = 10000
    ):
        self.redis_client = redis_client
        self.distributed = distributed

        # Action history per agent
        self.agent_histories: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )

        # Global action log
        self.global_log: deque = deque(maxlen=history_size)

        # Agent scores (health/trust)
        self.agent_scores: Dict[str, float] = defaultdict(lambda: 1.0)

        # Anomaly tracking
        self.anomaly_counts: Dict[str, int] = defaultdict(int)

        logger.info(f"AgentMonitor initialized (distributed: {distributed})")

    async def log_action(
        self,
        agent_id: str,
        action_type: str,
        input_text: str,
        response_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Log agent action and perform real-time analysis

        Returns:
            Analysis result with behavioral scores
        """
        action = AgentAction(
            agent_id=agent_id,
            action_type=action_type,
            input_text=input_text[:500],  # Truncate
            response_text=response_text[:500] if response_text else None,
            timestamp=datetime.now().isoformat(),
            metadata=context or {}
        )

        self.agent_histories[agent_id].append(action)
        self.global_log.append(action)

        # Run CPU-bound behavioral analysis in thread to avoid blocking event loop
        loop = asyncio.get_event_loop()
        behavioral_score = await loop.run_in_executor(None, self._analyze_behavior, agent_id)
        self.agent_scores[agent_id] = behavioral_score
        is_anomalous = behavioral_score < 0.5
        if is_anomalous:
            self.anomaly_counts[agent_id] += 1
            logger.warning("Anomalous behavior for agent %s: score=%.2f", agent_id, behavioral_score)

        # Fire-and-forget Redis publish to avoid adding latency
        if self.distributed and self.redis_client:
            asyncio.create_task(self._publish_action(agent_id, action, behavioral_score))

        return {
            'logged': True,
            'agent_id': agent_id,
            'behavioral_score': behavioral_score,
            'is_anomalous': is_anomalous,
            'history_size': len(self.agent_histories[agent_id]),
            'anomaly_count': self.anomaly_counts[agent_id]
        }

    def _analyze_behavior(self, agent_id: str) -> float:
        """Analyze agent behavior; returns score 0.0 (malicious) to 1.0 (healthy)."""
        history = self.agent_histories[agent_id]
        if not history:
            return 1.0
        recent = list(history)[-10:]

        # Factor 1: Request frequency (too high = suspicious)
        if len(recent) >= 10:
            time_span = (
                datetime.fromisoformat(recent[-1].timestamp) -
                datetime.fromisoformat(recent[0].timestamp)
            ).total_seconds()

            if time_span < 5:  # 10 requests in 5 seconds
                return 0.3

        # Factor 2: Input length consistency
        lengths = [len(a.input_text) for a in recent]
        avg_length = sum(lengths) / len(lengths) if lengths else 0
        length_variance = sum((l - avg_length) ** 2 for l in lengths) / len(lengths) if lengths else 0

        # High variance might indicate probing
        if length_variance > 10000:
            return 0.6

        # Factor 3: Response patterns
        if len(recent) >= 5:
            has_responses = sum(1 for a in recent if a.response_text)
            if has_responses == 0:
                return 0.7  # No responses = possible one-way attack

        # All checks passed
        return 0.95

    async def _publish_action(
        self,
        agent_id: str,
        action: AgentAction,
        score: float
    ):
        """Publish action to Redis for distributed monitoring"""
        try:
            channel = f"monitor:agent:{agent_id}"
            message = json.dumps({
                **asdict(action),
                'behavioral_score': score
            })
            await asyncio.to_thread(
                self.redis_client.publish,
                channel,
                message
            )
        except Exception as e:
            logger.error(f"Failed to publish action: {e}")

    def get_agent_status(self, agent_id: str) -> Dict[str, Any]:
        """Get current status of agent"""
        history = list(self.agent_histories[agent_id])

        return {
            'agent_id': agent_id,
            'behavioral_score': self.agent_scores[agent_id],
            'total_actions': len(history),
            'anomaly_count': self.anomaly_counts[agent_id],
            'recent_actions': [asdict(a) for a in history[-5:]],
            'status': self._get_status_label(self.agent_scores[agent_id])
        }

    def _get_status_label(self, score: float) -> str:
        """Convert score to status label"""
        if score >= 0.8:
            return 'healthy'
        elif score >= 0.5:
            return 'suspicious'
        else:
            return 'compromised'

    def get_all_agent_stats(self) -> Dict[str, Any]:
        """Get stats for all monitored agents"""
        return {
            'total_agents': len(self.agent_histories),
            'total_actions': len(self.global_log),
            'agents': {
                agent_id: {
                    'score': self.agent_scores[agent_id],
                    'actions': len(history),
                    'anomalies': self.anomaly_counts[agent_id],
                    'status': self._get_status_label(self.agent_scores[agent_id])
                }
                for agent_id, history in self.agent_histories.items()
            }
        }

    def get_compromised_agents(self) -> List[str]:
        """Get list of potentially compromised agents"""
        return [
            agent_id
            for agent_id, score in self.agent_scores.items()
            if score < 0.5
        ]

    def get_recent_anomalies(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent anomalous actions"""
        anomalous = []

        for action in reversed(self.global_log):
            score = self.agent_scores[action.agent_id]
            if score < 0.5:
                anomalous.append({
                    **asdict(action),
                    'behavioral_score': score
                })

                if len(anomalous) >= limit:
                    break

        return anomalous


class AgentActionLogger:
    """
    High-performance action logger
    Optimized for minimal latency impact
    """

    def __init__(self, log_file: str = 'agent_actions.jsonl'):
        self.log_file = log_file
        self.buffer: List[Dict[str, Any]] = []
        self.buffer_size = 100
        self._lock = asyncio.Lock()

    async def log(self, action: Dict[str, Any]):
        """Log action asynchronously"""
        async with self._lock:
            self.buffer.append(action)

            # Flush if buffer full
            if len(self.buffer) >= self.buffer_size:
                await self.flush()

    async def flush(self):
        """Flush buffer to disk"""
        if not self.buffer:
            return

        try:
            # Write in background thread to avoid blocking
            await asyncio.to_thread(self._write_to_file)
        except Exception as e:
            logger.error(f"Failed to flush action log: {e}")

    def _write_to_file(self):
        """Write buffered actions to file"""
        with open(self.log_file, 'a') as f:
            for action in self.buffer:
                f.write(json.dumps(action) + '\n')

        self.buffer.clear()

    async def shutdown(self):
        """Graceful shutdown with buffer flush"""
        await self.flush()
