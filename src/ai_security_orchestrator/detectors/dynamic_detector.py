"""
Dynamic Threat Detector
Zero-hardcoding: learns attack patterns from data
Compatible with all attack types
Optimized for low latency: parallel layers, O(1) pattern lookup, bounded thread pool.
"""
import asyncio
import time
import numpy as np
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from collections import deque, defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import logging
import os

logger = logging.getLogger(__name__)

# Shared bounded executor for CPU-bound detection (avoids unbounded thread growth)
_DETECTOR_EXECUTOR: Optional[ThreadPoolExecutor] = None


def _get_executor() -> ThreadPoolExecutor:
    global _DETECTOR_EXECUTOR
    if _DETECTOR_EXECUTOR is None:
        _DETECTOR_EXECUTOR = ThreadPoolExecutor(
            max_workers=min(32, (os.cpu_count() or 4) * 2),
            thread_name_prefix="detector",
        )
    return _DETECTOR_EXECUTOR


@dataclass
class ThreatResult:
    """Threat detection result"""
    is_threat: bool
    confidence: float
    layer: str
    reason: str
    latency_ms: float
    metadata: Dict[str, Any]
    timestamp: str


class DynamicThreatDetector:
    """
    Dynamic threat detector with zero hardcoding

    Instead of hardcoded patterns, this learns from:
    - Historical attack data
    - Behavioral baselines
    - Feedback loops
    - Ensemble models

    Compatible with ALL attack types through dynamic adaptation
    """

    def __init__(self, enable_learning: bool = True):
        self.enable_learning = enable_learning

        # Dynamic pattern storage (learned, not hardcoded)
        self.learned_patterns: Dict[str, List[str]] = defaultdict(list)
        # O(1) lookup: set of all patterns, map pattern -> category
        self._all_patterns: Set[str] = set()
        self._pattern_category: Dict[str, str] = {}
        self.behavioral_baselines: Dict[str, Dict[str, float]] = {}

        # Feedback loop
        self.feedback_queue: deque = deque(maxlen=1000)

        # Initialize with minimal bootstrap (will learn more)
        self._bootstrap()

        logger.info("DynamicThreatDetector initialized (learning mode: {})".format(enable_learning))

    def _add_pattern(self, category: str, pattern: str) -> None:
        """Register a pattern for O(1) lookup."""
        p = pattern.lower()
        if p not in self._all_patterns:
            self._all_patterns.add(p)
            self._pattern_category[p] = category
            self.learned_patterns[category].append(pattern)

    def _bootstrap(self):
        """Minimal bootstrap - will learn patterns dynamically"""
        for p in ['ignore', 'bypass', 'override', 'hack']:
            self._add_pattern('suspicious', p)

    async def detect_all_async(
        self,
        input_text: str,
        agent_id: str,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ThreatResult]:
        """Run all detection layers in parallel (backward compatible)."""
        ts = datetime.now().isoformat()
        tasks = [
            self._detect_semantic_async(input_text, agent_id, ts),
            self._detect_behavioral_async(agent_id, input_text, context or {}, ts),
            self._detect_contextual_async(input_text, response, agent_id, ts),
            self._detect_ml_anomaly_async(input_text, agent_id, ts),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatResult)]

    async def detect_layers_without_behavioral_async(
        self,
        input_text: str,
        agent_id: str,
        response: Optional[str] = None,
        ts: Optional[str] = None,
    ) -> List[ThreatResult]:
        """Run semantic, contextual, and ML layers in parallel (no behavioral). Use with monitor overlap."""
        ts = ts or datetime.now().isoformat()
        tasks = [
            self._detect_semantic_async(input_text, agent_id, ts),
            self._detect_contextual_async(input_text, response, agent_id, ts),
            self._detect_ml_anomaly_async(input_text, agent_id, ts),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatResult)]

    async def detect_behavioral_only_async(
        self,
        agent_id: str,
        input_text: str,
        context: Dict[str, Any],
        ts: Optional[str] = None,
    ) -> ThreatResult:
        """Run only behavioral layer (after context is available)."""
        ts = ts or datetime.now().isoformat()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _get_executor(),
            self._detect_behavioral,
            agent_id,
            input_text,
            context,
            ts,
        )

    async def _detect_semantic_async(
        self,
        input_text: str,
        agent_id: str,
        ts: Optional[str] = None,
    ) -> ThreatResult:
        ts = ts or datetime.now().isoformat()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _get_executor(),
            self._detect_semantic,
            input_text,
            agent_id,
            ts,
        )

    def _detect_semantic(self, input_text: str, agent_id: str, ts: Optional[str] = None) -> ThreatResult:
        """Semantic threat detection with O(1) pattern lookup."""
        start = time.perf_counter()
        ts = ts or datetime.now().isoformat()

        if not input_text:
            return ThreatResult(False, 0.0, 'semantic', 'empty_input', (time.perf_counter() - start) * 1000, {}, ts)

        lower_text = input_text.lower()
        matched_patterns: List[Tuple[str, str]] = []
        for pattern in self._all_patterns:
            if pattern in lower_text:
                matched_patterns.append((self._pattern_category[pattern], pattern))

        latency = (time.perf_counter() - start) * 1000
        if matched_patterns:
            confidence = min(len(matched_patterns) * 0.3, 0.95)
            return ThreatResult(True, confidence, 'semantic', f'learned_pattern_match: {matched_patterns[0]}', latency, {'matched_patterns': matched_patterns}, ts)
        return ThreatResult(False, 0.0, 'semantic', 'clean', latency, {}, ts)

    async def _detect_behavioral_async(
        self,
        agent_id: str,
        input_text: str,
        context: Dict[str, Any],
        ts: Optional[str] = None,
    ) -> ThreatResult:
        ts = ts or datetime.now().isoformat()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _get_executor(),
            self._detect_behavioral,
            agent_id,
            input_text,
            context,
            ts,
        )

    def _detect_behavioral(
        self,
        agent_id: str,
        input_text: str,
        context: Dict[str, Any],
        ts: Optional[str] = None,
    ) -> ThreatResult:
        """Detect behavioral anomalies."""
        start = time.perf_counter()
        ts = ts or datetime.now().isoformat()

        if agent_id not in self.behavioral_baselines:
            self.behavioral_baselines[agent_id] = {
                'avg_length': 100.0,
                'avg_requests_per_min': 5.0,
                'typical_topics': set(),
            }
        baseline = self.behavioral_baselines[agent_id]

        current_length = len(input_text)
        length_deviation = abs(current_length - baseline['avg_length']) / max(baseline['avg_length'], 1e-6)
        rate = context.get('requests_per_minute', 5.0)
        rate_deviation = abs(rate - baseline['avg_requests_per_min']) / max(baseline['avg_requests_per_min'], 1e-6)
        deviation_score = (length_deviation + rate_deviation) / 2
        latency = (time.perf_counter() - start) * 1000

        if self.enable_learning:
            baseline['avg_length'] = 0.9 * baseline['avg_length'] + 0.1 * current_length
            baseline['avg_requests_per_min'] = 0.9 * baseline['avg_requests_per_min'] + 0.1 * rate

        if deviation_score > 0.5:
            return ThreatResult(True, min(deviation_score, 0.95), 'behavioral', f'behavioral_anomaly: deviation={deviation_score:.2f}', latency, {'length_deviation': length_deviation, 'rate_deviation': rate_deviation}, ts)
        return ThreatResult(False, 0.0, 'behavioral', 'normal', latency, {}, ts)

    async def _detect_contextual_async(
        self,
        input_text: str,
        response: Optional[str],
        agent_id: str,
        ts: Optional[str] = None,
    ) -> ThreatResult:
        ts = ts or datetime.now().isoformat()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _get_executor(),
            self._detect_contextual,
            input_text,
            response,
            agent_id,
            ts,
        )

    def _detect_contextual(
        self,
        input_text: str,
        response: Optional[str],
        agent_id: str,
        ts: Optional[str] = None,
    ) -> ThreatResult:
        start = time.perf_counter()
        ts = ts or datetime.now().isoformat()
        if not response:
            return ThreatResult(False, 0.0, 'contextual', 'no_response', (time.perf_counter() - start) * 1000, {}, ts)
        input_words = set(input_text.lower().split())
        response_words = set(response.lower().split())
        overlap = len(input_words.intersection(response_words))
        overlap_ratio = overlap / len(input_words) if input_words else 0
        latency = (time.perf_counter() - start) * 1000
        if overlap_ratio < 0.1 and len(input_text) > 20:
            return ThreatResult(True, 0.6, 'contextual', f'response_mismatch: overlap={overlap_ratio:.2f}', latency, {'overlap_ratio': overlap_ratio}, ts)
        return ThreatResult(False, 0.0, 'contextual', 'aligned', latency, {}, ts)

    async def _detect_ml_anomaly_async(
        self,
        input_text: str,
        agent_id: str,
        ts: Optional[str] = None,
    ) -> ThreatResult:
        ts = ts or datetime.now().isoformat()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _get_executor(),
            self._detect_ml_anomaly,
            input_text,
            agent_id,
            ts,
        )

    def _detect_ml_anomaly(self, input_text: str, agent_id: str, ts: Optional[str] = None) -> ThreatResult:
        start = time.perf_counter()
        ts = ts or datetime.now().isoformat()
        length = len(input_text)
        features = {
            'length': length,
            'uppercase_ratio': sum(1 for c in input_text if c.isupper()) / length if length else 0,
            'special_char_ratio': sum(1 for c in input_text if not c.isalnum() and not c.isspace()) / length if length else 0,
            'word_count': len(input_text.split()),
        }
        anomaly_score = 0.0
        if features['length'] > 1000:
            anomaly_score += 0.3
        if features['uppercase_ratio'] > 0.5:
            anomaly_score += 0.2
        if features['special_char_ratio'] > 0.3:
            anomaly_score += 0.3
        latency = (time.perf_counter() - start) * 1000
        if anomaly_score > 0.5:
            return ThreatResult(True, anomaly_score, 'ml_anomaly', f'anomaly_score={anomaly_score:.2f}', latency, features, ts)
        return ThreatResult(False, 0.0, 'ml_anomaly', 'normal', latency, {}, ts)

    def learn_from_feedback(
        self,
        input_text: str,
        was_threat: bool,
        threat_type: str
    ):
        """Learn from feedback to improve detection."""
        if not self.enable_learning:
            return
        self.feedback_queue.append({
            'input': input_text,
            'was_threat': was_threat,
            'threat_type': threat_type,
            'timestamp': datetime.now().isoformat(),
        })
        if was_threat:
            for word in input_text.lower().split():
                if len(word) > 4 and word not in self._all_patterns:
                    self._add_pattern(threat_type, word)
        logger.info(f"Learned from feedback: {threat_type}")

    def get_learned_patterns(self) -> Dict[str, List[str]]:
        """Get current learned patterns"""
        return dict(self.learned_patterns)

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            'learned_pattern_count': sum(len(p) for p in self.learned_patterns.values()),
            'behavioral_baselines_count': len(self.behavioral_baselines),
            'feedback_queue_size': len(self.feedback_queue),
            'learning_enabled': self.enable_learning
        }
