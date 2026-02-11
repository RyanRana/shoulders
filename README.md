# Mr. Shoulders

**Mr. Shoulders** is a security layer that sits in front of your AI agents. It checks every request and response, blocks bad stuff, and keeps agents from going off the rails—without you maintaining a list of rules. It learns from feedback and adapts at runtime.

---

## What it does (simple)

1. **Checks every input** — Before your agent sees it. Looks for prompt injection, hijacking, and other attacks.
2. **Checks every response** — Optional. Catches mismatched or suspicious agent output.
3. **Watches behavior** — Tracks each agent over time and flags when behavior drifts from normal.
4. **Recovers automatically** — If something’s wrong (e.g. compromised agent), it reroutes to a fallback instead of failing.
5. **Learns** — You can send feedback (this was a threat / this was fine); it updates what it treats as dangerous.
6. **Scales** — Optional Redis mode so many instances can share state and load.

So: **one place to secure, monitor, and recover your AI traffic.**

---

## Stats at a glance

| What | Value |
|------|--------|
| **Detection layers** | 4 (semantic, behavioral, contextual, ML anomaly) — run in parallel |
| **Max check time** | 5 s (then fail-safe block) |
| **Result cache** | 2 s TTL, up to 2,048 entries (duplicate requests skip work) |
| **Threat threshold** | 0.7 confidence to block |
| **Redis connections** | 32 (when distributed) |
| **Python** | 3.8+ |

---

## Quick start

```bash
pip install -e .

# One-off check
ai-security check "Your input here" --agent-id agent_123

# Run the API
ai-security serve
```

Server: `http://localhost:8000`  
API docs: `http://localhost:8000/docs`

---

## Main endpoints

| Endpoint | What it does |
|----------|----------------|
| `POST /check` | Run a security check (input + optional response + agent_id) |
| `POST /feedback` | Send feedback so the system can learn (was it a threat? what type?) |
| `GET /metrics` | Totals: checks, blocked, recovered, avg latency, cache hits |
| `GET /health` | Is the service up? |
| `GET /agent/{id}/status` | How is this agent doing (score, actions, anomalies)? |
| `GET /agents/compromised` | List of agents currently marked compromised |

---

## Example: check one input

```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"input": "Your text here", "agent_id": "agent_123"}'
```

Example response:

```json
{
  "blocked": false,
  "latency_ms": 45.2,
  "threats": [],
  "monitoring": { "behavioral_score": 0.95 }
}
```

If it’s blocked, you get `blocked: true`, `threats` (with layer and reason), and optional `recovery` (e.g. fallback agent).

---

## Use it from Python

```python
from ai_security_orchestrator import DynamicSecurityOrchestrator

orchestrator = DynamicSecurityOrchestrator(
    enable_learning=True,
    confidence_threshold=0.7,
)

async def protect(user_prompt: str, agent_id: str):
    result = await orchestrator.check_async(user_prompt, agent_id)
    if result["blocked"]:
        return None  # or handle threats
    return user_prompt
```

With Redis (distributed):

```python
orchestrator = DynamicSecurityOrchestrator(
    redis_url="redis://localhost:6379",
    enable_distributed=True,
    enable_learning=True,
)
```

---

## CLI

| Command | What it does |
|---------|----------------|
| `ai-security serve` | Start API (default port 8000) |
| `ai-security check "input"` | Run a single check |
| `ai-security monitor` | Live view of agent stats |
| `ai-security stats` | System totals (checks, blocked, recovered, latency) |

Use `--redis-url` and `--enable-distributed` for multi-instance.

---

## What’s inside (high level)

- **Orchestrator** — Runs the check: monitor + 4 detection layers (with overlap for speed), then optional reroute. Handles cache, timeouts, and metrics.
- **Detector** — Four layers: learned patterns (semantic), behavior vs baseline, input–response match (contextual), simple ML-style anomaly. All parallel; learns from feedback.
- **Monitor** — Logs each agent’s actions and keeps a health score; flags compromised agents.
- **Router** — Picks fallback agents by load (in-flight + latency). Reroutes on failure; keeps a bounded history of decisions.

---

## Docs

- **[INSTALL.md](INSTALL.md)** — Install, integrate, deploy.
- **[PRODUCT_SPEC.md](PRODUCT_SPEC.md)** — Full spec and API details.

---

## License

MIT
