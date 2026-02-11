
# Installation Guide
## AI Security Orchestrator - Enterprise Edition

Complete guide for installing and deploying the AI Security Orchestrator in any environment.

---

## Quick Start (2 Minutes)

### 1. Install Package

```bash
cd mr.shoulders
pip install -e .
```

### 2. Start Server

```bash
ai-security serve
```

That's it! The orchestrator is now protecting your system. Visit `http://localhost:8000/docs` for the interactive API.

---

## Full Installation

### Prerequisites

- Python 3.8+
- pip
- (Optional) Redis for distributed mode
- (Optional) Docker for containerized deployment

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/ai-security-orchestrator.git
cd mr.shoulders
```

### Step 2: Install Dependencies

#### Basic Installation
```bash
pip install -e .
```

#### With Development Tools
```bash
pip install -e ".[dev]"
```

#### With Monitoring Tools
```bash
pip install -e ".[monitoring]"
```

#### With Advanced ML
```bash
pip install -e ".[ml]"
```

#### Full Installation (Everything)
```bash
pip install -e ".[dev,monitoring,ml]"
```

### Step 3: Verify Installation

```bash
ai-security --version
# Should output: 2.0.0

ai-security check "Hello world"
# Should output: ✅ ALLOWED
```

---

## Integration with Your AI System

### Python Integration

```python
# 1. Import the orchestrator
from ai_security_orchestrator import DynamicSecurityOrchestrator

# 2. Initialize
orchestrator = DynamicSecurityOrchestrator(
    enable_learning=True,
    confidence_threshold=0.7
)

# 3. Protect your AI agent
async def protected_agent_call(user_input, agent):
    # Security check BEFORE processing
    security_result = await orchestrator.check_async(
        input_text=user_input,
        agent_id=agent.id
    )

    if security_result['blocked']:
        # Handle blocked request
        return {
            "error": "Request blocked for security reasons",
            "threats": security_result['threats']
        }

    # Process normally
    response = await agent.process(user_input)

    # Verify response
    response_check = await orchestrator.check_async(
        input_text=user_input,
        agent_id=agent.id,
        response=response
    )

    if response_check['blocked']:
        # Automatic recovery triggered
        return {
            "warning": "Response contained threats, rerouted",
            "recovery": response_check['recovery'],
            "safe_response": "I cannot provide that information."
        }

    return {"response": response}
```

### REST API Integration

#### Start Server
```bash
ai-security serve --host 0.0.0.0 --port 8000
```

#### Make Requests

```python
import httpx

async def check_security(input_text, agent_id):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/check",
            json={
                "input": input_text,
                "agent_id": agent_id
            }
        )
        return response.json()

# Usage
result = await check_security(
    "User input here",
    "agent_123"
)

if result['blocked']:
    print("Blocked:", result['threats'])
else:
    print("Allowed")
```

### Runtime API Interception

```python
from ai_security_orchestrator.core.router import APIInterceptor

# Create interceptor
interceptor = APIInterceptor(orchestrator)

# Wrap API calls
async def safe_api_call(data):
    result = await interceptor.intercept_call(
        external_api.process,  # Your API function
        data,
        agent_id='your_agent_id',
        call_type='external_api'
    )
    return result

# Now all calls are verified at runtime
```

---

## Distributed Deployment

### With Redis

#### 1. Start Redis
```bash
docker run -d -p 6379:6379 redis:latest
```

#### 2. Configure Orchestrator
```python
orchestrator = DynamicSecurityOrchestrator(
    redis_url="redis://localhost:6379",
    enable_distributed=True,
    enable_learning=True
)
```

#### 3. Start Multiple Instances
```bash
# Terminal 1
ai-security serve --port 8000 --redis-url redis://localhost:6379 --enable-distributed

# Terminal 2
ai-security serve --port 8001 --redis-url redis://localhost:6379 --enable-distributed

# Terminal 3
ai-security serve --port 8002 --redis-url redis://localhost:6379 --enable-distributed
```

All instances share state via Redis!

### With Docker

#### Build Image
```bash
docker build -t ai-security-orchestrator:2.0.0 .
```

#### Run Container
```bash
docker run -d \
  --name orchestrator \
  -p 8000:8000 \
  -e REDIS_URL=redis://redis:6379 \
  -e ENABLE_DISTRIBUTED=true \
  ai-security-orchestrator:2.0.0
```

### With Kubernetes

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-security-orchestrator
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ai-security
  template:
    metadata:
      labels:
        app: ai-security
    spec:
      containers:
      - name: orchestrator
        image: ai-security-orchestrator:2.0.0
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        - name: ENABLE_DISTRIBUTED
          value: "true"
        - name: ENABLE_LEARNING
          value: "true"
---
apiVersion: v1
kind: Service
metadata:
  name: ai-security-service
spec:
  selector:
    app: ai-security
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

Deploy:
```bash
kubectl apply -f deployment.yaml
```

---

## Configuration

### Environment Variables

```bash
# Redis
export REDIS_URL=redis://localhost:6379
export REDIS_PASSWORD=your_password

# Orchestrator
export ENABLE_DISTRIBUTED=true
export ENABLE_LEARNING=true
export CONFIDENCE_THRESHOLD=0.7

# Performance
export MAX_CONCURRENT_CHECKS=1000
export CHECK_TIMEOUT_MS=5000

# Logging
export LOG_LEVEL=INFO
export LOG_FORMAT=json
```

### Configuration File

Create `config.yaml`:

```yaml
orchestrator:
  redis_url: "redis://localhost:6379"
  distributed: true
  learning: true
  confidence_threshold: 0.7

detection:
  enable_semantic: true
  enable_behavioral: true
  enable_contextual: true
  enable_ml: true

monitoring:
  history_size: 10000
  flush_interval: 60
  enable_metrics: true

recovery:
  enable_auto_reroute: true
  fallback_chain:
    - backup_agent
    - safe_mode_agent
    - minimal_agent
```

Load configuration:
```python
import yaml

with open('config.yaml') as f:
    config = yaml.safe_load(f)

orchestrator = DynamicSecurityOrchestrator(**config['orchestrator'])
```

---

## Monitoring Setup

### Prometheus Metrics

```python
from prometheus_client import start_http_server

# Start metrics server
start_http_server(9090)

# Metrics are automatically exposed at http://localhost:9090/metrics
```

### Grafana Dashboard

1. Import `grafana/dashboard.json`
2. Configure Prometheus data source
3. View real-time metrics

### Logging

```python
import logging

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Or JSON logging
import json_logging
json_logging.init_fastapi(enable_json=True)
```

---

## Testing

### Run Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=ai_security_orchestrator --cov-report=html

# Specific test
pytest
```

### Integration Tests

```bash
# Start test server
ai-security serve --port 8000 &

# Run integration tests
pytest tests/integration/

# Stop server
pkill ai-security
```

---

## Production Checklist

Before deploying to production:

- [ ] Redis cluster configured and tested
- [ ] Distributed mode enabled
- [ ] Learning enabled with feedback loop
- [ ] Monitoring dashboards configured (Grafana)
- [ ] Alert rules configured (Prometheus)
- [ ] Load testing completed (>10k req/sec)
- [ ] Failure recovery tested
- [ ] API interception configured
- [ ] Log aggregation configured (ELK/Datadog)
- [ ] Backup and recovery procedures documented
- [ ] Security audit completed
- [ ] Performance benchmarks met (<50ms latency)
- [ ] High availability configured (3+ instances)
- [ ] Circuit breakers tested
- [ ] Rate limiting configured

---

## Troubleshooting

### Common Issues

#### 1. Import Error

```bash
# Error: Module not found
# Solution: Install in editable mode
pip install -e .
```

#### 2. Redis Connection Error

```bash
# Error: Cannot connect to Redis
# Solution: Check Redis is running
docker ps | grep redis

# Start if not running
docker run -d -p 6379:6379 redis:latest
```

#### 3. High Latency

```bash
# Check metrics
curl http://localhost:8000/metrics

# Enable distributed mode
export ENABLE_DISTRIBUTED=true

# Increase concurrent checks
export MAX_CONCURRENT_CHECKS=2000
```

#### 4. Memory Usage

```bash
# Reduce history size in config
monitoring:
  history_size: 1000  # Instead of 10000
```

---

## Performance Tuning

### For High Throughput

```python
# Increase concurrency
orchestrator = DynamicSecurityOrchestrator(
    max_concurrent_checks=5000
)

# Use distributed mode
orchestrator = DynamicSecurityOrchestrator(
    redis_url="redis://localhost:6379",
    enable_distributed=True
)
```

### For Low Latency

```python
# Disable learning (slight speedup)
orchestrator = DynamicSecurityOrchestrator(
    enable_learning=False  # ~5ms faster
)

# Reduce history size
monitor = AgentMonitor(history_size=100)
```

### For Large Scale

```yaml
# Scale horizontally with Kubernetes
replicas: 10

# Use Redis Cluster
redis_url: "redis://redis-cluster:6379"

# Configure load balancer
loadBalancer:
  algorithm: least_connections
```

---

## Upgrade Guide

### From 1.x to 2.0

```bash
# 1. Backup configuration
cp config.yaml config.yaml.backup

# 2. Upgrade package
pip install --upgrade ai-security-orchestrator

# 3. Update configuration (new fields)
# Add to config.yaml:
orchestrator:
  enable_learning: true  # NEW
  confidence_threshold: 0.7  # NEW

# 4. Restart services
ai-security serve
```

---

## Support

### Documentation
- Full docs: `/docs`
- API reference: `http://localhost:8000/docs` (when server running)
- Product spec: `PRODUCT_SPEC.md`

### Community
- GitHub Issues: Report bugs and feature requests
- Discussions: Ask questions and share ideas

### Enterprise Support
- Email: security@example.com
- Slack: #ai-security-support

---

## Next Steps

1. ✅ Integrate with your AI system (see examples above)
2. ✅ Deploy to staging environment
3. ✅ Load test and tune performance
4. ✅ Configure monitoring and alerts
5. ✅ Deploy to production
6. ✅ Monitor and learn from feedback

---

## License

MIT License - See LICENSE file for details

---

**Version**: 2.0.0
**Status**: Production Ready
**Support**: Enterprise-grade

For detailed feature documentation, see `PRODUCT_SPEC.md`.
