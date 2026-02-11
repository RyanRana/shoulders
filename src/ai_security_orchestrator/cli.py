"""
CLI Interface for AI Security Orchestrator
"""
import asyncio
import click
import uvicorn
import logging
from typing import Optional

from .core.orchestrator import DynamicSecurityOrchestrator
from .monitors.agent_monitor import AgentMonitor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version='2.0.0')
def main():
    """AI Security Orchestrator CLI"""
    pass


@main.command()
@click.option('--host', default='0.0.0.0', help='Host to bind')
@click.option('--port', default=8000, help='Port to bind')
@click.option('--workers', default=1, help='Number of workers')
@click.option('--redis-url', help='Redis URL for distributed mode')
@click.option('--enable-distributed/--no-distributed', default=False)
@click.option('--enable-learning/--no-learning', default=True)
def serve(host, port, workers, redis_url, enable_distributed, enable_learning):
    """Start the security server"""
    click.echo(f"Starting AI Security Orchestrator on {host}:{port}")
    click.echo(f"Workers: {workers}")
    click.echo(f"Distributed: {enable_distributed}")
    click.echo(f"Learning: {enable_learning}")

    # Import FastAPI app
    from .api import create_app

    app = create_app(
        redis_url=redis_url,
        enable_distributed=enable_distributed,
        enable_learning=enable_learning
    )

    uvicorn.run(
        app,
        host=host,
        port=port,
        workers=workers
    )


@main.command()
@click.argument('input_text')
@click.option('--agent-id', default='cli', help='Agent ID')
@click.option('--response', help='Agent response to verify')
@click.option('--redis-url', help='Redis URL')
def check(input_text, agent_id, response, redis_url):
    """Run security check on input"""
    click.echo("Running security check...")

    async def _check():
        orchestrator = DynamicSecurityOrchestrator(
            redis_url=redis_url,
            enable_distributed=bool(redis_url)
        )

        result = await orchestrator.check_async(
            input_text=input_text,
            agent_id=agent_id,
            response=response
        )

        return result

    result = asyncio.run(_check())

    if result['blocked']:
        click.secho("🚫 BLOCKED", fg='red', bold=True)
        click.echo(f"Threats detected: {len(result['threats'])}")
        for threat in result['threats']:
            click.echo(f"  - {threat['layer']}: {threat['reason']}")

        if 'recovery' in result:
            click.secho("\n✅ Recovery Action:", fg='green')
            click.echo(f"  Action: {result['recovery']['action']}")
            click.echo(f"  Fallback: {result['recovery'].get('fallback_agent', 'N/A')}")
    else:
        click.secho("✅ ALLOWED", fg='green', bold=True)

    click.echo(f"\nLatency: {result['latency_ms']:.2f}ms")


@main.command()
@click.option('--redis-url', help='Redis URL')
def monitor(redis_url):
    """Start interactive monitoring"""
    click.echo("Starting agent monitor...")

    async def _monitor():
        monitor = AgentMonitor(
            redis_client=None,  # Would connect to Redis if provided
            distributed=bool(redis_url)
        )

        click.echo("\nMonitoring agents. Press Ctrl+C to stop.\n")

        try:
            while True:
                stats = monitor.get_all_agent_stats()

                click.clear()
                click.secho("=== Agent Monitor ===", bold=True)
                click.echo(f"Total agents: {stats['total_agents']}")
                click.echo(f"Total actions: {stats['total_actions']}")
                click.echo()

                for agent_id, agent_stats in stats['agents'].items():
                    status = agent_stats['status']
                    color = 'green' if status == 'healthy' else 'yellow' if status == 'suspicious' else 'red'

                    click.secho(f"Agent: {agent_id}", bold=True)
                    click.secho(f"  Status: {status}", fg=color)
                    click.echo(f"  Score: {agent_stats['score']:.2f}")
                    click.echo(f"  Actions: {agent_stats['actions']}")
                    click.echo(f"  Anomalies: {agent_stats['anomalies']}")
                    click.echo()

                await asyncio.sleep(5)

        except KeyboardInterrupt:
            click.echo("\nMonitoring stopped.")

    asyncio.run(_monitor())


@main.command()
@click.option('--redis-url', help='Redis URL')
def stats(redis_url):
    """Show system statistics"""
    async def _stats():
        orchestrator = DynamicSecurityOrchestrator(
            redis_url=redis_url,
            enable_distributed=bool(redis_url)
        )

        metrics = orchestrator.get_metrics()

        click.secho("=== System Statistics ===", bold=True)
        click.echo(f"Total checks: {metrics['total_checks']}")
        click.echo(f"Threats blocked: {metrics['threats_blocked']}")
        click.echo(f"Failures recovered: {metrics['failures_recovered']}")
        click.echo(f"Average latency: {metrics['avg_latency_ms']:.2f}ms")
        click.echo(f"Distributed mode: {metrics['distributed_mode']}")
        click.echo(f"Learning enabled: {metrics['learning_enabled']}")

    asyncio.run(_stats())


if __name__ == '__main__':
    main()
