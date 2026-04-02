import os
import click

@click.group()
@click.option("--config-dir", default=os.path.expanduser("~/.agentproof"), help="Config directory")
@click.option("--api-url", default="https://api.agentproof.dev/v1", help="API base URL")
@click.pass_context
def cli(ctx, config_dir, api_url):
    """AgentProof: Cryptographic proof that a human stands behind an AI agent."""
    ctx.ensure_object(dict)
    ctx.obj["config_dir"] = config_dir
    ctx.obj["api_url"] = api_url

# Import commands to register them
import agentproof.cli.keygen
import agentproof.cli.register
import agentproof.cli.verify
import agentproof.cli.email
import agentproof.cli.revoke
import agentproof.cli.credential
