import os
import click

@click.group()
@click.option("--config-dir", default=os.path.expanduser("~/.agentdid"), help="Config directory")
@click.option("--api-url", default="https://agentdid-api.fly.dev/v1", help="API base URL")
@click.pass_context
def cli(ctx, config_dir, api_url):
    """agentdid: Cryptographic proof that a human stands behind an AI agent."""
    ctx.ensure_object(dict)
    ctx.obj["config_dir"] = config_dir
    ctx.obj["api_url"] = api_url

# Import commands to register them
import agentdid.cli.keygen
import agentdid.cli.register
import agentdid.cli.verify
import agentdid.cli.email
import agentdid.cli.revoke
import agentdid.cli.credential
