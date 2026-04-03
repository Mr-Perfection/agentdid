import json
import os
import tomllib
import click
from agentdid.cli.main import cli

@cli.command()
@click.option("--format", "fmt", type=click.Choice(["jwt", "agent-card"]), default="jwt", help="Output format")
@click.pass_context
def credential(ctx, fmt):
    """Export your agent's credential."""
    config_dir = ctx.obj["config_dir"]
    cred_path = os.path.join(config_dir, "credential.jwt")
    config_path = os.path.join(config_dir, "config.toml")
    if not os.path.exists(cred_path):
        click.echo("No credential found. Run `agentdid register` first.")
        ctx.exit(1)
        return
    credential_jwt = open(cred_path, "r").read().strip()
    if fmt == "jwt":
        click.echo(credential_jwt)
        return
    with open(config_path, "rb") as f:
        config = tomllib.load(f)
    agent_card = {
        "id": config["did"],
        "verification": {"type": "AgentDID", "issuer": "did:web:rureal.ai", "credential": credential_jwt},
    }
    click.echo(json.dumps(agent_card, indent=2))
