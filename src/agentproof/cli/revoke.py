import hashlib
import os
from datetime import datetime, timezone
import click
import httpx
import tomllib
from agentproof.cli.main import cli
from agentproof.core.crypto import sign_payload

@cli.command()
@click.pass_context
def revoke(ctx):
    """Revoke your agent's credential."""
    config_dir = ctx.obj["config_dir"]
    key_path = os.path.join(config_dir, "agent.key")
    config_path = os.path.join(config_dir, "config.toml")
    if not os.path.exists(key_path) or not os.path.exists(config_path):
        click.echo("No registered agent found. Run `agentproof register` first.")
        ctx.exit(1)
        return
    private_key = open(key_path, "rb").read()
    with open(config_path, "rb") as f:
        config = tomllib.load(f)
    did = config["did"]
    api_url = config.get("api_url", ctx.obj["api_url"])
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:revoke:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = httpx.post(f"{api_url}/agents/{did}/revoke", json={"timestamp": timestamp, "signature": signature.hex()})
    if response.status_code != 200:
        click.echo(f"Error: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return
    click.echo("Agent credential revoked.")
