import hashlib
import os
import sys
from datetime import datetime, timezone
import click
import httpx
from agentdid.cli.main import cli
from agentdid.core.crypto import sign_payload

def _load_agent_context(ctx):
    config_dir = ctx.obj["config_dir"]
    key_path = os.path.join(config_dir, "agent.key")
    config_path = os.path.join(config_dir, "config.toml")
    if not os.path.exists(key_path) or not os.path.exists(config_path):
        click.echo("No registered agent found. Run `agentdid register` first.")
        ctx.exit(1)
        return None, None, None
    private_key = open(key_path, "rb").read()
    import tomllib
    with open(config_path, "rb") as f:
        config = tomllib.load(f)
    return private_key, config["did"], config.get("api_url", ctx.obj["api_url"])

def _sign_mutation(private_key, did, action):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    return timestamp, signature

@cli.command("verify-email")
@click.option("--email", required=True, help="Email address to verify")
@click.pass_context
def verify_email(ctx, email):
    """Send a verification code to your email."""
    private_key, did, api_url = _load_agent_context(ctx)
    if private_key is None: return
    timestamp, signature = _sign_mutation(private_key, did, "verify-email")
    response = httpx.post(f"{api_url}/agents/{did}/verify-email", json={
        "timestamp": timestamp, "signature": signature.hex(),
    })
    if response.status_code != 200:
        click.echo(f"Error: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return
    click.echo("Check your email for a 6-digit code.")

@cli.command("confirm-email")
@click.option("--code", required=True, help="6-digit verification code")
@click.pass_context
def confirm_email(ctx, code):
    """Submit your verification code to upgrade to Level 1."""
    config_dir = ctx.obj["config_dir"]
    private_key, did, api_url = _load_agent_context(ctx)
    if private_key is None: return
    timestamp, signature = _sign_mutation(private_key, did, "confirm-email")
    response = httpx.post(f"{api_url}/agents/{did}/confirm-email", json={
        "code": code, "timestamp": timestamp, "signature": signature.hex(),
    })
    if response.status_code != 200:
        click.echo(f"Error: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return
    data = response.json()
    with open(os.path.join(config_dir, "credential.jwt"), "w") as f:
        f.write(data["credential_jwt"])
    click.echo(f"Email verified. Upgraded to Level {data['verification_level']}.")
