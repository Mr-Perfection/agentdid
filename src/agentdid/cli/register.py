import hashlib
import os
from datetime import datetime, timezone
import click
import httpx
import tomli_w
from agentdid.cli.main import cli
from agentdid.core.crypto import sign_payload

@cli.command()
@click.option("--name", default=None, help="Display name for the agent")
@click.option("--email", default=None, help="Owner email for L1 verification")
@click.pass_context
def register(ctx, name, email):
    """Register your agent with agentdid."""
    config_dir = ctx.obj["config_dir"]
    api_url = ctx.obj["api_url"]
    key_path = os.path.join(config_dir, "agent.key")
    pub_path = os.path.join(config_dir, "agent.pub")
    if not os.path.exists(key_path) or not os.path.exists(pub_path):
        click.echo("No keypair found. Run `agentdid keygen` first.")
        ctx.exit(1)
        return
    private_key = open(key_path, "rb").read()
    public_key_hex = open(pub_path, "r").read().strip()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key_hex}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    body = {"public_key": public_key_hex, "timestamp": timestamp, "signature": signature.hex()}
    if name: body["display_name"] = name
    if email: body["owner_email"] = email
    response = httpx.post(f"{api_url}/agents/register", json=body)
    if response.status_code != 200:
        click.echo(f"Registration failed: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return
    data = response.json()
    config = {"api_url": api_url, "did": data["did"]}
    with open(os.path.join(config_dir, "config.toml"), "wb") as f:
        tomli_w.dump(config, f)
    with open(os.path.join(config_dir, "credential.jwt"), "w") as f:
        f.write(data["credential_jwt"])
    click.echo(f"Registered {data['did']}  (Level {data['verification_level']})")
