import click
import httpx
from agentproof.cli.main import cli

@cli.command()
@click.argument("did")
@click.pass_context
def verify(ctx, did):
    """Verify an agent by DID."""
    api_url = ctx.obj["api_url"]
    response = httpx.get(f"{api_url}/agents/{did}/verify")
    if response.status_code == 404:
        click.echo(f"Agent not found: {did}")
        ctx.exit(1)
        return
    if response.status_code != 200:
        click.echo(f"Error: {response.text}")
        ctx.exit(1)
        return
    data = response.json()
    level_desc = {0: "registered", 1: "email verified"}
    level = data["verification_level"]
    click.echo(f"  Agent: {data.get('display_name') or '(unnamed)'}")
    click.echo(f"  DID:   {data['did']}")
    click.echo(f"  Level: {level} ({level_desc.get(level, 'unknown')})")
    valid_mark = "Valid" if data["valid"] else "INVALID"
    if data["revoked"]: valid_mark = "REVOKED"
    expires = data.get("credential_expires", "unknown")
    click.echo(f"  Status: {valid_mark} (expires {expires})")
