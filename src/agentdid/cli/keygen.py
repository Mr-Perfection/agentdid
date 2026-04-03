import os
import stat
import click
from agentdid.cli.main import cli
from agentdid.core.crypto import generate_keypair

@cli.command()
@click.option("--force", is_flag=True, help="Overwrite existing keys")
@click.pass_context
def keygen(ctx, force):
    """Generate a new Ed25519 keypair."""
    config_dir = ctx.obj["config_dir"]
    os.makedirs(config_dir, exist_ok=True)
    key_path = os.path.join(config_dir, "agent.key")
    pub_path = os.path.join(config_dir, "agent.pub")
    if os.path.exists(key_path) and not force:
        click.echo(f"Key already exists at {key_path}. Use --force to overwrite.")
        ctx.exit(1)
        return
    private_key, public_key = generate_keypair()
    with open(key_path, "wb") as f:
        f.write(private_key)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    with open(pub_path, "w") as f:
        f.write(public_key.hex())
    click.echo(f"Keypair generated:")
    click.echo(f"  Private key: {key_path}")
    click.echo(f"  Public key:  {pub_path}")
