from unittest.mock import patch, MagicMock
import tomli_w
from agentdid.cli.main import cli
from agentdid.core.crypto import generate_keypair

def _setup_registered_agent(tmp_path):
    private_key, public_key = generate_keypair()
    (tmp_path / "agent.key").write_bytes(private_key)
    (tmp_path / "agent.pub").write_text(public_key.hex())
    config = {"api_url": "https://api.rureal.ai/v1", "did": "did:key:z6MkTest"}
    with open(tmp_path / "config.toml", "wb") as f:
        tomli_w.dump(config, f)

def test_revoke_success(runner, tmp_path):
    _setup_registered_agent(tmp_path)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"did": "did:key:z6MkTest", "revoked": True}
    with patch("agentdid.cli.revoke.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, ["--config-dir", str(tmp_path), "revoke"])
    assert result.exit_code == 0
    assert "revoked" in result.output.lower()
