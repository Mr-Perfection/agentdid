from unittest.mock import patch, MagicMock
from agentdid.cli.main import cli
from agentdid.core.crypto import generate_keypair

def _setup_keys(tmp_path):
    private_key, public_key = generate_keypair()
    (tmp_path / "agent.key").write_bytes(private_key)
    (tmp_path / "agent.pub").write_text(public_key.hex())
    return private_key, public_key

def test_register_success(runner, tmp_path):
    _setup_keys(tmp_path)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"did": "did:key:z6MkTest", "verification_level": 0, "credential_jwt": "eyJ..."}
    with patch("agentdid.cli.register.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, ["--config-dir", str(tmp_path), "register", "--name", "my-agent"])
    assert result.exit_code == 0
    assert "did:key:z6MkTest" in result.output
    assert (tmp_path / "config.toml").exists()
    assert (tmp_path / "credential.jwt").exists()

def test_register_no_keys(runner, tmp_path):
    result = runner.invoke(cli, ["--config-dir", str(tmp_path), "register", "--name", "my-agent"])
    assert result.exit_code != 0 or "No keypair found" in result.output
