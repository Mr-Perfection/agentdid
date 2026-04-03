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

def test_verify_email_sends_code(runner, tmp_path):
    _setup_registered_agent(tmp_path)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": "Verification code sent"}
    with patch("agentdid.cli.email.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, ["--config-dir", str(tmp_path), "verify-email", "--email", "test@example.com"])
    assert result.exit_code == 0
    assert "code" in result.output.lower() or "Check your email" in result.output

def test_confirm_email_success(runner, tmp_path):
    _setup_registered_agent(tmp_path)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"verification_level": 1, "credential_jwt": "eyJ..."}
    with patch("agentdid.cli.email.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, ["--config-dir", str(tmp_path), "confirm-email", "--code", "123456"])
    assert result.exit_code == 0
    assert "Level 1" in result.output or "verified" in result.output.lower()
    assert (tmp_path / "credential.jwt").read_text() == "eyJ..."
