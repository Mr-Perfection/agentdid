from unittest.mock import patch, MagicMock
from agentdid.cli.main import cli

def test_verify_agent_success(runner):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "did": "did:key:z6MkTest", "display_name": "my-agent", "verification_level": 1,
        "email_verified": True, "valid": True, "revoked": False,
        "created_at": "2026-04-01T00:00:00+00:00", "credential_expires": "2026-07-01T00:00:00+00:00",
    }
    with patch("agentdid.cli.verify.httpx.get", return_value=mock_response):
        result = runner.invoke(cli, ["verify", "did:key:z6MkTest"])
    assert result.exit_code == 0
    assert "my-agent" in result.output
    assert "Level: 1" in result.output

def test_verify_agent_not_found(runner):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {"detail": "Agent not found"}
    with patch("agentdid.cli.verify.httpx.get", return_value=mock_response):
        result = runner.invoke(cli, ["verify", "did:key:z6MkNotFound"])
    assert result.exit_code != 0 or "not found" in result.output.lower()
