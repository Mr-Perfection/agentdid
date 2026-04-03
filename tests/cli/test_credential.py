import json
import tomli_w
from agentdid.cli.main import cli

def test_credential_jwt(runner, tmp_path):
    (tmp_path / "credential.jwt").write_text("eyJhbGciOiJFZERTQSJ9.test.sig")
    with open(tmp_path / "config.toml", "wb") as f:
        tomli_w.dump({"did": "did:key:z6MkTest", "api_url": "http://test"}, f)
    result = runner.invoke(cli, ["--config-dir", str(tmp_path), "credential", "--format", "jwt"])
    assert result.exit_code == 0
    assert "eyJhbGciOiJFZERTQSJ9.test.sig" in result.output

def test_credential_agent_card(runner, tmp_path):
    (tmp_path / "credential.jwt").write_text("eyJhbGciOiJFZERTQSJ9.test.sig")
    with open(tmp_path / "config.toml", "wb") as f:
        tomli_w.dump({"did": "did:key:z6MkTest", "api_url": "http://test"}, f)
    result = runner.invoke(cli, ["--config-dir", str(tmp_path), "credential", "--format", "agent-card"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["id"] == "did:key:z6MkTest"
    assert "rureal" in data["verification"]["issuer"].lower()
