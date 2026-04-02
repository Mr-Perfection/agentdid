from agentproof.cli.main import cli

def test_keygen_creates_files(runner, tmp_path):
    result = runner.invoke(cli, ["--config-dir", str(tmp_path), "keygen"])
    assert result.exit_code == 0
    assert (tmp_path / "agent.pub").exists()
    assert (tmp_path / "agent.key").exists()
    pub_content = (tmp_path / "agent.pub").read_text().strip()
    assert len(pub_content) == 64

def test_keygen_refuses_overwrite(runner, tmp_path):
    runner.invoke(cli, ["--config-dir", str(tmp_path), "keygen"])
    result = runner.invoke(cli, ["--config-dir", str(tmp_path), "keygen"])
    assert result.exit_code != 0 or "already exists" in result.output

def test_keygen_force_overwrite(runner, tmp_path):
    runner.invoke(cli, ["--config-dir", str(tmp_path), "keygen"])
    result = runner.invoke(cli, ["--config-dir", str(tmp_path), "keygen", "--force"])
    assert result.exit_code == 0

def test_keygen_key_file_permissions(runner, tmp_path):
    result = runner.invoke(cli, ["--config-dir", str(tmp_path), "keygen"])
    assert result.exit_code == 0
    key_path = tmp_path / "agent.key"
    mode = oct(key_path.stat().st_mode & 0o777)
    assert mode == "0o600"
