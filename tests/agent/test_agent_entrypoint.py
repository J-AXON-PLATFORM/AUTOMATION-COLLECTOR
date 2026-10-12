import json
import subprocess
import sys
from uuid import uuid4

import pytest

import jaxon_agent
from jaxon_agent.__main__ import main


def test_agent_identity() -> None:
    assert jaxon_agent.PROGRAM_NAME == "J-AXON Agent"
    assert jaxon_agent.__version__ == "0.1.0"


def test_agent_main(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert capsys.readouterr().out == "J-AXON Agent 0.1.0\n"


def test_agent_module_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "jaxon_agent"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout == "J-AXON Agent 0.1.0\n"
    assert "Discovery Executor" not in result.stdout


def test_agent_initialize_command(tmp_path, capsys) -> None:
    state_dir = tmp_path / "agent-state"
    agent_id = str(uuid4())

    assert main(["initialize", "--agent-id", agent_id, "--state-dir", str(state_dir)]) == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["agentId"] == agent_id
    assert output["publicKey"].startswith("ssh-ed25519 ")
    assert output["publicKeyFingerprint"].startswith("SHA256:")
    assert "PRIVATE KEY" not in captured.out
    assert captured.err == ""


def test_agent_initialize_rejects_invalid_uuid(tmp_path, capsys) -> None:
    state_dir = tmp_path / "agent-state"

    assert main(["initialize", "--agent-id", "not-a-uuid", "--state-dir", str(state_dir)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "UUIDv4" in captured.err
    assert not state_dir.exists()
