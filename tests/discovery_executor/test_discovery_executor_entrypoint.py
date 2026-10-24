import json
import subprocess
import sys
from uuid import uuid4

import pytest

import jaxon_discovery_executor
from jaxon_discovery_executor.__main__ import main


def test_discovery_executor_identity() -> None:
    assert jaxon_discovery_executor.PROGRAM_NAME == "J-AXON Discovery Executor"
    assert jaxon_discovery_executor.__version__ == "0.1.0"


def test_discovery_executor_main(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert capsys.readouterr().out == "J-AXON Discovery Executor 0.1.0\n"


def test_discovery_executor_module_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "jaxon_discovery_executor"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout == "J-AXON Discovery Executor 0.1.0\n"
    assert result.stdout != "J-AXON Agent 0.1.0\n"


def test_discovery_executor_initialize_command(tmp_path, capsys) -> None:
    executor_id = str(uuid4())
    state_dir = tmp_path / "executor-state"

    assert main(["initialize", "--executor-id", executor_id, "--state-dir", str(state_dir)]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["executorId"] == executor_id
    assert output["publicKeyPath"] == str(state_dir / "executor_ed25519.pub")
    assert output["publicKey"].startswith("ssh-ed25519 ")
    assert output["publicKeyFingerprint"].startswith("SHA256:")
    assert "private" not in output


def test_discovery_executor_initialize_rejects_invalid_id(tmp_path, capsys) -> None:
    state_dir = tmp_path / "executor-state"

    assert main(["initialize", "--executor-id", "invalid", "--state-dir", str(state_dir)]) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert "UUIDv4" in output.err
    assert not state_dir.exists()
