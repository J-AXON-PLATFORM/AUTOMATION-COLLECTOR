import json
import subprocess
import sys
from uuid import uuid4

import pytest

import jaxon_agent
import jaxon_agent.__main__ as agent_main
from jaxon_agent.__main__ import main
from jaxon_agent.snapshot import SnapshotSendResult


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


def test_agent_send_snapshot_command_exposes_only_safe_metadata(monkeypatch, capsys) -> None:
    result = SnapshotSendResult(
        agentId="0c504dfb-15d6-431d-b1f4-f64354a44b21",
        capturedAt="2026-10-15T12:00:00.000Z",
        createdAt="2026-10-15T12:00:00.000Z",
        messageId="d9bdb20c-9b56-4b91-8c4a-a83f64d5802a",
        remotePath="/snapshots/d9bdb20c-9b56-4b91-8c4a-a83f64d5802a.json",
        snapshotId="069cc5e5-f8dc-405a-94eb-5b6eef59a335",
        status="SENT",
    )
    monkeypatch.setattr(agent_main, "send_snapshot", lambda state_dir: result)

    assert main(["send-snapshot", "--state-dir", "/private/state"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "agentId": result.agentId,
        "capturedAt": result.capturedAt,
        "createdAt": result.createdAt,
        "messageId": result.messageId,
        "remotePath": result.remotePath,
        "snapshotId": result.snapshotId,
        "status": "SENT",
    }
    assert "PRIVATE KEY" not in captured.out
    assert "ssh-ed25519" not in captured.out
    assert "hostname" not in captured.out
    assert captured.err == ""
