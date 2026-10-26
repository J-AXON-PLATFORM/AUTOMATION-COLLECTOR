import io
import json
import os
import subprocess
import sys
from uuid import uuid4

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import jaxon_discovery_executor
from jaxon_discovery_executor.__main__ import main
from jaxon_discovery_executor.ledger import DiscoveryLedger


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


def test_discovery_executor_configure_sftp_command(tmp_path, capsys) -> None:
    executor_id = str(uuid4())
    state_dir = tmp_path / "executor-state"
    main(["initialize", "--executor-id", executor_id, "--state-dir", str(state_dir)])
    capsys.readouterr()
    private_key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    host_key = paramiko.Ed25519Key.from_private_key(io.StringIO(private_key.decode("ascii")))

    assert (
        main(
            [
                "configure-sftp",
                "--state-dir",
                str(state_dir),
                "--host",
                "sftp.example",
                "--port",
                "2022",
                "--username",
                f"discovery-executor-{executor_id}",
                "--host-key",
                f"ssh-ed25519 {host_key.get_base64()}",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["executorId"] == executor_id
    assert output["changed"] is True
    assert "PRIVATE KEY" not in json.dumps(output)


def test_discovery_executor_verify_sftp_command(tmp_path, capsys, monkeypatch) -> None:
    class Result:
        def to_json(self):
            return '{"status":"verified"}'

    monkeypatch.setattr(
        "jaxon_discovery_executor.__main__.verify_sftp", lambda _state_dir: Result()
    )

    assert main(["verify-sftp", "--state-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "verified"}


def test_discovery_executor_run_once_command(tmp_path, capsys, monkeypatch) -> None:
    class Result:
        def to_json(self):
            return '{"status":"IDLE"}'

    monkeypatch.setattr("jaxon_discovery_executor.__main__.run_once", lambda _state_dir: Result())

    assert main(["run-once", "--state-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "IDLE"}


def test_run_once_reports_corrupt_ledger_without_traceback_or_path(tmp_path, capsys) -> None:
    executor_id = str(uuid4())
    state_dir = tmp_path / "executor-state"
    main(["initialize", "--executor-id", executor_id, "--state-dir", str(state_dir)])
    capsys.readouterr()
    private_key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    host_key = paramiko.Ed25519Key.from_private_key(io.StringIO(private_key.decode("ascii")))
    assert (
        main(
            [
                "configure-sftp",
                "--state-dir",
                str(state_dir),
                "--host",
                "sftp.example",
                "--port",
                "2022",
                "--username",
                f"discovery-executor-{executor_id}",
                "--host-key",
                f"ssh-ed25519 {host_key.get_base64()}",
            ]
        )
        == 0
    )
    capsys.readouterr()
    job_id = str(uuid4())
    with DiscoveryLedger(str(state_dir)) as ledger:
        ledger.receive(job_id, b"{}", str(uuid4()), "2026-10-25T12:09:00Z")
    record = state_dir / "discovery-ledger" / f"{job_id}.json"
    value = json.loads(record.read_bytes())
    value["startedAt"] = None
    record.write_text(json.dumps(value))
    os.chmod(record, 0o600)

    assert main(["run-once", "--state-dir", str(state_dir)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "safe local, contract or SFTP failure" in output.err
    assert "Traceback" not in output.err
    assert str(state_dir) not in output.err
