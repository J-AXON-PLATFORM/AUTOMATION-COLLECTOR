import io
import json
import os
import stat
from uuid import uuid4

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import jaxon_discovery_executor.sftp as executor_sftp
from jaxon_discovery_executor.identity import initialize_identity
from jaxon_discovery_executor.sftp import (
    ExecutorSftpConfigurationError,
    ExecutorSftpVerificationError,
    configure_sftp,
    verify_sftp,
)


def host_key() -> paramiko.Ed25519Key:
    private_key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return paramiko.Ed25519Key.from_private_key(io.StringIO(private_key.decode("ascii")))


def test_configures_exact_executor_idempotently_without_replacing_values(tmp_path) -> None:
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    public = f"ssh-ed25519 {key.get_base64()}"
    username = f"discovery-executor-{identity.executorId}"

    first = configure_sftp(str(state_dir), "sftp.example", 2022, username, public)
    before = (state_dir / "sftp.json").stat().st_mtime_ns
    second = configure_sftp(str(state_dir), "sftp.example", 2022, username, public)

    assert first.executorId == identity.executorId
    assert first.changed is True
    assert second.changed is False
    assert stat.S_IMODE((state_dir / "sftp.json").stat().st_mode) == 0o600
    assert (state_dir / "sftp.json").stat().st_mtime_ns == before
    assert initialize_identity(identity.executorId, str(state_dir)) == identity
    with pytest.raises(ExecutorSftpConfigurationError, match="different values"):
        configure_sftp(str(state_dir), "other.example", 2022, username, public)


def test_rejects_wrong_identity_username_and_host_key_without_writing(tmp_path) -> None:
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()

    with pytest.raises(ExecutorSftpConfigurationError, match="identity"):
        configure_sftp(
            str(state_dir),
            "sftp.example",
            2022,
            f"discovery-executor-{uuid4()}",
            f"ssh-ed25519 {key.get_base64()}",
        )
    with pytest.raises(ExecutorSftpConfigurationError, match="host-key"):
        configure_sftp(str(state_dir), "sftp.example", 2022, "invalid", "ssh-rsa AAAA")
    with pytest.raises(ExecutorSftpConfigurationError, match="host"):
        configure_sftp(
            str(state_dir),
            "a" * 254,
            2022,
            f"discovery-executor-{identity.executorId}",
            f"ssh-ed25519 {key.get_base64()}",
        )
    assert not (state_dir / "sftp.json").exists()


def test_verifies_once_with_pinned_host_and_exact_executor_key(tmp_path) -> None:
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    username = f"discovery-executor-{identity.executorId}"
    configured = configure_sftp(
        str(state_dir),
        "sftp.example",
        2022,
        username,
        f"ssh-ed25519 {key.get_base64()}",
    )
    calls = {"connect_count": 0}

    class Sftp:
        class Channel:
            def settimeout(self, value):
                calls["operation_timeout"] = value

        def get_channel(self):
            return self.Channel()

        def close(self):
            calls["sftp_closed"] = True

    class Client:
        def __init__(self):
            self.keys = paramiko.HostKeys()

        def set_missing_host_key_policy(self, policy):
            calls["policy"] = policy

        def get_host_keys(self):
            calls["keys"] = self.keys
            return self.keys

        def connect(self, **kwargs):
            calls["connect_count"] += 1
            calls["connect"] = kwargs

        def open_sftp(self):
            calls["opened"] = True
            return Sftp()

        def close(self):
            calls["client_closed"] = True

    result = verify_sftp(str(state_dir), Client)

    assert result.status == "verified"
    assert result.executorId == identity.executorId
    assert result.hostKeyFingerprint == configured.hostKeyFingerprint
    assert isinstance(calls["policy"], paramiko.RejectPolicy)
    assert list(calls["keys"]) == ["[sftp.example]:2022"]
    assert calls["keys"].lookup("[sftp.example]:2022")["ssh-ed25519"] == key
    connection = calls["connect"]
    assert isinstance(connection["pkey"], paramiko.Ed25519Key)
    assert connection["pkey"].get_base64() == identity.publicKey.split()[1]
    assert connection["allow_agent"] is False
    assert connection["look_for_keys"] is False
    assert connection["timeout"] == 10
    assert connection["banner_timeout"] == 10
    assert connection["auth_timeout"] == 10
    assert connection["channel_timeout"] == 60
    assert calls["operation_timeout"] == 60
    assert calls["connect_count"] == 1
    assert "password" not in connection and "key_filename" not in connection
    assert calls["opened"] and calls["sftp_closed"] and calls["client_closed"]
    assert "PRIVATE KEY" not in result.to_json()


def test_configuration_is_closed_private_and_fail_closed(tmp_path) -> None:
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    configure_sftp(
        str(state_dir),
        "sftp.example",
        22,
        f"discovery-executor-{identity.executorId}",
        f"ssh-ed25519 {key.get_base64()}",
    )

    config_path = state_dir / "sftp.json"
    config = json.loads(config_path.read_text())
    assert set(config) == {
        "formatVersion",
        "host",
        "hostKey",
        "hostKeyFingerprint",
        "port",
        "username",
    }
    assert identity.publicKey not in config_path.read_text()

    config["unexpected"] = True
    config_path.write_text(json.dumps(config))
    os.chmod(config_path, 0o600)
    with pytest.raises(ExecutorSftpVerificationError, match="not valid"):
        verify_sftp(str(state_dir))


def test_rejects_unsafe_configuration_and_connection_failure_without_retry(tmp_path) -> None:
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    configure_sftp(
        str(state_dir),
        "sftp.example",
        22,
        f"discovery-executor-{identity.executorId}",
        f"ssh-ed25519 {key.get_base64()}",
    )
    os.chmod(state_dir / "sftp.json", 0o644)
    with pytest.raises(Exception, match="not valid"):
        verify_sftp(str(state_dir))

    os.chmod(state_dir / "sftp.json", 0o600)
    calls = 0

    class FailingClient:
        def __init__(self):
            self.keys = paramiko.HostKeys()

        def set_missing_host_key_policy(self, _policy):
            pass

        def get_host_keys(self):
            return self.keys

        def connect(self, **_kwargs):
            nonlocal calls
            calls += 1
            raise paramiko.AuthenticationException("sensitive")

        def close(self):
            pass

    with pytest.raises(ExecutorSftpVerificationError, match="verified securely"):
        verify_sftp(str(state_dir), FailingClient)
    assert calls == 1


def test_rejects_symlink_fifo_and_overlong_stored_host_safely(tmp_path) -> None:
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    username = f"discovery-executor-{identity.executorId}"
    configure_sftp(str(state_dir), "sftp.example", 22, username, f"ssh-ed25519 {key.get_base64()}")
    config_path = state_dir / "sftp.json"
    valid_content = config_path.read_bytes()

    config_path.unlink()
    config_path.symlink_to(state_dir / "executor.json")
    with pytest.raises(ExecutorSftpVerificationError, match="not valid"):
        verify_sftp(str(state_dir))

    config_path.unlink()
    os.mkfifo(config_path, mode=0o600)
    with pytest.raises(ExecutorSftpVerificationError, match="not valid"):
        verify_sftp(str(state_dir))

    config_path.unlink()
    config = json.loads(valid_content)
    config["host"] = "a" * 254
    config_path.write_text(json.dumps(config))
    os.chmod(config_path, 0o600)
    with pytest.raises(ExecutorSftpVerificationError, match="not valid"):
        verify_sftp(str(state_dir))


def test_rejects_private_key_changed_after_identity_validation(tmp_path, monkeypatch) -> None:
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    configure_sftp(
        str(state_dir),
        "sftp.example",
        22,
        f"discovery-executor-{identity.executorId}",
        f"ssh-ed25519 {key.get_base64()}",
    )
    replacement = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    original_read = executor_sftp._read_private_file
    private_reads = 0

    def replacing_read(descriptor, name):
        nonlocal private_reads
        content = original_read(descriptor, name)
        if name == "executor_ed25519":
            private_reads += 1
            if private_reads == 1:
                return replacement
        return content

    monkeypatch.setattr(executor_sftp, "_read_private_file", replacing_read)
    with pytest.raises(ExecutorSftpVerificationError, match="not valid"):
        verify_sftp(str(state_dir))
