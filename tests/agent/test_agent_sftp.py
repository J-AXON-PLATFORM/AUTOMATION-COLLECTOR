import io
import json
import os
import stat
from uuid import uuid4

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jaxon_agent.identity import initialize_identity
from jaxon_agent.sftp import SftpConfigurationError, configure_sftp, verify_sftp


def host_key() -> paramiko.Ed25519Key:
    private_key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return paramiko.Ed25519Key.from_private_key(io.StringIO(private_key.decode("ascii")))


def test_configures_sftp_idempotently_without_replacing_values(tmp_path) -> None:
    state_dir = tmp_path / "agent"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    public = f"ssh-ed25519 {key.get_base64()}"

    first = configure_sftp(str(state_dir), "sftp.example", 2022, "agent-test", public)
    before = (state_dir / "sftp.json").stat().st_mtime_ns
    second = configure_sftp(str(state_dir), "sftp.example", 2022, "agent-test", public)

    assert first.agentId == identity.agentId
    assert first.changed is True
    assert second.changed is False
    assert second.hostKeyFingerprint.startswith("SHA256:")
    assert stat.S_IMODE((state_dir / "sftp.json").stat().st_mode) == 0o600
    assert (state_dir / "sftp.json").stat().st_mtime_ns == before
    assert initialize_identity(identity.agentId, str(state_dir)) == identity
    with pytest.raises(SftpConfigurationError, match="different values"):
        configure_sftp(str(state_dir), "other.example", 2022, "agent-test", public)


def test_rejects_invalid_configuration_without_writing(tmp_path) -> None:
    state_dir = tmp_path / "agent"
    initialize_identity(str(uuid4()), str(state_dir))

    with pytest.raises(SftpConfigurationError, match="host-key"):
        configure_sftp(str(state_dir), "sftp.example", 2022, "agent-test", "ssh-rsa AAAA")
    assert not (state_dir / "sftp.json").exists()


def test_verifies_with_only_pinned_host_and_exact_identity_key(tmp_path) -> None:
    state_dir = tmp_path / "agent"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    public = f"ssh-ed25519 {key.get_base64()}"
    configured = configure_sftp(str(state_dir), "sftp.example", 2022, "agent-test", public)
    calls = {}

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
            calls["connect"] = kwargs

        def open_sftp(self):
            calls["opened"] = True
            return Sftp()

        def close(self):
            calls["client_closed"] = True

    result = verify_sftp(str(state_dir), Client)

    assert result.status == "verified"
    assert result.agentId == identity.agentId
    assert result.hostKeyFingerprint == configured.hostKeyFingerprint
    assert isinstance(calls["policy"], paramiko.RejectPolicy)
    assert list(calls["keys"]) == ["[sftp.example]:2022"]
    assert calls["keys"].lookup("[sftp.example]:2022")["ssh-ed25519"] == key
    connection = calls["connect"]
    assert isinstance(connection["pkey"], paramiko.Ed25519Key)
    assert connection["allow_agent"] is False
    assert connection["look_for_keys"] is False
    assert connection["timeout"] == 10
    assert connection["banner_timeout"] == 10
    assert connection["auth_timeout"] == 10
    assert connection["channel_timeout"] == 60
    assert calls["operation_timeout"] == 60
    assert "password" not in connection and "key_filename" not in connection
    assert calls["opened"] and calls["sftp_closed"] and calls["client_closed"]
    assert "PRIVATE KEY" not in result.to_json()


def test_rejects_unsafe_config_file(tmp_path) -> None:
    state_dir = tmp_path / "agent"
    initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    configure_sftp(
        str(state_dir), "sftp.example", 2022, "agent-test", f"ssh-ed25519 {key.get_base64()}"
    )
    os.chmod(state_dir / "sftp.json", 0o644)

    with pytest.raises(Exception, match="not valid"):
        verify_sftp(str(state_dir))


def test_configuration_contains_no_private_material(tmp_path) -> None:
    state_dir = tmp_path / "agent"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    key = host_key()
    configure_sftp(
        str(state_dir), "sftp.example", 2022, "agent-test", f"ssh-ed25519 {key.get_base64()}"
    )

    config = json.loads((state_dir / "sftp.json").read_text())
    assert set(config) == {
        "formatVersion",
        "host",
        "hostKey",
        "hostKeyFingerprint",
        "port",
        "username",
    }
    assert identity.publicKey not in (state_dir / "sftp.json").read_text()
