import errno
import io
import json
import os
import stat
from collections import namedtuple
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jaxon_agent.identity import initialize_identity
from jaxon_agent.sftp import configure_sftp
from jaxon_agent.snapshot import (
    MAX_SNAPSHOT_BYTES,
    SnapshotError,
    _architecture,
    collect_snapshot_payload,
    send_snapshot,
)

MESSAGE_ID = UUID("d9bdb20c-9b56-4b91-8c4a-a83f64d5802a")
SNAPSHOT_ID = UUID("069cc5e5-f8dc-405a-94eb-5b6eef59a335")
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
DiskUsage = namedtuple("DiskUsage", "total used free")


def payload() -> dict:
    return {
        "architecture": "X86_64",
        "hostname": "agent-host",
        "logicalCpuCount": 8,
        "memoryBytes": 16 * 1024 * 1024 * 1024,
        "operatingSystem": {"family": "LINUX", "name": "Test Linux", "version": "1"},
        "storageVolumes": [{"availableBytes": 2000, "name": "/", "totalBytes": 4000}],
    }


def host_key() -> paramiko.Ed25519Key:
    host_private = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return paramiko.Ed25519Key.from_private_key(io.StringIO(host_private.decode("ascii")))


def configured_state(tmp_path):
    state_dir = tmp_path / "agent"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    trusted_host_key = host_key()
    configure_sftp(
        str(state_dir),
        "sftp.example",
        2022,
        f"agent-{identity.agentId}",
        f"ssh-ed25519 {trusted_host_key.get_base64()}",
    )
    return state_dir, identity


class Channel:
    def __init__(self):
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value


class RemoteFile:
    def __init__(self, sftp, path):
        self.sftp = sftp
        self.path = path

    def __enter__(self):
        if self.path in self.sftp.files:
            raise OSError(errno.EEXIST, "exists")
        self.sftp.files[self.path] = b""
        return self

    def write(self, content):
        self.sftp.files[self.path] += content
        if self.sftp.fail_write:
            raise OSError("upload failed")

    def __exit__(self, *_):
        return False


class FakeSftp:
    def __init__(self, *, directory_exists=True, fail_write=False, collide_on_open=False):
        self.directories = {"/snapshots"} if directory_exists else set()
        self.files = {}
        self.fail_write = fail_write
        self.collide_on_open = collide_on_open
        self.channel = Channel()
        self.closed = False
        self.removed = []
        self.renames = []

    def get_channel(self):
        return self.channel

    def stat(self, path):
        if path in self.directories:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_size=0)
        if path in self.files:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=len(self.files[path]))
        raise FileNotFoundError(errno.ENOENT, "missing", path)

    def mkdir(self, path):
        self.directories.add(path)

    def file(self, path, mode):
        assert mode == "wx"
        if self.collide_on_open:
            self.files[path] = b"concurrent"
            raise OSError(errno.EEXIST, "exists")
        return RemoteFile(self, path)

    def rename(self, source, target):
        if target in self.files:
            raise OSError(errno.EEXIST, "exists")
        self.files[target] = self.files.pop(source)
        self.renames.append((source, target))

    def remove(self, path):
        self.removed.append(path)
        if path not in self.files:
            raise FileNotFoundError(errno.ENOENT, "missing", path)
        del self.files[path]

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, sftp):
        self.sftp = sftp
        self.keys = paramiko.HostKeys()
        self.closed = False
        self.connect_arguments = None
        self.policy = None

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self.keys

    def connect(self, **kwargs):
        self.connect_arguments = kwargs

    def open_sftp(self):
        return self.sftp

    def close(self):
        self.closed = True


def factories(sftp):
    clients = []

    def factory():
        client = FakeClient(sftp)
        clients.append(client)
        return client

    return factory, clients


def fixed_uuids():
    values = iter((MESSAGE_ID, SNAPSHOT_ID))
    return lambda: next(values)


def test_sends_exact_valid_snapshot_with_atomic_rename_and_safe_result(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    sftp = FakeSftp()
    factory, clients = factories(sftp)

    result = send_snapshot(
        str(state_dir),
        client_factory=factory,
        uuid_factory=fixed_uuids(),
        clock=lambda: NOW,
        payload_collector=payload,
    )

    temporary = f"/snapshots/{MESSAGE_ID}.json.part"
    final = f"/snapshots/{MESSAGE_ID}.json"
    assert result.agentId == identity.agentId
    assert result.messageId == str(MESSAGE_ID)
    assert result.snapshotId == str(SNAPSHOT_ID)
    assert result.remotePath == final
    assert result.status == "SENT"
    assert temporary not in sftp.files
    assert sftp.renames == [(temporary, final)]
    document = json.loads(sftp.files[final])
    assert document == {
        "agentId": identity.agentId,
        "capturedAt": "2026-10-15T12:00:00.000Z",
        "contractVersion": "1.0",
        "createdAt": "2026-10-15T12:00:00.000Z",
        "messageId": str(MESSAGE_ID),
        "messageType": "AGENT_SNAPSHOT",
        "payload": payload(),
        "snapshotId": str(SNAPSHOT_ID),
    }
    assert set(os.listdir(state_dir)) == {"agent.json", "id_ed25519", "id_ed25519.pub", "sftp.json"}
    client = clients[0]
    assert isinstance(client.policy, paramiko.RejectPolicy)
    assert client.connect_arguments["allow_agent"] is False
    assert client.connect_arguments["look_for_keys"] is False
    assert "password" not in client.connect_arguments
    assert "key_filename" not in client.connect_arguments
    assert client.sftp.channel.timeout == 60
    assert client.sftp.closed and client.closed
    safe_output = result.to_json()
    assert "agent-host" not in safe_output
    assert "ssh-ed25519" not in safe_output
    assert "PRIVATE KEY" not in safe_output


def test_creates_snapshot_directory_idempotently_when_missing(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    sftp = FakeSftp(directory_exists=False)
    factory, _ = factories(sftp)

    send_snapshot(
        str(state_dir),
        client_factory=factory,
        uuid_factory=fixed_uuids(),
        clock=lambda: NOW,
        payload_collector=payload,
    )

    assert "/snapshots" in sftp.directories


def test_rejects_existing_final_without_overwriting_it(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    final = f"/snapshots/{MESSAGE_ID}.json"
    sftp = FakeSftp()
    sftp.files[final] = b"existing"
    factory, clients = factories(sftp)

    with pytest.raises(SnapshotError, match="already exists"):
        send_snapshot(
            str(state_dir),
            client_factory=factory,
            uuid_factory=fixed_uuids(),
            clock=lambda: NOW,
            payload_collector=payload,
        )

    assert sftp.files[final] == b"existing"
    assert clients[0].sftp.closed and clients[0].closed


def test_cleans_only_its_own_temporary_and_closes_after_upload_failure(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    sftp = FakeSftp(fail_write=True)
    unrelated = "/snapshots/unrelated.json.part"
    sftp.files[unrelated] = b"keep"
    factory, clients = factories(sftp)

    with pytest.raises(SnapshotError, match="transferred securely"):
        send_snapshot(
            str(state_dir),
            client_factory=factory,
            uuid_factory=fixed_uuids(),
            clock=lambda: NOW,
            payload_collector=payload,
        )

    own = f"/snapshots/{MESSAGE_ID}.json.part"
    assert sftp.removed == [own]
    assert own not in sftp.files
    assert sftp.files[unrelated] == b"keep"
    assert clients[0].sftp.closed and clients[0].closed


def test_does_not_remove_partial_created_by_concurrent_sender(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    temporary = f"/snapshots/{MESSAGE_ID}.json.part"
    sftp = FakeSftp(collide_on_open=True)
    factory, clients = factories(sftp)

    with pytest.raises(SnapshotError, match="transferred securely"):
        send_snapshot(
            str(state_dir),
            client_factory=factory,
            uuid_factory=fixed_uuids(),
            clock=lambda: NOW,
            payload_collector=payload,
        )

    assert sftp.files[temporary] == b"concurrent"
    assert sftp.removed == []
    assert clients[0].sftp.closed and clients[0].closed


def test_rejects_wrong_host_key_before_upload_and_closes_client(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    sftp = FakeSftp()
    clients = []

    class WrongHostClient(FakeClient):
        def connect(self, **kwargs):
            self.connect_arguments = kwargs
            raise paramiko.BadHostKeyException(
                kwargs["hostname"], host_key(), next(iter(self.keys.values()))["ssh-ed25519"]
            )

    def factory():
        client = WrongHostClient(sftp)
        clients.append(client)
        return client

    with pytest.raises(SnapshotError, match="transferred securely"):
        send_snapshot(
            str(state_dir),
            client_factory=factory,
            uuid_factory=fixed_uuids(),
            clock=lambda: NOW,
            payload_collector=payload,
        )

    assert sftp.files == {}
    assert clients[0].closed


def test_validates_offline_before_opening_connection(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    opened = False

    def factory():
        nonlocal opened
        opened = True
        raise AssertionError

    invalid = payload()
    invalid["forbidden"] = True
    with pytest.raises(SnapshotError, match="collected and validated"):
        send_snapshot(
            str(state_dir),
            client_factory=factory,
            uuid_factory=fixed_uuids(),
            clock=lambda: NOW,
            payload_collector=lambda: invalid,
        )
    assert opened is False


def test_rejects_snapshot_larger_than_five_mib_before_connecting(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    oversized = payload()
    oversized["hostname"] = "x" * MAX_SNAPSHOT_BYTES

    with pytest.raises(SnapshotError, match="maximum supported size"):
        send_snapshot(
            str(state_dir),
            client_factory=lambda: pytest.fail("connection must not open"),
            uuid_factory=fixed_uuids(),
            clock=lambda: NOW,
            payload_collector=lambda: oversized,
        )


def test_rejects_unsupported_platform_before_reading_state(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("jaxon_agent.snapshot.sys.platform", "win32")

    with pytest.raises(SnapshotError, match="POSIX/Linux"):
        send_snapshot(str(tmp_path / "missing"))


def test_requires_independent_uuid_v4_identifiers_before_connecting(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)

    with pytest.raises(SnapshotError, match="identifiers must be independent"):
        send_snapshot(
            str(state_dir),
            client_factory=lambda: pytest.fail("connection must not open"),
            uuid_factory=lambda: MESSAGE_ID,
            clock=lambda: NOW,
            payload_collector=payload,
        )


def test_uses_independent_utc_capture_and_creation_timestamps(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    sftp = FakeSftp()
    factory, _ = factories(sftp)
    instants = iter((NOW, NOW.replace(second=1)))

    result = send_snapshot(
        str(state_dir),
        client_factory=factory,
        uuid_factory=fixed_uuids(),
        clock=lambda: next(instants),
        payload_collector=payload,
    )

    assert result.capturedAt == "2026-10-15T12:00:00.000Z"
    assert result.createdAt == "2026-10-15T12:00:01.000Z"


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        ("x86_64", "X86_64"),
        ("AMD64", "X86_64"),
        ("i686", "X86"),
        ("aarch64", "ARM64"),
        ("armv7l", "ARM32"),
        ("mips64", "OTHER"),
    ],
)
def test_maps_architecture(machine, expected) -> None:
    assert _architecture(machine) == expected


def test_collects_only_minimum_linux_system_values(monkeypatch) -> None:
    monkeypatch.setattr("jaxon_agent.snapshot.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "jaxon_agent.snapshot.platform.freedesktop_os_release",
        lambda: {"NAME": "Example Linux", "VERSION_ID": "42"},
    )
    monkeypatch.setattr("jaxon_agent.snapshot.platform.machine", lambda: "aarch64")
    monkeypatch.setattr("jaxon_agent.snapshot.socket.gethostname", lambda: "host-42")
    monkeypatch.setattr("jaxon_agent.snapshot.os.cpu_count", lambda: 12)
    monkeypatch.setattr(
        "jaxon_agent.snapshot.os.sysconf",
        lambda name: {"SC_PHYS_PAGES": 1024, "SC_PAGE_SIZE": 4096}[name],
    )
    monkeypatch.setattr(
        "jaxon_agent.snapshot.shutil.disk_usage", lambda path: DiskUsage(10_000, 4_000, 6_000)
    )

    assert collect_snapshot_payload() == {
        "architecture": "ARM64",
        "hostname": "host-42",
        "logicalCpuCount": 12,
        "memoryBytes": 4_194_304,
        "operatingSystem": {"family": "LINUX", "name": "Example Linux", "version": "42"},
        "storageVolumes": [{"availableBytes": 6_000, "name": "/", "totalBytes": 10_000}],
    }


@pytest.mark.parametrize("cpu_count", [None, 0, -1])
def test_rejects_impossible_or_incomplete_system_values(monkeypatch, cpu_count) -> None:
    monkeypatch.setattr("jaxon_agent.snapshot.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "jaxon_agent.snapshot.platform.freedesktop_os_release",
        lambda: {"NAME": "Example Linux", "VERSION_ID": "42"},
    )
    monkeypatch.setattr("jaxon_agent.snapshot.socket.gethostname", lambda: "host")
    monkeypatch.setattr("jaxon_agent.snapshot.os.cpu_count", lambda: cpu_count)

    with pytest.raises(SnapshotError, match="CPU"):
        collect_snapshot_payload()


def test_rejects_impossible_storage_values(monkeypatch) -> None:
    monkeypatch.setattr("jaxon_agent.snapshot.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "jaxon_agent.snapshot.platform.freedesktop_os_release",
        lambda: {"NAME": "Example Linux", "VERSION_ID": "42"},
    )
    monkeypatch.setattr("jaxon_agent.snapshot.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("jaxon_agent.snapshot.socket.gethostname", lambda: "host")
    monkeypatch.setattr("jaxon_agent.snapshot.os.cpu_count", lambda: 2)
    monkeypatch.setattr("jaxon_agent.snapshot.os.sysconf", lambda name: 1024)
    monkeypatch.setattr(
        "jaxon_agent.snapshot.shutil.disk_usage", lambda path: DiskUsage(10, -1, 11)
    )

    with pytest.raises(SnapshotError, match="Storage"):
        collect_snapshot_payload()
