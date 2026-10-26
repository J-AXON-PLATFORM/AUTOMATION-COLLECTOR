from __future__ import annotations

import errno
import io
import json
import os
import stat
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jaxon_discovery_executor.identity import initialize_identity
from jaxon_discovery_executor.ledger import (
    DiscoveryLedger,
    DiscoveryLedgerError,
    DiscoveryRunLock,
)
from jaxon_discovery_executor.runner import DiscoveryRunnerError, run_once
from jaxon_discovery_executor.scanner import BasicScanResult
from jaxon_discovery_executor.sftp import configure_sftp

NOW = datetime(2026, 10, 25, 12, 10, tzinfo=UTC)


def host_key() -> paramiko.Ed25519Key:
    private = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return paramiko.Ed25519Key.from_private_key(io.StringIO(private.decode("ascii")))


def configured_state(tmp_path):
    state_dir = tmp_path / "executor"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    trusted = host_key()
    configure_sftp(
        str(state_dir),
        "sftp.example",
        2022,
        f"discovery-executor-{identity.executorId}",
        f"ssh-ed25519 {trusted.get_base64()}",
    )
    return state_dir, identity


def job_document(identity, job_id=None, scope="127.0.0.1/32", expires_at=None):
    job_id = job_id or str(uuid4())
    value = {
        "createdAt": "2026-10-25T12:00:00Z",
        "executorId": identity.executorId,
        "expiresAt": expires_at or "2026-10-25T13:00:00Z",
        "jobId": job_id,
        "messageType": "DISCOVERY_JOB",
        "profile": "BASIC",
        "schemaVersion": "1.0",
        "scopeCidr": scope,
        "scopeId": str(uuid4()),
    }
    return job_id, json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class RemoteFile:
    def __init__(self, mailbox, path, mode):
        self.mailbox = mailbox
        self.path = path
        self.mode = mode

    def __enter__(self):
        if self.mode == "wx":
            if self.path in self.mailbox.files:
                raise OSError(errno.EEXIST, "exists")
            self.mailbox.files[self.path] = b""
        return self

    def __exit__(self, *_args):
        return False

    def read(self, maximum):
        return self.mailbox.files[self.path][:maximum]

    def write(self, content):
        uploaded = content[:-1] if self.mailbox.short_upload else content
        self.mailbox.files[self.path] += uploaded


class Mailbox:
    def __init__(self):
        self.directories = {"/jobs", "/results"}
        self.files = {}
        self.rename_failures = []
        self.short_upload = False

    def stat(self, path):
        if path in self.directories:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_size=0)
        if path in self.files:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=len(self.files[path]))
        raise FileNotFoundError(errno.ENOENT, "missing", path)

    def listdir_attr(self, path):
        prefix = path + "/"
        return [
            SimpleNamespace(
                filename=name.removeprefix(prefix),
                st_mode=stat.S_IFREG | 0o600,
                st_size=len(content),
            )
            for name, content in self.files.items()
            if name.startswith(prefix) and "/" not in name.removeprefix(prefix)
        ]

    def file(self, path, mode):
        return RemoteFile(self, path, mode)

    def rename(self, source, target):
        if self.rename_failures:
            raise self.rename_failures.pop(0)
        if target in self.files:
            raise OSError(errno.EEXIST, "exists")
        self.files[target] = self.files.pop(source)

    def get_channel(self):
        return SimpleNamespace(settimeout=lambda _value: None)

    def close(self):
        pass


class Client:
    def __init__(self, mailbox):
        self.mailbox = mailbox
        self.keys = paramiko.HostKeys()

    def set_missing_host_key_policy(self, _policy):
        pass

    def get_host_keys(self):
        return self.keys

    def connect(self, **_kwargs):
        pass

    def open_sftp(self):
        return self.mailbox

    def close(self):
        pass


def client_factory(mailbox):
    return lambda: Client(mailbox)


def one_observation(_scope):
    return BasicScanResult(
        1,
        1,
        [
            {
                "evidence": ["TCP"],
                "hostname": None,
                "ipAddress": "127.0.0.1",
                "macAddress": None,
                "openTcpPorts": [443],
            }
        ],
    )


def test_run_once_selects_one_job_and_delivers_exact_result(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    first_id = "00000000-0000-4000-8000-000000000001"
    second_id = "00000000-0000-4000-8000-000000000002"
    first_id, first = job_document(identity, first_id)
    second_id, second = job_document(identity, second_id)
    mailbox.files[f"/jobs/{second_id}.json"] = second
    mailbox.files[f"/jobs/{first_id}.json"] = first

    result = run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=one_observation,
    )

    assert result.jobId == first_id
    assert result.status == "DELIVERED"
    final = json.loads(mailbox.files[f"/results/{first_id}.json"])
    assert final["jobId"] == first_id
    assert final["status"] == "SUCCEEDED"
    assert final["summary"] == {
        "observationsFound": 1,
        "targetsConsidered": 1,
        "targetsScanned": 1,
    }
    with DiscoveryLedger(str(state_dir)) as ledger:
        assert ledger.get(first_id).state == "DELIVERED"
        assert ledger.get(second_id) is None


def test_delivery_resumes_identical_partial_without_reexecution(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    job_id, document = job_document(identity)
    mailbox.files[f"/jobs/{job_id}.json"] = document
    mailbox.rename_failures.append(OSError("temporary failure"))
    scans = []

    def scan(scope):
        scans.append(scope)
        return one_observation(scope)

    with pytest.raises(DiscoveryRunnerError):
        run_once(
            str(state_dir),
            client_factory=client_factory(mailbox),
            clock=lambda: NOW,
            scan_executor=scan,
        )
    temporary = mailbox.files[f"/results/{job_id}.json.part"]

    result = run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=lambda _scope: pytest.fail("job must not be reexecuted"),
    )
    assert result.status == "DELIVERED"
    assert mailbox.files[f"/results/{job_id}.json"] == temporary
    assert scans == ["127.0.0.1/32"]


def test_interrupted_running_job_becomes_failed_without_reexecution(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    job_id, document = job_document(identity)
    with DiscoveryLedger(str(state_dir)) as ledger:
        record = ledger.receive(job_id, document, str(uuid4()), "2026-10-25T12:09:00Z")
        ledger.running(record)

    result = run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=lambda _scope: pytest.fail("job must not be reexecuted"),
    )
    delivered = json.loads(mailbox.files[f"/results/{job_id}.json"])
    assert result.status == "DELIVERED"
    assert delivered["status"] == "FAILED"
    assert delivered["failureCode"] == "EXECUTION_INTERRUPTED"


def test_interrupted_recovery_handles_only_one_job_per_invocation(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    first_id = "00000000-0000-4000-8000-000000000001"
    second_id = "00000000-0000-4000-8000-000000000002"
    first_id, first = job_document(identity, first_id)
    second_id, second = job_document(identity, second_id)
    with DiscoveryLedger(str(state_dir)) as ledger:
        first_record = ledger.receive(first_id, first, str(uuid4()), "2026-10-25T12:09:00Z")
        ledger.running(first_record)
        second_record = ledger.receive(second_id, second, str(uuid4()), "2026-10-25T12:09:00Z")
        ledger.running(second_record)

    outcome = run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=lambda _scope: pytest.fail("jobs must not be reexecuted"),
    )

    assert outcome.jobId == first_id
    with DiscoveryLedger(str(state_dir)) as ledger:
        assert ledger.get(first_id).state == "DELIVERED"
        assert ledger.get(second_id).state == "RUNNING"


def test_ready_result_is_delivered_before_recovering_another_job(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    first_id = "00000000-0000-4000-8000-000000000001"
    second_id = "00000000-0000-4000-8000-000000000002"
    first_id, first = job_document(identity, first_id)
    second_id, second = job_document(identity, second_id)
    mailbox.files[f"/jobs/{first_id}.json"] = first
    mailbox.rename_failures.append(OSError("temporary failure"))
    with pytest.raises(DiscoveryRunnerError):
        run_once(
            str(state_dir),
            client_factory=client_factory(mailbox),
            clock=lambda: NOW,
            scan_executor=one_observation,
        )
    with DiscoveryLedger(str(state_dir)) as ledger:
        second_record = ledger.receive(second_id, second, str(uuid4()), "2026-10-25T12:09:00Z")
        ledger.running(second_record)

    outcome = run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=lambda _scope: pytest.fail("jobs must not be reexecuted"),
    )

    assert outcome.jobId == first_id
    with DiscoveryLedger(str(state_dir)) as ledger:
        assert ledger.get(first_id).state == "DELIVERED"
        assert ledger.get(second_id).state == "RUNNING"


def test_interrupted_recovery_tolerates_wall_clock_rollback(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    job_id, document = job_document(identity)
    with DiscoveryLedger(str(state_dir)) as ledger:
        record = ledger.receive(job_id, document, str(uuid4()), "2026-10-25T12:11:00Z")
        ledger.running(record)

    run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=lambda _scope: pytest.fail("job must not be reexecuted"),
    )

    result = json.loads(mailbox.files[f"/results/{job_id}.json"])
    assert result["startedAt"] == result["completedAt"] == "2026-10-25T12:11:00Z"


def test_oversized_scope_returns_failed_without_probes(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    job_id, document = job_document(identity, scope="10.0.0.0/19")
    mailbox.files[f"/jobs/{job_id}.json"] = document

    run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=lambda _scope: pytest.fail("oversized scope must not be scanned"),
    )

    delivered = json.loads(mailbox.files[f"/results/{job_id}.json"])
    assert delivered["failureCode"] == "SCOPE_TOO_LARGE"
    assert delivered["summary"]["targetsConsidered"] == 8192


def test_remote_job_change_is_rejected(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    job_id, document = job_document(identity)
    mailbox.files[f"/jobs/{job_id}.json"] = document
    run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=one_observation,
    )
    changed = json.loads(document)
    changed["scopeId"] = str(UUID("00000000-0000-4000-8000-000000000099"))
    mailbox.files[f"/jobs/{job_id}.json"] = json.dumps(changed).encode()

    with pytest.raises(DiscoveryRunnerError):
        run_once(
            str(state_dir),
            client_factory=client_factory(mailbox),
            clock=lambda: NOW,
            scan_executor=one_observation,
        )


@pytest.mark.parametrize("destination", ["partial", "final"])
def test_delivery_rejects_conflicting_remote_content_without_reexecution(
    tmp_path, destination
) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    job_id, document = job_document(identity)
    mailbox.files[f"/jobs/{job_id}.json"] = document
    mailbox.rename_failures.append(OSError("temporary failure"))
    with pytest.raises(DiscoveryRunnerError):
        run_once(
            str(state_dir),
            client_factory=client_factory(mailbox),
            clock=lambda: NOW,
            scan_executor=one_observation,
        )
    mailbox.files.pop(f"/results/{job_id}.json.part")
    suffix = ".json.part" if destination == "partial" else ".json"
    mailbox.files[f"/results/{job_id}{suffix}"] = b"conflict"

    with pytest.raises(DiscoveryRunnerError, match="conflicting content"):
        run_once(
            str(state_dir),
            client_factory=client_factory(mailbox),
            clock=lambda: NOW,
            scan_executor=lambda _scope: pytest.fail("job must not be reexecuted"),
        )


def test_delivery_accepts_identical_final_without_reexecution(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    job_id, document = job_document(identity)
    mailbox.files[f"/jobs/{job_id}.json"] = document
    mailbox.rename_failures.append(OSError("temporary failure"))
    with pytest.raises(DiscoveryRunnerError):
        run_once(
            str(state_dir),
            client_factory=client_factory(mailbox),
            clock=lambda: NOW,
            scan_executor=one_observation,
        )
    result = mailbox.files.pop(f"/results/{job_id}.json.part")
    mailbox.files[f"/results/{job_id}.json"] = result

    outcome = run_once(
        str(state_dir),
        client_factory=client_factory(mailbox),
        clock=lambda: NOW,
        scan_executor=lambda _scope: pytest.fail("job must not be reexecuted"),
    )
    assert outcome.status == "DELIVERED"


def test_delivery_rejects_short_upload_and_keeps_result_ready(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    mailbox.short_upload = True
    job_id, document = job_document(identity)
    mailbox.files[f"/jobs/{job_id}.json"] = document

    with pytest.raises(DiscoveryRunnerError, match="could not be verified"):
        run_once(
            str(state_dir),
            client_factory=client_factory(mailbox),
            clock=lambda: NOW,
            scan_executor=one_observation,
        )
    with DiscoveryLedger(str(state_dir)) as ledger:
        assert ledger.get(job_id).state == "RESULT_READY"


def test_run_lock_is_nonblocking(tmp_path) -> None:
    state_dir, _identity = configured_state(tmp_path)
    with (
        DiscoveryRunLock(str(state_dir)),
        pytest.raises(DiscoveryLedgerError, match="already active"),
    ):
        DiscoveryRunLock(str(state_dir))


def test_ledger_rejects_symlink_fifo_and_malformed_record(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    job_id, document = job_document(identity)
    with DiscoveryLedger(str(state_dir)) as ledger:
        ledger.receive(job_id, document, str(uuid4()), "2026-10-25T12:09:00Z")
    record = state_dir / "discovery-ledger" / f"{job_id}.json"

    value = json.loads(record.read_bytes())
    value["startedAt"] = None
    record.write_text(json.dumps(value))
    os.chmod(record, 0o600)
    with (
        DiscoveryLedger(str(state_dir)) as ledger,
        pytest.raises(DiscoveryLedgerError, match="invalid record"),
    ):
        ledger.get(job_id)

    record.unlink()
    target = tmp_path / "outside"
    target.write_text("outside")
    record.symlink_to(target)
    with (
        DiscoveryLedger(str(state_dir)) as ledger,
        pytest.raises(DiscoveryLedgerError, match="invalid record"),
    ):
        ledger.get(job_id)

    record.unlink()
    os.mkfifo(record, mode=0o600)
    with (
        DiscoveryLedger(str(state_dir)) as ledger,
        pytest.raises(DiscoveryLedgerError, match="unsafe record"),
    ):
        ledger.get(job_id)
