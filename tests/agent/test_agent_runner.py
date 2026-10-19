import errno
import io
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jaxon_agent.identity import initialize_identity
from jaxon_agent.ledger import AgentRunLock, LedgerError, TaskLedger
from jaxon_agent.runner import (
    AgentRunnerError,
    CapabilityTimeoutError,
    _result_retry_delay,
    run_agent,
)
from jaxon_agent.sftp import configure_sftp

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def host_key() -> paramiko.Ed25519Key:
    private = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return paramiko.Ed25519Key.from_private_key(io.StringIO(private.decode("ascii")))


def configured_state(tmp_path):
    state_dir = tmp_path / "agent"
    identity = initialize_identity(str(uuid4()), str(state_dir))
    trusted = host_key()
    configure_sftp(
        str(state_dir),
        "sftp.example",
        2022,
        f"agent-{identity.agentId}",
        f"ssh-ed25519 {trusted.get_base64()}",
    )
    return state_dir, identity


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
        self.mailbox.result_documents_attempted.append(content)
        if self.mailbox.write_failures:
            raise self.mailbox.write_failures.pop(0)
        self.mailbox.files[self.path] += content


class Mailbox:
    def __init__(self):
        self.directories = {"/tasks", "/responses", "/snapshots"}
        self.files = {}
        self.connect_attempts = 0
        self.connect_failures = []
        self.removed = []
        self.result_documents_attempted = []
        self.write_failures = []

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
        if target in self.files:
            raise OSError(errno.EEXIST, "exists")
        self.files[target] = self.files.pop(source)

    def remove(self, path):
        self.removed.append(path)
        del self.files[path]

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
        self.mailbox.connect_attempts += 1
        if self.mailbox.connect_failures:
            failure = self.mailbox.connect_failures.pop(0)
            if failure is not None:
                raise failure

    def open_sftp(self):
        return self.mailbox

    def close(self):
        pass


def client_factory(mailbox):
    return lambda: Client(mailbox)


def task_document(identity, *, task_type="COLLECT_SNAPSHOT", expires_at=None):
    task_id = str(uuid4())
    value = {
        "agentId": identity.agentId,
        "contractVersion": "1.0",
        "createdAt": "2026-10-18T12:00:00.000Z",
        "expiresAt": expires_at or "2026-10-18T12:15:00.000Z",
        "messageId": str(uuid4()),
        "messageType": "AGENT_TASK",
        "payload": {},
        "taskId": task_id,
        "taskType": task_type,
    }
    return task_id, json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class NoJitter:
    def uniform(self, _minimum, _maximum):
        return 0


class MaximumJitter:
    def __init__(self):
        self.ranges = []

    def uniform(self, minimum, maximum):
        self.ranges.append((minimum, maximum))
        return maximum


def run_once(state_dir, mailbox, **overrides):
    arguments = {
        "once": True,
        "client_factory": client_factory(mailbox),
        "clock": lambda: NOW,
        "sleeper": lambda _seconds: None,
        "random_source": NoJitter(),
        "install_signal_handlers": False,
    }
    arguments.update(overrides)
    return run_agent(str(state_dir), **arguments)


def result_documents(mailbox):
    return {
        path: json.loads(content)
        for path, content in mailbox.files.items()
        if path.startswith("/responses/") and path.endswith(".json")
    }


def test_executes_collect_snapshot_once_and_keeps_deterministic_result(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    executions = []

    result = run_once(
        state_dir,
        mailbox,
        snapshot_executor=lambda state, timeout: executions.append((state, timeout)),
    )
    first_result = next(iter(result_documents(mailbox).values()))
    run_once(
        state_dir,
        mailbox,
        snapshot_executor=lambda *_args: pytest.fail("task must not execute twice"),
    )

    assert result.agentId == identity.agentId
    assert result.cycles == 1
    assert len(executions) == 1
    assert first_result["status"] == "SUCCEEDED"
    assert first_result["taskId"] == task_id
    assert len(result_documents(mailbox)) == 1
    assert stat.S_IMODE(os.stat(state_dir / "task-ledger").st_mode) == 0o700
    records = list((state_dir / "task-ledger").iterdir())
    assert len(records) == 1
    assert stat.S_IMODE(records[0].stat().st_mode) == 0o600


def test_succeeds_on_first_delivery_attempt_without_waiting(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    waits = []

    run_once(
        state_dir,
        mailbox,
        sleeper=waits.append,
        snapshot_executor=lambda *_args: None,
    )

    assert mailbox.connect_attempts == 2  # one poll session and one Result delivery session
    assert waits == []


def test_retries_transient_delivery_with_full_jitter_without_reexecution(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    mailbox.write_failures = [
        ConnectionResetError(errno.ECONNRESET, "connection reset"),
        TimeoutError("operation timed out"),
        EOFError("established transport closed"),
        ConnectionAbortedError(errno.ECONNABORTED, "channel closed"),
    ]
    executions = []
    waits = []
    jitter = MaximumJitter()

    run_once(
        state_dir,
        mailbox,
        sleeper=waits.append,
        random_source=jitter,
        snapshot_executor=lambda *_args: executions.append("executed"),
    )

    assert executions == ["executed"]
    assert waits == [5, 10, 20, 40]
    assert jitter.ranges == [(0, 5), (0, 10), (0, 20), (0, 40)]
    assert len(mailbox.result_documents_attempted) == 5
    assert len(set(mailbox.result_documents_attempted)) == 1
    assert next(iter(result_documents(mailbox).values()))["status"] == "SUCCEEDED"


def test_retry_delay_applies_five_minute_cap() -> None:
    jitter = MaximumJitter()

    assert _result_retry_delay(10, jitter) == 300
    assert jitter.ranges == [(0, 300)]


def test_exhausts_five_transient_attempts_and_keeps_terminal_result(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    mailbox.connect_failures = [None] + [
        ConnectionRefusedError(errno.ECONNREFUSED, "refused") for _ in range(5)
    ]
    executions = []
    waits = []

    with pytest.raises(AgentRunnerError, match="exhausted its transient retry limit"):
        run_once(
            state_dir,
            mailbox,
            sleeper=waits.append,
            snapshot_executor=lambda *_args: executions.append("executed"),
        )

    with TaskLedger(str(state_dir)) as ledger:
        record = ledger.get(task_id)
    assert executions == ["executed"]
    assert mailbox.connect_attempts == 6  # poll plus five Result attempts
    assert waits == [0, 0, 0, 0]
    assert record is not None and record.state == "TERMINAL"
    assert record.resultDocument is not None


def test_manual_restart_delivers_pending_result_without_reexecution(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    mailbox.connect_failures = [None] + [TimeoutError("temporary") for _ in range(5)]
    executions = []

    with pytest.raises(AgentRunnerError, match="exhausted"):
        run_once(
            state_dir,
            mailbox,
            snapshot_executor=lambda *_args: executions.append("executed"),
        )

    with TaskLedger(str(state_dir)) as ledger:
        pending = ledger.get(task_id)
    assert pending is not None
    own_partial = f"/responses/{pending.resultMessageId}.json.part"
    mailbox.files[own_partial] = b"stale"
    mailbox.files["/responses/unrelated.json.part"] = b"keep"

    run_once(
        state_dir,
        mailbox,
        snapshot_executor=lambda *_args: pytest.fail("task must not execute twice"),
    )

    delivered = next(iter(result_documents(mailbox).values()))
    assert executions == ["executed"]
    delivered_bytes = next(iter(mailbox.files[path] for path in result_documents(mailbox)))
    assert pending.resultDocument == delivered_bytes
    assert delivered["messageId"] == pending.resultMessageId
    assert delivered["resultId"] == pending.resultId
    assert delivered["taskId"] == pending.taskId
    assert own_partial in mailbox.removed
    assert mailbox.files["/responses/unrelated.json.part"] == b"keep"


@pytest.mark.parametrize(
    "failure",
    [
        paramiko.AuthenticationException("secret-password"),
        paramiko.BadHostKeyException("sftp.example", host_key(), host_key()),
        paramiko.SSHException("unclassified-secret-detail"),
    ],
)
def test_permanent_or_unclassified_connection_failure_is_not_retried_and_is_safe(
    tmp_path, failure
) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    mailbox.connect_failures = [None, failure]
    waits = []

    with pytest.raises(AgentRunnerError) as raised:
        run_once(
            state_dir,
            mailbox,
            sleeper=waits.append,
            snapshot_executor=lambda *_args: None,
        )

    assert mailbox.connect_attempts == 2  # poll plus one Result attempt
    assert waits == []
    assert "secret" not in str(raised.value)


def test_conflicting_final_result_is_permanent_and_not_retried(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document

    with TaskLedger(str(state_dir)) as ledger:
        record = ledger.begin(task_id, "COLLECT_SNAPSHOT", document, str(uuid4()), str(uuid4()))
        record = ledger.terminal(record, b"expected", "2026-10-18T12:00:00.000Z")
    mailbox.files[f"/responses/{record.resultMessageId}.json"] = b"conflicting"
    waits = []

    with pytest.raises(AgentRunnerError, match="conflicting content"):
        run_once(state_dir, mailbox, sleeper=waits.append)

    assert mailbox.connect_attempts == 1
    assert waits == []


def test_permission_failure_during_result_write_is_not_retried(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    mailbox.write_failures = [PermissionError(errno.EACCES, "sensitive remote path")]
    waits = []

    with pytest.raises(AgentRunnerError) as raised:
        run_once(
            state_dir,
            mailbox,
            sleeper=waits.append,
            snapshot_executor=lambda *_args: None,
        )

    assert len(mailbox.result_documents_attempted) == 1
    assert waits == []
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("unknown-secret-detail"), paramiko.SSHException("unknown-secret-detail")],
)
def test_unknown_result_delivery_error_fails_closed_without_leaking_details(
    tmp_path, failure
) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    mailbox.write_failures = [failure]
    waits = []

    with pytest.raises(AgentRunnerError, match="failed permanently") as raised:
        run_once(
            state_dir,
            mailbox,
            sleeper=waits.append,
            snapshot_executor=lambda *_args: None,
        )

    assert len(mailbox.result_documents_attempted) == 1
    assert waits == []
    assert "secret" not in str(raised.value)


def test_identical_remote_final_completes_pending_result_idempotently(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id = str(uuid4())
    message_id = str(uuid4())
    document = b"identical-result"
    with TaskLedger(str(state_dir)) as ledger:
        record = ledger.begin(task_id, "COLLECT_SNAPSHOT", b"task", message_id, str(uuid4()))
        ledger.terminal(record, document, "2026-10-18T12:00:00.000Z")
    mailbox.files[f"/responses/{message_id}.json"] = document

    run_once(state_dir, mailbox)

    with TaskLedger(str(state_dir)) as ledger:
        delivered = ledger.get(task_id)
    assert delivered is not None and delivered.state == "TRANSFERRED"
    assert mailbox.result_documents_attempted == []


def test_transient_failure_cleans_only_own_partial_before_retry(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    mailbox.files["/responses/unrelated.json.part"] = b"keep"
    mailbox.write_failures = [ConnectionResetError(errno.ECONNRESET, "reset")]

    run_once(state_dir, mailbox, snapshot_executor=lambda *_args: None)

    own_partials = [path for path in mailbox.removed if path != "/responses/unrelated.json.part"]
    assert len(own_partials) == 1
    assert own_partials[0].endswith(".json.part")
    assert mailbox.files["/responses/unrelated.json.part"] == b"keep"


def test_recovers_running_record_as_failed_without_reexecution(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document
    with TaskLedger(str(state_dir)) as ledger:
        ledger.begin(task_id, "COLLECT_SNAPSHOT", document, str(uuid4()), str(uuid4()))

    run_once(
        state_dir,
        mailbox,
        snapshot_executor=lambda *_args: pytest.fail("interrupted task must not restart"),
    )

    result = next(iter(result_documents(mailbox).values()))
    assert result["status"] == "FAILED"
    assert result["error"]["code"] == "EXECUTION_INTERRUPTED"


@pytest.mark.parametrize(
    ("task_type", "expires_at", "expected_code"),
    [
        ("COLLECT_SNAPSHOT", "2026-10-18T11:59:59.000Z", "TASK_EXPIRED"),
        ("COLLECT_NETWORK_STATE", None, "CAPABILITY_NOT_AVAILABLE"),
    ],
)
def test_rejects_non_executable_task_without_invoking_capability(
    tmp_path, task_type, expires_at, expected_code
) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity, task_type=task_type, expires_at=expires_at)
    mailbox.files[f"/tasks/{task_id}.json"] = document

    run_once(
        state_dir,
        mailbox,
        snapshot_executor=lambda *_args: pytest.fail("capability must not execute"),
    )

    result = next(iter(result_documents(mailbox).values()))
    assert result["status"] == "REJECTED"
    assert result["error"]["code"] == expected_code


def test_reports_timeout_as_terminal_failure(tmp_path) -> None:
    state_dir, identity = configured_state(tmp_path)
    mailbox = Mailbox()
    task_id, document = task_document(identity)
    mailbox.files[f"/tasks/{task_id}.json"] = document

    def time_out(*_args):
        raise CapabilityTimeoutError

    run_once(state_dir, mailbox, snapshot_executor=time_out)

    result = next(iter(result_documents(mailbox).values()))
    assert result["status"] == "FAILED"
    assert result["error"]["code"] == "CAPABILITY_TIMEOUT"


def test_refuses_second_active_runner_for_same_state(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)

    with AgentRunLock(str(state_dir)), pytest.raises(LedgerError, match="already active"):
        AgentRunLock(str(state_dir))


def test_prunes_only_transferred_records_after_thirty_days(tmp_path) -> None:
    state_dir, _ = configured_state(tmp_path)
    task_id = str(uuid4())
    with TaskLedger(str(state_dir)) as ledger:
        record = ledger.begin(task_id, "COLLECT_SNAPSHOT", b"task", str(uuid4()), str(uuid4()))
        record = ledger.terminal(record, b"result", "2026-09-01T00:00:00.000Z")
        ledger.transferred(record, "2026-09-01T00:00:00.000Z")
        ledger.prune(NOW + timedelta(days=1))
        assert ledger.get(task_id) is None
