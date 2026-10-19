"""Foreground polling runner for the bounded COLLECT_SNAPSHOT capability."""

from __future__ import annotations

import errno
import json
import multiprocessing
import random
import signal
import stat
import time
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from types import FrameType
from typing import Any
from uuid import UUID, uuid4

import paramiko

from jaxon_agent.contracts import MAX_TASK_BYTES, AgentContractValidator, ContractError
from jaxon_agent.ledger import AgentRunLock, LedgerError, LedgerRecord, TaskLedger
from jaxon_agent.sftp import (
    SftpVerificationError,
    load_sftp_state,
    open_sftp_session,
)
from jaxon_agent.snapshot import SnapshotError, send_snapshot

TASK_DIRECTORY = "/tasks"
RESPONSE_DIRECTORY = "/responses"
BATCH_SIZE = 10
POLL_SECONDS = 60
POLL_JITTER_SECONDS = 15
STARTUP_JITTER_SECONDS = 60
CAPABILITY_TIMEOUT_SECONDS = 5 * 60


class AgentRunnerError(RuntimeError):
    """A safe foreground runner failure."""


@dataclass(frozen=True)
class AgentRunResult:
    agentId: str
    cycles: int
    status: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class PollCycleResult:
    handled: int


class StopRequest:
    def __init__(self) -> None:
        self.requested = False

    def request(self, _signum: int, _frame: FrameType | None) -> None:
        self.requested = True


def run_agent(
    state_dir_value: str,
    *,
    once: bool = False,
    client_factory=paramiko.SSHClient,
    validator_factory=AgentContractValidator,
    uuid_factory=uuid4,
    clock=lambda: datetime.now(UTC),
    sleeper=time.sleep,
    random_source=None,
    snapshot_executor=None,
    install_signal_handlers: bool = True,
) -> AgentRunResult:
    """Poll serially and retain each terminal result until atomic SFTP transfer."""
    stop = StopRequest()
    previous_handlers: dict[int, Any] = {}
    try:
        with AgentRunLock(state_dir_value), TaskLedger(state_dir_value) as ledger:
            state = load_sftp_state(state_dir_value)
            if install_signal_handlers:
                for signum in (signal.SIGINT, signal.SIGTERM):
                    previous_handlers[signum] = signal.signal(signum, stop.request)
            random_source = random_source or random.SystemRandom()
            if not once:
                sleeper(random_source.uniform(0, STARTUP_JITTER_SECONDS))
            cycles = 0
            executor = snapshot_executor or execute_snapshot_with_timeout
            while not stop.requested:
                _recover_interrupted(ledger, state.identity.agentId, validator_factory, clock)
                _retry_terminal_results(
                    ledger,
                    state,
                    client_factory,
                    clock,
                )
                _poll_cycle(
                    state_dir_value,
                    state,
                    ledger,
                    client_factory,
                    validator_factory,
                    uuid_factory,
                    clock,
                    executor,
                )
                ledger.prune(clock())
                cycles += 1
                if once:
                    break
                sleeper(
                    POLL_SECONDS + random_source.uniform(-POLL_JITTER_SECONDS, POLL_JITTER_SECONDS)
                )
            return AgentRunResult(state.identity.agentId, cycles, "STOPPED")
    except AgentRunnerError:
        raise
    except (ContractError, LedgerError, SftpVerificationError, OSError, ValueError) as exception:
        raise AgentRunnerError(
            "Agent runner stopped after a safe local or SFTP failure."
        ) from exception
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def _poll_cycle(
    state_dir_value: str,
    state,
    ledger: TaskLedger,
    client_factory,
    validator_factory,
    uuid_factory,
    clock,
    snapshot_executor,
) -> PollCycleResult:
    candidates: list[tuple[str, bytes]] = []
    with open_sftp_session(state, client_factory) as sftp:
        _require_remote_directory(sftp, TASK_DIRECTORY)
        for details in sorted(sftp.listdir_attr(TASK_DIRECTORY), key=lambda item: item.filename):
            task_id = _task_id_from_filename(details.filename)
            if task_id is None or ledger.get(task_id) is not None:
                continue
            if details.st_mode is None or not stat.S_ISREG(details.st_mode):
                continue
            if details.st_size is None or details.st_size > MAX_TASK_BYTES:
                ledger.unreportable(task_id, b"")
                continue
            path = f"{TASK_DIRECTORY}/{details.filename}"
            with sftp.file(path, mode="rb") as remote:
                document = remote.read(MAX_TASK_BYTES + 1)
            if not isinstance(document, bytes) or len(document) > MAX_TASK_BYTES:
                ledger.unreportable(task_id, b"")
                continue
            candidates.append((task_id, document))
            if len(candidates) == BATCH_SIZE:
                break

    for task_id, document in candidates:
        _handle_task(
            state_dir_value,
            state,
            ledger,
            task_id,
            document,
            client_factory,
            validator_factory,
            uuid_factory,
            clock,
            snapshot_executor,
        )
    return PollCycleResult(len(candidates))


def _handle_task(
    state_dir_value: str,
    state,
    ledger: TaskLedger,
    task_id: str,
    document: bytes,
    client_factory,
    validator_factory,
    uuid_factory,
    clock,
    snapshot_executor,
) -> None:
    validator = validator_factory()
    try:
        task = validator.validate_after_receive(document)
    except ContractError:
        task = _recover_correlation(document, task_id)
        if task is None:
            ledger.unreportable(task_id, document)
            return
        status, code, message = "REJECTED", "CONTRACT_INVALID", "Task contract is invalid."
    else:
        if task["taskId"] != task_id:
            status, code, message = (
                "REJECTED",
                "TASK_ID_MISMATCH",
                "Task identity does not match its mailbox path.",
            )
        elif task["agentId"] != state.identity.agentId:
            status, code, message = (
                "REJECTED",
                "AGENT_ID_MISMATCH",
                "Task targets a different Agent.",
            )
        elif _parse_timestamp(task["expiresAt"]) <= clock():
            status, code, message = "REJECTED", "TASK_EXPIRED", "Task expired before execution."
        elif task["taskType"] != "COLLECT_SNAPSHOT":
            status, code, message = (
                "REJECTED",
                "CAPABILITY_NOT_AVAILABLE",
                "Task capability is not available in this Agent version.",
            )
        else:
            status = code = message = None

    message_id = _new_uuid(uuid_factory)
    result_id = _new_uuid(uuid_factory, message_id)
    record = ledger.begin(task_id, task["taskType"], document, message_id, result_id)
    if status is None:
        try:
            snapshot_executor(state_dir_value, CAPABILITY_TIMEOUT_SECONDS)
        except CapabilityTimeoutError:
            status, code, message = "FAILED", "CAPABILITY_TIMEOUT", "Snapshot collection timed out."
        except Exception:
            status, code, message = "FAILED", "COLLECTION_FAILED", "Snapshot collection failed."
        else:
            status = "SUCCEEDED"

    completed_at = _timestamp(clock())
    result = _result_document(
        validator,
        state.identity.agentId,
        record,
        status,
        completed_at,
        code,
        message,
    )
    record = ledger.terminal(record, result, completed_at)
    _transfer_result(ledger, record, state, client_factory, clock)


def _recover_interrupted(ledger, agent_id, validator_factory, clock) -> None:
    validator = validator_factory()
    for record in ledger.records():
        if record.state != "RUNNING":
            continue
        completed_at = _timestamp(clock())
        document = _result_document(
            validator,
            agent_id,
            record,
            "FAILED",
            completed_at,
            "EXECUTION_INTERRUPTED",
            "Agent stopped before task execution completed.",
        )
        ledger.terminal(record, document, completed_at)


def _retry_terminal_results(ledger, state, client_factory, clock) -> None:
    for record in ledger.records():
        if record.state == "TERMINAL":
            _transfer_result(ledger, record, state, client_factory, clock)


def _transfer_result(ledger, record, state, client_factory, clock) -> None:
    if record.resultDocument is None or record.resultMessageId is None:
        raise LedgerError("Terminal Agent result is incomplete.")
    temporary = f"{RESPONSE_DIRECTORY}/{record.resultMessageId}.json.part"
    final = f"{RESPONSE_DIRECTORY}/{record.resultMessageId}.json"
    with open_sftp_session(state, client_factory) as sftp:
        _require_remote_directory(sftp, RESPONSE_DIRECTORY)
        if _remote_equals(sftp, final, record.resultDocument):
            ledger.transferred(record, _timestamp(clock()))
            return
        if _remote_exists(sftp, final):
            raise AgentRunnerError("Agent result destination contains conflicting content.")
        if _remote_exists(sftp, temporary):
            sftp.remove(temporary)
        created = False
        try:
            remote = sftp.file(temporary, mode="wx")
            created = True
            with remote:
                remote.write(record.resultDocument)
            uploaded = sftp.stat(temporary)
            if uploaded.st_size != len(record.resultDocument):
                raise AgentRunnerError("Agent result upload could not be verified.")
            sftp.rename(temporary, final)
            if not _remote_equals(sftp, final, record.resultDocument):
                raise AgentRunnerError("Agent result finalization could not be verified.")
        except Exception:
            if created:
                with suppress(OSError):
                    sftp.remove(temporary)
            raise
    ledger.transferred(record, _timestamp(clock()))


class CapabilityTimeoutError(RuntimeError):
    pass


def execute_snapshot_with_timeout(state_dir_value: str, timeout_seconds: int) -> None:
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_snapshot_process, args=(state_dir_value,))
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join()
        raise CapabilityTimeoutError
    if process.exitcode != 0:
        raise SnapshotError("Snapshot capability failed in its isolated process.")


def _snapshot_process(state_dir_value: str) -> None:
    try:
        send_snapshot(state_dir_value)
    except Exception:
        raise SystemExit(1) from None


def _result_document(
    validator,
    agent_id: str,
    record: LedgerRecord,
    status: str,
    completed_at: str,
    code: str | None,
    message: str | None,
) -> bytes:
    value = {
        "agentId": agent_id,
        "completedAt": completed_at,
        "contractVersion": "1.0",
        "createdAt": completed_at,
        "messageId": record.resultMessageId,
        "messageType": "AGENT_RESULT",
        "resultId": record.resultId,
        "status": status,
        "taskId": record.taskId,
        "taskType": record.taskType,
    }
    if code is not None and message is not None:
        value["error"] = {"code": code, "message": message}
    document = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    validator.validate_before_emit(document)
    return document


def _recover_correlation(document: bytes, filename_task_id: str) -> dict[str, Any] | None:
    try:
        value = json.loads(document)
        task_id = value["taskId"]
        task_type = value["taskType"]
        if task_id != filename_task_id or not _is_uuid_v4(task_id):
            return None
        if task_type not in {
            "COLLECT_SNAPSHOT",
            "COLLECT_NETWORK_STATE",
            "COLLECT_SOFTWARE_INVENTORY",
        }:
            return None
        return value
    except UnicodeError, json.JSONDecodeError, TypeError, KeyError:
        return None


def _require_remote_directory(sftp, path: str) -> None:
    details = sftp.stat(path)
    if details.st_mode is None or not stat.S_ISDIR(details.st_mode):
        raise AgentRunnerError("Agent mailbox path is not a directory.")


def _remote_exists(sftp, path: str) -> bool:
    try:
        sftp.stat(path)
        return True
    except OSError as exception:
        if exception.errno == errno.ENOENT:
            return False
        raise


def _remote_equals(sftp, path: str, expected: bytes) -> bool:
    try:
        details = sftp.stat(path)
    except OSError as exception:
        if exception.errno == errno.ENOENT:
            return False
        raise
    if (
        details.st_mode is None
        or not stat.S_ISREG(details.st_mode)
        or details.st_size != len(expected)
    ):
        return False
    with sftp.file(path, mode="rb") as remote:
        return remote.read(len(expected) + 1) == expected


def _task_id_from_filename(filename: str) -> str | None:
    if not filename.endswith(".json"):
        return None
    candidate = filename.removesuffix(".json")
    return candidate if _is_uuid_v4(candidate) and str(UUID(candidate)) == candidate else None


def _is_uuid_v4(value: object) -> bool:
    try:
        parsed = UUID(value)  # type: ignore[arg-type]
    except ValueError, AttributeError, TypeError:
        return False
    return parsed.version == 4 and parsed.variant == "specified in RFC 4122"


def _new_uuid(factory, different_from: str | None = None) -> str:
    value = factory()
    if (
        not isinstance(value, UUID)
        or value.version != 4
        or value.variant != "specified in RFC 4122"
    ):
        raise AgentRunnerError("Agent result identity generation failed.")
    result = str(value)
    if result == different_from:
        raise AgentRunnerError("Agent result identifiers must be independent.")
    return result


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError
    return parsed


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
