"""Private, atomic local ledger for terminal Agent task results."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from jaxon_agent.identity import (
    IdentityInitializationError,
    _validate_directory,
    _verify_directory_identity,
)

LEDGER_DIRECTORY = "task-ledger"
RUN_LOCK = "run.lock"
RETENTION = timedelta(days=30)


class LedgerError(RuntimeError):
    """A safe local ledger failure."""


@dataclass(frozen=True)
class LedgerRecord:
    taskId: str
    taskFingerprint: str
    taskType: str
    state: str
    resultMessageId: str | None
    resultId: str | None
    completedAt: str | None
    resultDocument: bytes | None
    transferredAt: str | None


class AgentRunLock:
    def __init__(self, state_dir_value: str) -> None:
        self._root = -1
        self._lock = -1
        path = Path(state_dir_value).expanduser().absolute()
        try:
            self._root, details = _open_private_directory(path)
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
            self._lock = os.open(RUN_LOCK, flags, 0o600, dir_fd=self._root)
            os.fchmod(self._lock, 0o600)
            lock_details = os.fstat(self._lock)
            if (
                not stat.S_ISREG(lock_details.st_mode)
                or lock_details.st_uid != os.geteuid()
                or stat.S_IMODE(lock_details.st_mode) != 0o600
            ):
                raise LedgerError("Agent runner lock is not safe.")
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exception:
                raise LedgerError("Another Agent runner is already active.") from exception
            _verify_directory_identity(path, details)
        except LedgerError:
            self.close()
            raise
        except (OSError, IdentityInitializationError) as exception:
            self.close()
            raise LedgerError("Agent runner lock could not be acquired safely.") from exception

    def close(self) -> None:
        if self._lock >= 0:
            with suppress(OSError):
                fcntl.flock(self._lock, fcntl.LOCK_UN)
            os.close(self._lock)
            self._lock = -1
        if self._root >= 0:
            os.close(self._root)
            self._root = -1

    def __enter__(self) -> AgentRunLock:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class TaskLedger:
    def __init__(self, state_dir_value: str) -> None:
        path = Path(state_dir_value).expanduser().absolute()
        self._root = -1
        self._directory = -1
        try:
            self._root, root_details = _open_private_directory(path)
            try:
                os.mkdir(LEDGER_DIRECTORY, 0o700, dir_fd=self._root)
                os.fsync(self._root)
            except FileExistsError:
                pass
            self._directory = os.open(
                LEDGER_DIRECTORY,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=self._root,
            )
            _validate_directory(os.fstat(self._directory))
            _verify_directory_identity(path, root_details)
        except (OSError, IdentityInitializationError) as exception:
            self.close()
            raise LedgerError("Agent task ledger is not safe.") from exception

    def close(self) -> None:
        if self._directory >= 0:
            os.close(self._directory)
            self._directory = -1
        if self._root >= 0:
            os.close(self._root)
            self._root = -1

    def __enter__(self) -> TaskLedger:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def get(self, task_id: str) -> LedgerRecord | None:
        name = _record_name(task_id)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._directory)
        except FileNotFoundError:
            return None
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_size > 8 * 1024 * 1024
            ):
                raise LedgerError("Agent task ledger contains an unsafe record.")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read()
            return _decode_record(task_id, content)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exception:
            raise LedgerError("Agent task ledger contains an invalid record.") from exception
        finally:
            os.close(descriptor)

    def begin(
        self,
        task_id: str,
        task_type: str,
        task_document: bytes,
        result_message_id: str,
        result_id: str,
    ) -> LedgerRecord:
        record = LedgerRecord(
            taskId=task_id,
            taskFingerprint=hashlib.sha256(task_document).hexdigest(),
            taskType=task_type,
            state="RUNNING",
            resultMessageId=result_message_id,
            resultId=result_id,
            completedAt=None,
            resultDocument=None,
            transferredAt=None,
        )
        self._store(record)
        return record

    def terminal(self, record: LedgerRecord, document: bytes, completed_at: str) -> LedgerRecord:
        terminal = LedgerRecord(
            taskId=record.taskId,
            taskFingerprint=record.taskFingerprint,
            taskType=record.taskType,
            state="TERMINAL",
            resultMessageId=record.resultMessageId,
            resultId=record.resultId,
            completedAt=completed_at,
            resultDocument=document,
            transferredAt=None,
        )
        self._store(terminal)
        return terminal

    def transferred(self, record: LedgerRecord, transferred_at: str) -> LedgerRecord:
        if record.state != "TERMINAL" or record.resultDocument is None:
            raise LedgerError("Only a terminal result can be marked transferred.")
        transferred = LedgerRecord(
            taskId=record.taskId,
            taskFingerprint=record.taskFingerprint,
            taskType=record.taskType,
            state="TRANSFERRED",
            resultMessageId=record.resultMessageId,
            resultId=record.resultId,
            completedAt=record.completedAt,
            resultDocument=record.resultDocument,
            transferredAt=transferred_at,
        )
        self._store(transferred)
        return transferred

    def unreportable(self, task_id: str, task_document: bytes) -> LedgerRecord:
        record = LedgerRecord(
            taskId=task_id,
            taskFingerprint=hashlib.sha256(task_document).hexdigest(),
            taskType="UNREPORTABLE",
            state="UNREPORTABLE",
            resultMessageId=None,
            resultId=None,
            completedAt=None,
            resultDocument=None,
            transferredAt=None,
        )
        self._store(record)
        return record

    def records(self) -> list[LedgerRecord]:
        records: list[LedgerRecord] = []
        for name in sorted(os.listdir(self._directory)):
            if name.endswith(".json.part"):
                self._remove_safe_temporary(name)
                continue
            if not name.endswith(".json"):
                raise LedgerError("Agent task ledger contains an unexpected entry.")
            records.append(self.get(name.removesuffix(".json")) or _never())
        return records

    def prune(self, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise LedgerError("Ledger retention requires a UTC clock.")
        cutoff = now - RETENTION
        for record in self.records():
            if record.state != "TRANSFERRED" or record.transferredAt is None:
                continue
            transferred = datetime.fromisoformat(record.transferredAt.removesuffix("Z") + "+00:00")
            if transferred < cutoff:
                os.unlink(_record_name(record.taskId), dir_fd=self._directory)
                os.fsync(self._directory)

    def _store(self, record: LedgerRecord) -> None:
        content = _encode_record(record)
        final_name = _record_name(record.taskId)
        temporary_name = final_name + ".part"
        self._remove_safe_temporary(temporary_name)
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._directory,
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(
                temporary_name,
                final_name,
                src_dir_fd=self._directory,
                dst_dir_fd=self._directory,
            )
            os.fsync(self._directory)
        except OSError as exception:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=self._directory)
            raise LedgerError("Agent task ledger could not be updated atomically.") from exception
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _remove_safe_temporary(self, name: str) -> None:
        try:
            details = os.stat(name, dir_fd=self._directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise LedgerError("Agent task ledger contains an unsafe temporary record.")
        os.unlink(name, dir_fd=self._directory)


def _open_private_directory(path: Path) -> tuple[int, os.stat_result]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise LedgerError("Agent task state requires POSIX no-follow support.")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    details = os.fstat(descriptor)
    _validate_directory(details)
    return descriptor, details


def _record_name(task_id: str) -> str:
    parsed = UUID(task_id)
    if parsed.version != 4 or str(parsed) != task_id:
        raise LedgerError("Agent task ledger identity is not a canonical UUIDv4.")
    return f"{task_id}.json"


def _encode_record(record: LedgerRecord) -> bytes:
    document = {
        "completedAt": record.completedAt,
        "formatVersion": 1,
        "resultDocument": (
            base64.b64encode(record.resultDocument).decode("ascii")
            if record.resultDocument is not None
            else None
        ),
        "resultDocumentSha256": (
            hashlib.sha256(record.resultDocument).hexdigest()
            if record.resultDocument is not None
            else None
        ),
        "resultId": record.resultId,
        "resultMessageId": record.resultMessageId,
        "state": record.state,
        "taskFingerprint": record.taskFingerprint,
        "taskId": record.taskId,
        "taskType": record.taskType,
        "transferredAt": record.transferredAt,
    }
    return (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _decode_record(task_id: str, content: bytes) -> LedgerRecord:
    value = json.loads(content)
    expected = {
        "completedAt",
        "formatVersion",
        "resultDocument",
        "resultDocumentSha256",
        "resultId",
        "resultMessageId",
        "state",
        "taskFingerprint",
        "taskId",
        "taskType",
        "transferredAt",
    }
    if set(value) != expected or value["formatVersion"] != 1 or value["taskId"] != task_id:
        raise ValueError
    document = (
        base64.b64decode(value["resultDocument"], validate=True)
        if value["resultDocument"] is not None
        else None
    )
    if (document is None) != (value["resultDocumentSha256"] is None):
        raise ValueError
    if (
        document is not None
        and hashlib.sha256(document).hexdigest() != value["resultDocumentSha256"]
    ):
        raise ValueError
    if value["state"] not in {"RUNNING", "TERMINAL", "TRANSFERRED", "UNREPORTABLE"}:
        raise ValueError
    return LedgerRecord(
        taskId=value["taskId"],
        taskFingerprint=value["taskFingerprint"],
        taskType=value["taskType"],
        state=value["state"],
        resultMessageId=value["resultMessageId"],
        resultId=value["resultId"],
        completedAt=value["completedAt"],
        resultDocument=document,
        transferredAt=value["transferredAt"],
    )


def _never() -> LedgerRecord:
    raise LedgerError("Agent task ledger record disappeared during inspection.")
