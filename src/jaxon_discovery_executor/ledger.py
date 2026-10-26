"""Private atomic state for one-shot Discovery Job execution."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import stat
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from jaxon_discovery_executor.identity import (
    ExecutorIdentityInitializationError,
    _validate_directory,
    _verify_directory_identity,
)

LEDGER_DIRECTORY = "discovery-ledger"
RUN_LOCK = "run.lock"
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_JOB_BYTES = 64 * 1024
MAX_RESULT_BYTES = 5 * 1024 * 1024


class DiscoveryLedgerError(RuntimeError):
    """A safe local Discovery ledger failure."""


@dataclass(frozen=True)
class DiscoveryLedgerRecord:
    jobId: str
    jobFingerprint: str
    jobDocument: bytes
    state: str
    resultId: str
    startedAt: str
    completedAt: str | None
    resultDocument: bytes | None
    deliveredAt: str | None


class DiscoveryRunLock:
    def __init__(self, state_dir_value: str) -> None:
        self._root = -1
        self._lock = -1
        path = Path(state_dir_value).expanduser().absolute()
        try:
            self._root, details = _open_private_directory(path)
            created = False
            try:
                self._lock = os.open(
                    RUN_LOCK,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self._root,
                )
                created = True
            except FileExistsError:
                self._lock = os.open(RUN_LOCK, os.O_RDWR | os.O_NOFOLLOW, dir_fd=self._root)
            os.fchmod(self._lock, 0o600)
            lock_details = os.fstat(self._lock)
            if (
                not stat.S_ISREG(lock_details.st_mode)
                or lock_details.st_uid != os.geteuid()
                or stat.S_IMODE(lock_details.st_mode) != 0o600
            ):
                raise DiscoveryLedgerError("Discovery runner lock is not safe.")
            if created:
                os.fsync(self._root)
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exception:
                raise DiscoveryLedgerError(
                    "Another Discovery Executor runner is already active."
                ) from exception
            _verify_directory_identity(path, details)
        except DiscoveryLedgerError:
            self.close()
            raise
        except (OSError, ExecutorIdentityInitializationError) as exception:
            self.close()
            raise DiscoveryLedgerError(
                "Discovery Executor runner lock could not be acquired safely."
            ) from exception

    def close(self) -> None:
        if self._lock >= 0:
            with suppress(OSError):
                fcntl.flock(self._lock, fcntl.LOCK_UN)
            os.close(self._lock)
            self._lock = -1
        if self._root >= 0:
            os.close(self._root)
            self._root = -1

    def __enter__(self) -> DiscoveryRunLock:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class DiscoveryLedger:
    def __init__(self, state_dir_value: str) -> None:
        self._root = -1
        self._directory = -1
        path = Path(state_dir_value).expanduser().absolute()
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
        except (OSError, ExecutorIdentityInitializationError) as exception:
            self.close()
            raise DiscoveryLedgerError("Discovery Job ledger is not safe.") from exception

    def close(self) -> None:
        if self._directory >= 0:
            os.close(self._directory)
            self._directory = -1
        if self._root >= 0:
            os.close(self._root)
            self._root = -1

    def __enter__(self) -> DiscoveryLedger:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def get(self, job_id: str) -> DiscoveryLedgerRecord | None:
        name = _record_name(job_id)
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                dir_fd=self._directory,
            )
        except FileNotFoundError:
            return None
        except OSError as exception:
            raise DiscoveryLedgerError(
                "Discovery Job ledger contains an invalid record."
            ) from exception
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_size > MAX_RECORD_BYTES
            ):
                raise DiscoveryLedgerError("Discovery Job ledger contains an unsafe record.")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                return _decode_record(job_id, stream.read())
        except (
            OSError,
            AttributeError,
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
        ) as exception:
            raise DiscoveryLedgerError(
                "Discovery Job ledger contains an invalid record."
            ) from exception
        finally:
            os.close(descriptor)

    def records(self) -> list[DiscoveryLedgerRecord]:
        records: list[DiscoveryLedgerRecord] = []
        for name in sorted(os.listdir(self._directory)):
            if name.endswith(".json.part"):
                self._remove_safe_temporary(name)
                continue
            if not name.endswith(".json"):
                raise DiscoveryLedgerError("Discovery Job ledger contains an unexpected entry.")
            record = self.get(name.removesuffix(".json"))
            if record is None:
                raise DiscoveryLedgerError("Discovery Job ledger changed during inspection.")
            records.append(record)
        return records

    def receive(
        self, job_id: str, job_document: bytes, result_id: str, started_at: str
    ) -> DiscoveryLedgerRecord:
        record = DiscoveryLedgerRecord(
            jobId=job_id,
            jobFingerprint=hashlib.sha256(job_document).hexdigest(),
            jobDocument=job_document,
            state="RECEIVED",
            resultId=result_id,
            startedAt=started_at,
            completedAt=None,
            resultDocument=None,
            deliveredAt=None,
        )
        self._store(record)
        return record

    def running(self, record: DiscoveryLedgerRecord) -> DiscoveryLedgerRecord:
        if record.state != "RECEIVED":
            raise DiscoveryLedgerError("Only a received Discovery Job can begin execution.")
        updated = replace(record, state="RUNNING")
        self._store(updated)
        return updated

    def result_ready(
        self, record: DiscoveryLedgerRecord, document: bytes, completed_at: str
    ) -> DiscoveryLedgerRecord:
        if record.state not in {"RECEIVED", "RUNNING"}:
            raise DiscoveryLedgerError("Discovery Result cannot be prepared from this state.")
        updated = replace(
            record,
            state="RESULT_READY",
            completedAt=completed_at,
            resultDocument=document,
        )
        self._store(updated)
        return updated

    def delivered(self, record: DiscoveryLedgerRecord, delivered_at: str) -> DiscoveryLedgerRecord:
        if record.state != "RESULT_READY" or record.resultDocument is None:
            raise DiscoveryLedgerError("Only a ready Discovery Result can be marked delivered.")
        updated = replace(record, state="DELIVERED", deliveredAt=delivered_at)
        self._store(updated)
        return updated

    def _store(self, record: DiscoveryLedgerRecord) -> None:
        content = _encode_record(record)
        if len(content) > MAX_RECORD_BYTES:
            raise DiscoveryLedgerError("Discovery Job ledger record exceeds its size limit.")
        final_name = _record_name(record.jobId)
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
            raise DiscoveryLedgerError(
                "Discovery Job ledger could not be updated atomically."
            ) from exception
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _remove_safe_temporary(self, name: str) -> None:
        try:
            details = os.stat(name, dir_fd=self._directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise DiscoveryLedgerError("Discovery Job ledger contains an unsafe temporary record.")
        os.unlink(name, dir_fd=self._directory)
        os.fsync(self._directory)


def _open_private_directory(path: Path) -> tuple[int, os.stat_result]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise DiscoveryLedgerError("Discovery Job state requires POSIX no-follow support.")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    details = os.fstat(descriptor)
    _validate_directory(details)
    return descriptor, details


def _record_name(job_id: str) -> str:
    parsed = UUID(job_id)
    if parsed.version != 4 or str(parsed) != job_id:
        raise DiscoveryLedgerError("Discovery Job identity is not a canonical UUIDv4.")
    return f"{job_id}.json"


def _encode_record(record: DiscoveryLedgerRecord) -> bytes:
    result_document = (
        base64.b64encode(record.resultDocument).decode("ascii")
        if record.resultDocument is not None
        else None
    )
    value = {
        "completedAt": record.completedAt,
        "deliveredAt": record.deliveredAt,
        "formatVersion": 1,
        "jobDocument": base64.b64encode(record.jobDocument).decode("ascii"),
        "jobFingerprint": record.jobFingerprint,
        "jobId": record.jobId,
        "resultDocument": result_document,
        "resultDocumentSha256": (
            hashlib.sha256(record.resultDocument).hexdigest()
            if record.resultDocument is not None
            else None
        ),
        "resultId": record.resultId,
        "startedAt": record.startedAt,
        "state": record.state,
    }
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def _decode_record(job_id: str, content: bytes) -> DiscoveryLedgerRecord:
    value = json.loads(content)
    expected = {
        "completedAt",
        "deliveredAt",
        "formatVersion",
        "jobDocument",
        "jobFingerprint",
        "jobId",
        "resultDocument",
        "resultDocumentSha256",
        "resultId",
        "startedAt",
        "state",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["formatVersion"] != 1
        or value["jobId"] != job_id
    ):
        raise ValueError
    job_document = base64.b64decode(value["jobDocument"], validate=True)
    if (
        len(job_document) > MAX_JOB_BYTES
        or hashlib.sha256(job_document).hexdigest() != value["jobFingerprint"]
    ):
        raise ValueError
    result_document = (
        base64.b64decode(value["resultDocument"], validate=True)
        if value["resultDocument"] is not None
        else None
    )
    if (result_document is None) != (value["resultDocumentSha256"] is None):
        raise ValueError
    if result_document is not None and (
        len(result_document) > MAX_RESULT_BYTES
        or hashlib.sha256(result_document).hexdigest() != value["resultDocumentSha256"]
    ):
        raise ValueError
    if value["state"] not in {"RECEIVED", "RUNNING", "RESULT_READY", "DELIVERED"}:
        raise ValueError
    result_id = UUID(value["resultId"])
    if result_id.version != 4 or str(result_id) != value["resultId"]:
        raise ValueError
    _parse_timestamp(value["startedAt"])
    state = value["state"]
    if state in {"RECEIVED", "RUNNING"} and any(
        item is not None for item in (value["completedAt"], result_document, value["deliveredAt"])
    ):
        raise ValueError
    if state == "RESULT_READY" and (
        value["completedAt"] is None or result_document is None or value["deliveredAt"] is not None
    ):
        raise ValueError
    if state == "DELIVERED" and (
        value["completedAt"] is None or result_document is None or value["deliveredAt"] is None
    ):
        raise ValueError
    if value["completedAt"] is not None:
        _parse_timestamp(value["completedAt"])
    if value["deliveredAt"] is not None:
        _parse_timestamp(value["deliveredAt"])
    return DiscoveryLedgerRecord(
        jobId=value["jobId"],
        jobFingerprint=value["jobFingerprint"],
        jobDocument=job_document,
        state=value["state"],
        resultId=value["resultId"],
        startedAt=value["startedAt"],
        completedAt=value["completedAt"],
        resultDocument=result_document,
        deliveredAt=value["deliveredAt"],
    )


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError
    return parsed
