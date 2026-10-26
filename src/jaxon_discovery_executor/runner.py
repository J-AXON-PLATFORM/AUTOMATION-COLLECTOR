"""One-shot Discovery Job pickup, execution and atomic Result delivery."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import paramiko

from jaxon_discovery_executor.contracts import (
    MAX_JOB_BYTES,
    DiscoveryContractError,
    DiscoveryJobContractValidator,
    DiscoveryResultContractValidator,
)
from jaxon_discovery_executor.ledger import (
    DiscoveryLedger,
    DiscoveryLedgerError,
    DiscoveryLedgerRecord,
    DiscoveryRunLock,
)
from jaxon_discovery_executor.scanner import (
    MAX_TARGETS,
    BasicScanResult,
    UnsupportedDiscoveryPlatformError,
    scan_basic,
)
from jaxon_discovery_executor.sftp import (
    ExecutorSftpVerificationError,
    load_sftp_state,
    open_sftp_session,
)

JOB_DIRECTORY = "/jobs"
RESULT_DIRECTORY = "/results"


class DiscoveryRunnerError(RuntimeError):
    """A safe one-shot Discovery Executor failure."""


@dataclass(frozen=True)
class DiscoveryRunResult:
    executorId: str
    jobId: str | None
    status: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


def run_once(
    state_dir_value: str,
    *,
    client_factory=paramiko.SSHClient,
    job_validator_factory=DiscoveryJobContractValidator,
    result_validator_factory=DiscoveryResultContractValidator,
    uuid_factory=uuid4,
    clock=lambda: datetime.now(UTC),
    scan_executor=scan_basic,
) -> DiscoveryRunResult:
    """Handle at most one local pending Result or one eligible remote Job."""
    try:
        with DiscoveryRunLock(state_dir_value), DiscoveryLedger(state_dir_value) as ledger:
            state = load_sftp_state(state_dir_value)
            job_validator = job_validator_factory()
            result_validator = result_validator_factory()
            ready = next(
                (record for record in ledger.records() if record.state == "RESULT_READY"), None
            )
            if ready is not None:
                _validate_ready(ready, state.identity.executorId, job_validator, result_validator)
                _deliver(ledger, ready, state, client_factory, clock)
                return DiscoveryRunResult(state.identity.executorId, ready.jobId, "DELIVERED")

            _recover_interrupted(
                ledger, state.identity.executorId, job_validator, result_validator, clock
            )

            ready = next(
                (record for record in ledger.records() if record.state == "RESULT_READY"), None
            )
            if ready is not None:
                _validate_ready(ready, state.identity.executorId, job_validator, result_validator)
                _deliver(ledger, ready, state, client_factory, clock)
                return DiscoveryRunResult(state.identity.executorId, ready.jobId, "DELIVERED")

            received = next(
                (record for record in ledger.records() if record.state == "RECEIVED"), None
            )
            if received is None:
                received = _receive_one(
                    ledger,
                    state,
                    client_factory,
                    job_validator,
                    uuid_factory,
                    clock,
                )
            if received is None:
                return DiscoveryRunResult(state.identity.executorId, None, "IDLE")

            ready = _execute(
                ledger,
                received,
                state.identity.executorId,
                job_validator,
                result_validator,
                clock,
                scan_executor,
            )
            _deliver(ledger, ready, state, client_factory, clock)
            return DiscoveryRunResult(state.identity.executorId, ready.jobId, "DELIVERED")
    except DiscoveryRunnerError:
        raise
    except (
        DiscoveryContractError,
        DiscoveryLedgerError,
        ExecutorSftpVerificationError,
        OSError,
        ValueError,
    ) as exception:
        raise DiscoveryRunnerError(
            "Discovery Executor stopped after a safe local, contract or SFTP failure."
        ) from exception


def _receive_one(ledger, state, client_factory, validator, uuid_factory, clock):
    with open_sftp_session(state, client_factory) as sftp:
        _require_remote_directory(sftp, JOB_DIRECTORY)
        for details in sorted(sftp.listdir_attr(JOB_DIRECTORY), key=lambda item: item.filename):
            job_id = _job_id_from_filename(details.filename)
            if job_id is None or details.st_mode is None or not stat.S_ISREG(details.st_mode):
                continue
            existing = ledger.get(job_id)
            if details.st_size is None or details.st_size > MAX_JOB_BYTES:
                if existing is None:
                    raise DiscoveryRunnerError("Discovery Job exceeds the maximum supported size.")
                raise DiscoveryRunnerError("Discovery Job changed after local receipt.")
            path = f"{JOB_DIRECTORY}/{details.filename}"
            with sftp.file(path, mode="rb") as remote:
                document = remote.read(MAX_JOB_BYTES + 1)
            if not isinstance(document, bytes) or len(document) > MAX_JOB_BYTES:
                raise DiscoveryRunnerError("Discovery Job exceeds the maximum supported size.")
            if existing is not None:
                if hashlib.sha256(document).hexdigest() != existing.jobFingerprint:
                    raise DiscoveryRunnerError("Discovery Job changed after local receipt.")
                continue
            job = validator.validate_after_receive(document)
            if job["jobId"] != job_id:
                raise DiscoveryRunnerError(
                    "Discovery Job identity does not match its mailbox path."
                )
            if job["executorId"] != state.identity.executorId:
                raise DiscoveryRunnerError("Discovery Job targets a different executor.")
            return ledger.receive(
                job_id,
                document,
                _new_uuid(uuid_factory),
                _timestamp(clock()),
            )
    return None


def _execute(
    ledger,
    record,
    executor_id,
    job_validator,
    result_validator,
    clock,
    scan_executor,
):
    job = _validated_job(record, executor_id, job_validator)
    scope_size = ipaddress.ip_network(job["scopeCidr"], strict=True).num_addresses
    failure_code = None
    scan = BasicScanResult(scope_size, 0, [])
    if _parse_timestamp(job["expiresAt"]) <= clock():
        failure_code = "JOB_EXPIRED"
    elif scope_size > MAX_TARGETS:
        failure_code = "SCOPE_TOO_LARGE"
    else:
        record = ledger.running(record)
        try:
            scan = scan_executor(job["scopeCidr"])
        except UnsupportedDiscoveryPlatformError:
            failure_code = "UNSUPPORTED_PLATFORM"
        except Exception:
            failure_code = "EXECUTION_ERROR"
    completed_at = _completion_timestamp(record.startedAt, clock())
    document = _result_document(
        result_validator,
        record,
        job,
        executor_id,
        completed_at,
        scan,
        failure_code,
    )
    return ledger.result_ready(record, document, completed_at)


def _recover_interrupted(ledger, executor_id, job_validator, result_validator, clock):
    for record in ledger.records():
        if record.state != "RUNNING":
            continue
        job = _validated_job(record, executor_id, job_validator)
        considered = ipaddress.ip_network(job["scopeCidr"], strict=True).num_addresses
        completed_at = _completion_timestamp(record.startedAt, clock())
        document = _result_document(
            result_validator,
            record,
            job,
            executor_id,
            completed_at,
            BasicScanResult(considered, 0, []),
            "EXECUTION_INTERRUPTED",
        )
        ledger.result_ready(record, document, completed_at)
        return


def _result_document(
    validator,
    record: DiscoveryLedgerRecord,
    job: dict[str, Any],
    executor_id: str,
    completed_at: str,
    scan: BasicScanResult,
    failure_code: str | None,
) -> bytes:
    observations = scan.observations if failure_code is None else []
    value = {
        "completedAt": completed_at,
        "executorId": executor_id,
        "failureCode": failure_code,
        "jobId": record.jobId,
        "messageType": "DISCOVERY_RESULT",
        "observations": observations,
        "profile": "BASIC",
        "resultId": record.resultId,
        "schemaVersion": "1.0",
        "scopeId": job["scopeId"],
        "startedAt": record.startedAt,
        "status": "SUCCEEDED" if failure_code is None else "FAILED",
        "summary": {
            "observationsFound": len(observations),
            "targetsConsidered": scan.targetsConsidered,
            "targetsScanned": scan.targetsScanned,
        },
    }
    document = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    validator.validate_before_emit(document, job["scopeCidr"])
    return document


def _validated_job(record, executor_id, validator):
    job = validator.validate_after_receive(record.jobDocument)
    if job["jobId"] != record.jobId or job["executorId"] != executor_id:
        raise DiscoveryRunnerError("Local Discovery Job correlation is invalid.")
    return job


def _validate_ready(record, executor_id, job_validator, result_validator) -> None:
    if record.resultDocument is None:
        raise DiscoveryLedgerError("Ready Discovery Result is incomplete.")
    job = _validated_job(record, executor_id, job_validator)
    result = result_validator.validate_before_emit(record.resultDocument, job["scopeCidr"])
    if (
        result["resultId"] != record.resultId
        or result["jobId"] != record.jobId
        or result["executorId"] != executor_id
        or result["scopeId"] != job["scopeId"]
    ):
        raise DiscoveryRunnerError("Local Discovery Result correlation is invalid.")


def _deliver(ledger, record, state, client_factory, clock) -> None:
    if record.resultDocument is None:
        raise DiscoveryLedgerError("Ready Discovery Result is incomplete.")
    temporary = f"{RESULT_DIRECTORY}/{record.jobId}.json.part"
    final = f"{RESULT_DIRECTORY}/{record.jobId}.json"
    with open_sftp_session(state, client_factory) as sftp:
        _require_remote_directory(sftp, RESULT_DIRECTORY)
        if _remote_equals(sftp, final, record.resultDocument):
            ledger.delivered(record, _timestamp(clock()))
            return
        if _remote_exists(sftp, final):
            raise DiscoveryRunnerError("Discovery Result destination contains conflicting content.")
        if _remote_exists(sftp, temporary):
            if not _remote_equals(sftp, temporary, record.resultDocument):
                raise DiscoveryRunnerError(
                    "Discovery Result temporary contains conflicting content."
                )
        else:
            with sftp.file(temporary, mode="wx") as remote:
                remote.write(record.resultDocument)
            uploaded = sftp.stat(temporary)
            if uploaded.st_size != len(record.resultDocument):
                raise DiscoveryRunnerError("Discovery Result upload could not be verified.")
        sftp.rename(temporary, final)
        if not _remote_equals(sftp, final, record.resultDocument):
            raise DiscoveryRunnerError("Discovery Result finalization could not be verified.")
    ledger.delivered(record, _timestamp(clock()))


def _require_remote_directory(sftp, path: str) -> None:
    details = sftp.stat(path)
    if details.st_mode is None or not stat.S_ISDIR(details.st_mode):
        raise DiscoveryRunnerError("Discovery mailbox path is not a directory.")


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


def _job_id_from_filename(filename: str) -> str | None:
    if not filename.endswith(".json"):
        return None
    candidate = filename.removesuffix(".json")
    try:
        parsed = UUID(candidate)
    except ValueError, AttributeError:
        return None
    return candidate if parsed.version == 4 and str(parsed) == candidate else None


def _new_uuid(factory) -> str:
    value = factory()
    if (
        not isinstance(value, UUID)
        or value.version != 4
        or value.variant != "specified in RFC 4122"
    ):
        raise DiscoveryRunnerError("Discovery Result identity generation failed.")
    return str(value)


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError
    return parsed


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _completion_timestamp(started_at: str, value: datetime) -> str:
    current = _timestamp(value)
    return started_at if _parse_timestamp(current) < _parse_timestamp(started_at) else current
