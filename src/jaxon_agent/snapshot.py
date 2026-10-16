"""One-shot collection and atomic SFTP transfer of a minimal Agent snapshot."""

from __future__ import annotations

import errno
import json
import os
import platform
import shutil
import socket
import stat
import sys
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import paramiko

from jaxon_agent.contracts import AgentContractValidator, ContractError
from jaxon_agent.sftp import (
    SftpConfigurationError,
    SftpVerificationError,
    load_sftp_state,
    open_sftp_session,
)

MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024
SNAPSHOT_DIRECTORY = "/snapshots"


class SnapshotError(RuntimeError):
    """A safe one-shot snapshot failure."""


@dataclass(frozen=True)
class SnapshotSendResult:
    agentId: str
    capturedAt: str
    createdAt: str
    messageId: str
    remotePath: str
    snapshotId: str
    status: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


def send_snapshot(
    state_dir_value: str,
    *,
    client_factory=paramiko.SSHClient,
    validator_factory=AgentContractValidator,
    uuid_factory=uuid4,
    clock=lambda: datetime.now(UTC),
    payload_collector=None,
) -> SnapshotSendResult:
    """Collect, validate and send one snapshot without local persistence or retries."""
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise SnapshotError("Snapshot collection requires supported POSIX/Linux.")

    try:
        state = load_sftp_state(state_dir_value)
        payload = (payload_collector or collect_snapshot_payload)()
        message_id = _new_uuid_v4(uuid_factory)
        snapshot_id = _new_uuid_v4(uuid_factory, different_from=message_id)
        captured_at = _utc_timestamp(clock())
        created_at = _utc_timestamp(clock())
        message = {
            "agentId": state.identity.agentId,
            "capturedAt": captured_at,
            "contractVersion": "1.0",
            "createdAt": created_at,
            "messageId": str(message_id),
            "messageType": "AGENT_SNAPSHOT",
            "payload": payload,
            "snapshotId": str(snapshot_id),
        }
        document = json.dumps(
            message, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(document) > MAX_SNAPSHOT_BYTES:
            raise SnapshotError("Snapshot exceeds the maximum supported size.")
        validator_factory().validate_before_emit(document)
    except SnapshotError:
        raise
    except (
        ContractError,
        SftpConfigurationError,
        SftpVerificationError,
        OSError,
        ValueError,
    ) as exception:
        raise SnapshotError("Snapshot could not be collected and validated safely.") from exception

    temporary_path = f"{SNAPSHOT_DIRECTORY}/{message_id}.json.part"
    final_path = f"{SNAPSHOT_DIRECTORY}/{message_id}.json"
    try:
        with open_sftp_session(state, client_factory) as sftp:
            _ensure_snapshot_directory(sftp)
            if _exists(sftp, temporary_path) or _exists(sftp, final_path):
                raise SnapshotError("Snapshot destination already exists.")
            temporary_created = False
            try:
                remote = sftp.file(temporary_path, mode="wx")
                temporary_created = True
                with remote:
                    remote.write(document)
                uploaded = sftp.stat(temporary_path)
                if uploaded.st_size != len(document):
                    raise SnapshotError("Snapshot upload could not be verified.")
                sftp.rename(temporary_path, final_path)
                final = sftp.stat(final_path)
                if final.st_size != len(document) or _exists(sftp, temporary_path):
                    raise SnapshotError("Snapshot finalization could not be verified.")
            except Exception:
                if temporary_created:
                    _remove_own_temporary(sftp, temporary_path)
                raise
    except SnapshotError:
        raise
    except Exception as exception:
        raise SnapshotError("Snapshot could not be transferred securely.") from exception

    return SnapshotSendResult(
        agentId=state.identity.agentId,
        capturedAt=captured_at,
        createdAt=created_at,
        messageId=str(message_id),
        remotePath=final_path,
        snapshotId=str(snapshot_id),
        status="SENT",
    )


def collect_snapshot_payload() -> dict[str, Any]:
    """Collect only the minimum approved Linux technical observations."""
    if platform.system() != "Linux":
        raise SnapshotError("Snapshot collection requires supported POSIX/Linux.")
    hostname = _bounded_text(socket.gethostname(), 253)
    release = platform.freedesktop_os_release()
    os_name = _bounded_text(release.get("NAME"), 128)
    os_version = _bounded_text(release.get("VERSION_ID") or release.get("VERSION"), 128)
    architecture = _architecture(platform.machine())
    cpu_count = os.cpu_count()
    if type(cpu_count) is not int or cpu_count < 1:
        raise SnapshotError("Logical CPU information is not valid.")
    pages = os.sysconf("SC_PHYS_PAGES")
    page_size = os.sysconf("SC_PAGE_SIZE")
    if type(pages) is not int or type(page_size) is not int or pages < 1 or page_size < 1:
        raise SnapshotError("Memory information is not valid.")
    memory_bytes = pages * page_size
    usage = shutil.disk_usage("/")
    if usage.total < 1 or usage.free < 0 or usage.free > usage.total:
        raise SnapshotError("Storage information is not valid.")
    return {
        "architecture": architecture,
        "hostname": hostname,
        "logicalCpuCount": cpu_count,
        "memoryBytes": memory_bytes,
        "operatingSystem": {
            "family": "LINUX",
            "name": os_name,
            "version": os_version,
        },
        "storageVolumes": [
            {
                "availableBytes": usage.free,
                "name": "/",
                "totalBytes": usage.total,
            }
        ],
    }


def _ensure_snapshot_directory(sftp) -> None:
    try:
        details = sftp.stat(SNAPSHOT_DIRECTORY)
    except OSError as exception:
        if exception.errno != errno.ENOENT:
            raise
        sftp.mkdir(SNAPSHOT_DIRECTORY)
        details = sftp.stat(SNAPSHOT_DIRECTORY)
    if details.st_mode is None or not stat.S_ISDIR(details.st_mode):
        raise SnapshotError("Snapshot destination is not a directory.")


def _exists(sftp, path: str) -> bool:
    try:
        sftp.stat(path)
        return True
    except OSError as exception:
        if exception.errno == errno.ENOENT:
            return False
        raise


def _remove_own_temporary(sftp, path: str) -> None:
    with suppress(OSError):
        sftp.remove(path)


def _new_uuid_v4(factory, different_from: UUID | None = None) -> UUID:
    value = factory()
    if (
        not isinstance(value, UUID)
        or value.version != 4
        or value.variant != "specified in RFC 4122"
    ):
        raise SnapshotError("Snapshot identity generation failed.")
    if different_from is not None and value == different_from:
        raise SnapshotError("Snapshot identifiers must be independent.")
    return value


def _utc_timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise SnapshotError("Snapshot timestamp generation failed.")
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bounded_text(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SnapshotError("Collected system information is incomplete or invalid.")
    return value


def _architecture(value: str) -> str:
    normalized = value.lower()
    if normalized in {"amd64", "x86_64"}:
        return "X86_64"
    if normalized in {"i386", "i486", "i586", "i686", "x86"}:
        return "X86"
    if normalized in {"aarch64", "arm64"}:
        return "ARM64"
    if normalized == "arm" or normalized.startswith(("armv6", "armv7")):
        return "ARM32"
    return "OTHER"
