"""Local Discovery Executor identity initialization without network access."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIVATE_KEY_NAME = "executor_ed25519"
PUBLIC_KEY_NAME = "executor_ed25519.pub"
METADATA_NAME = "executor.json"
EXPECTED_FILES = {PRIVATE_KEY_NAME, PUBLIC_KEY_NAME, METADATA_NAME}
OPTIONAL_FILES = {"sftp.json"}


class ExecutorIdentityInitializationError(RuntimeError):
    """A safe, operator-facing identity initialization failure."""


@dataclass(frozen=True)
class ExecutorInitializationResult:
    executorId: str
    publicKeyPath: str
    publicKeyFingerprint: str
    publicKey: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


def initialize_identity(
    executor_id_value: str, state_dir_value: str
) -> ExecutorInitializationResult:
    executor_id = _uuid_v4(executor_id_value)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ExecutorIdentityInitializationError(
            "Discovery Executor identity initialization requires POSIX no-follow support."
        )
    state_dir = Path(state_dir_value).expanduser().absolute()
    created = False
    try:
        try:
            path_details = state_dir.lstat()
        except FileNotFoundError:
            try:
                state_dir.mkdir(mode=0o700, parents=True)
                os.chmod(state_dir, 0o700, follow_symlinks=False)
                created = True
            except FileExistsError:
                pass
            path_details = state_dir.lstat()

        if not stat.S_ISDIR(path_details.st_mode):
            raise ExecutorIdentityInitializationError(
                "State directory must be a private directory."
            )

        descriptor = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory_details = os.fstat(descriptor)
            _validate_directory(directory_details)
            files = set(os.listdir(descriptor))
            if files and (
                not EXPECTED_FILES.issubset(files)
                or not files.issubset(EXPECTED_FILES | OPTIONAL_FILES)
            ):
                raise ExecutorIdentityInitializationError(
                    "Discovery Executor state is incomplete or incompatible."
                )
            result = (
                _load_existing(executor_id, state_dir, descriptor)
                if files
                else _create_identity(executor_id, state_dir, descriptor)
            )
            _verify_directory_identity(state_dir, directory_details)
            return result
        finally:
            os.close(descriptor)
    except ExecutorIdentityInitializationError:
        raise
    except (OSError, ValueError) as exception:
        if created:
            with suppress(OSError):
                state_dir.rmdir()
        raise ExecutorIdentityInitializationError(
            "Discovery Executor identity could not be initialized safely."
        ) from exception


def _create_identity(
    executor_id: UUID, state_dir: Path, descriptor: int
) -> ExecutorInitializationResult:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    )
    public_key = public_bytes.decode("ascii")
    metadata = {
        "executorId": str(executor_id),
        "formatVersion": 1,
        "keyAlgorithm": "ssh-ed25519",
        "publicKeyFingerprint": _fingerprint(public_key),
    }

    created_files: list[str] = []
    try:
        for name, content in (
            (PRIVATE_KEY_NAME, private_bytes + b"\n"),
            (PUBLIC_KEY_NAME, public_bytes + b"\n"),
            (
                METADATA_NAME,
                (json.dumps(metadata, separators=(",", ":"), sort_keys=True) + "\n").encode(),
            ),
        ):
            _write_exclusive(descriptor, name, content)
            created_files.append(name)
        os.fsync(descriptor)
        return _load_existing(executor_id, state_dir, descriptor)
    except Exception:
        for name in reversed(created_files):
            with suppress(OSError):
                os.unlink(name, dir_fd=descriptor)
        with suppress(OSError):
            os.fsync(descriptor)
        raise


def _load_existing(
    executor_id: UUID, state_dir: Path, descriptor: int
) -> ExecutorInitializationResult:
    try:
        private_bytes = _read_private_file(descriptor, PRIVATE_KEY_NAME)
        public_bytes = _read_private_file(descriptor, PUBLIC_KEY_NAME)
        metadata = json.loads(_read_private_file(descriptor, METADATA_NAME).decode("utf-8"))
        if set(metadata) != {
            "executorId",
            "formatVersion",
            "keyAlgorithm",
            "publicKeyFingerprint",
        }:
            raise ValueError
        if (
            metadata["executorId"] != str(executor_id)
            or type(metadata["formatVersion"]) is not int
            or metadata["formatVersion"] != 1
            or metadata["keyAlgorithm"] != "ssh-ed25519"
        ):
            raise ValueError

        private_key = serialization.load_ssh_private_key(private_bytes, password=None)
        public_key = serialization.load_ssh_public_key(public_bytes)
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(
            public_key, Ed25519PublicKey
        ):
            raise ValueError
        expected_public = private_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        actual_public = public_key.public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        if expected_public != actual_public:
            raise ValueError
        public_value = actual_public.decode("ascii")
        fingerprint = _fingerprint(public_value)
        if metadata["publicKeyFingerprint"] != fingerprint:
            raise ValueError
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exception:
        raise ExecutorIdentityInitializationError(
            "Discovery Executor state is incomplete or incompatible."
        ) from exception

    return ExecutorInitializationResult(
        executorId=str(executor_id),
        publicKeyPath=str(state_dir / PUBLIC_KEY_NAME),
        publicKeyFingerprint=fingerprint,
        publicKey=public_value,
    )


def _inspect_identity_descriptor(state_dir: Path, descriptor: int) -> ExecutorInitializationResult:
    files = set(os.listdir(descriptor))
    if not EXPECTED_FILES.issubset(files) or not files.issubset(EXPECTED_FILES | OPTIONAL_FILES):
        raise ExecutorIdentityInitializationError(
            "Discovery Executor state is incomplete or incompatible."
        )
    try:
        metadata = json.loads(_read_private_file(descriptor, METADATA_NAME).decode("utf-8"))
        executor_id = _uuid_v4(metadata["executorId"])
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        ExecutorIdentityInitializationError,
    ) as exception:
        raise ExecutorIdentityInitializationError(
            "Discovery Executor state is incomplete or incompatible."
        ) from exception
    return _load_existing(executor_id, state_dir, descriptor)


def _uuid_v4(value: str) -> UUID:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exception:
        raise ExecutorIdentityInitializationError("executor-id must be a UUIDv4.") from exception
    if parsed.version != 4 or parsed.variant != "specified in RFC 4122":
        raise ExecutorIdentityInitializationError("executor-id must be a UUIDv4.")
    return parsed


def _validate_directory(details: os.stat_result) -> None:
    if not stat.S_ISDIR(details.st_mode):
        raise ExecutorIdentityInitializationError("State directory must be a private directory.")
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
        raise ExecutorIdentityInitializationError(
            "State directory must be owned by the current user with mode 0700."
        )


def _read_private_file(descriptor: int, name: str) -> bytes:
    file_descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    try:
        details = os.fstat(file_descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ExecutorIdentityInitializationError(
                "Discovery Executor state contains an unsafe file."
            )
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o600:
            raise ExecutorIdentityInitializationError(
                "Discovery Executor state files must be owned by the current user with mode 0600."
            )
        with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(file_descriptor)


def _write_exclusive(descriptor: int, name: str, content: bytes) -> None:
    file_descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=descriptor,
    )
    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(file_descriptor)


def _verify_directory_identity(path: Path, expected: os.stat_result) -> None:
    actual = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != (
        expected.st_dev,
        expected.st_ino,
    ):
        raise ExecutorIdentityInitializationError("State directory changed during initialization.")


def _fingerprint(public_key: str) -> str:
    parts = public_key.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise ExecutorIdentityInitializationError(
            "Discovery Executor public key is not valid Ed25519 OpenSSH material."
        )
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as exception:
        raise ExecutorIdentityInitializationError(
            "Discovery Executor public key is not valid Ed25519 OpenSSH material."
        ) from exception
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"
