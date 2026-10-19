"""Local Agent identity initialization without network access."""

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

PRIVATE_KEY_NAME = "id_ed25519"
PUBLIC_KEY_NAME = "id_ed25519.pub"
METADATA_NAME = "agent.json"
EXPECTED_FILES = {PRIVATE_KEY_NAME, PUBLIC_KEY_NAME, METADATA_NAME}
OPTIONAL_FILES = {"sftp.json", "run.lock", "task-ledger"}


class IdentityInitializationError(RuntimeError):
    """A safe, operator-facing identity initialization failure."""


@dataclass(frozen=True)
class InitializationResult:
    agentId: str
    publicKeyPath: str
    publicKeyFingerprint: str
    publicKey: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


def initialize_identity(agent_id_value: str, state_dir_value: str) -> InitializationResult:
    agent_id = _uuid_v4(agent_id_value)
    if os.name != "posix":
        raise IdentityInitializationError("Agent identity initialization requires a POSIX system.")
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
            raise IdentityInitializationError("State directory must be a private directory.")

        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_descriptor = os.open(state_dir, flags)
        try:
            directory_details = os.fstat(directory_descriptor)
            _validate_directory(directory_details)
            files = set(os.listdir(directory_descriptor))
            if files:
                if not EXPECTED_FILES.issubset(files) or not files.issubset(
                    EXPECTED_FILES | OPTIONAL_FILES
                ):
                    raise IdentityInitializationError("Agent state is incomplete or incompatible.")
                result = _load_existing(agent_id, state_dir, directory_descriptor)
            else:
                result = _create_identity(agent_id, state_dir, directory_descriptor)
            _verify_directory_identity(state_dir, directory_details)
            return result
        finally:
            os.close(directory_descriptor)
    except IdentityInitializationError:
        raise
    except (OSError, ValueError) as exception:
        if created:
            with suppress(OSError):
                state_dir.rmdir()
        raise IdentityInitializationError(
            "Agent identity could not be initialized safely."
        ) from exception


def inspect_identity(state_dir_value: str) -> InitializationResult:
    """Load and validate a complete existing identity without changing it."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise IdentityInitializationError(
            "Agent identity inspection requires POSIX no-follow support."
        )
    state_dir = Path(state_dir_value).expanduser().absolute()
    try:
        details = state_dir.lstat()
        if not stat.S_ISDIR(details.st_mode):
            raise IdentityInitializationError("State directory must be a private directory.")
        descriptor = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return _inspect_identity_descriptor(state_dir, descriptor)
        finally:
            os.close(descriptor)
    except IdentityInitializationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exception:
        raise IdentityInitializationError(
            "Agent state is incomplete or incompatible."
        ) from exception


def _inspect_identity_descriptor(state_dir: Path, descriptor: int) -> InitializationResult:
    try:
        directory_details = os.fstat(descriptor)
        _validate_directory(directory_details)
        files = set(os.listdir(descriptor))
        if not EXPECTED_FILES.issubset(files) or not files.issubset(
            EXPECTED_FILES | OPTIONAL_FILES
        ):
            raise IdentityInitializationError("Agent state is incomplete or incompatible.")
        metadata = json.loads(_read_private_file(descriptor, METADATA_NAME))
        agent_id = _uuid_v4(metadata["agentId"])
        result = _load_existing(agent_id, state_dir, descriptor)
        _verify_directory_identity(state_dir, directory_details)
        return result
    except IdentityInitializationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exception:
        raise IdentityInitializationError(
            "Agent state is incomplete or incompatible."
        ) from exception


def _create_identity(
    agent_id: UUID, state_dir: Path, directory_descriptor: int
) -> InitializationResult:
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
    fingerprint = _fingerprint(public_key)
    metadata = {
        "agentId": str(agent_id),
        "formatVersion": 1,
        "keyAlgorithm": "ssh-ed25519",
        "publicKeyFingerprint": fingerprint,
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
            _write_exclusive(directory_descriptor, name, content)
            created_files.append(name)
        os.fsync(directory_descriptor)
        return _load_existing(agent_id, state_dir, directory_descriptor)
    except Exception:
        for name in reversed(created_files):
            with suppress(OSError):
                os.unlink(name, dir_fd=directory_descriptor)
        with suppress(OSError):
            os.fsync(directory_descriptor)
        raise


def _load_existing(
    agent_id: UUID, state_dir: Path, directory_descriptor: int
) -> InitializationResult:
    try:
        private_bytes = _read_private_file(directory_descriptor, PRIVATE_KEY_NAME)
        public_bytes = _read_private_file(directory_descriptor, PUBLIC_KEY_NAME)
        metadata_bytes = _read_private_file(directory_descriptor, METADATA_NAME)
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        if set(metadata) != {
            "agentId",
            "formatVersion",
            "keyAlgorithm",
            "publicKeyFingerprint",
        }:
            raise ValueError
        if (
            metadata["agentId"] != str(agent_id)
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
        raise IdentityInitializationError(
            "Agent state is incomplete or incompatible."
        ) from exception

    return InitializationResult(
        agentId=str(agent_id),
        publicKeyPath=str(state_dir / PUBLIC_KEY_NAME),
        publicKeyFingerprint=fingerprint,
        publicKey=public_value,
    )


def _uuid_v4(value: str) -> UUID:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exception:
        raise IdentityInitializationError("agent-id must be a UUIDv4.") from exception
    if parsed.version != 4 or parsed.variant != "specified in RFC 4122":
        raise IdentityInitializationError("agent-id must be a UUIDv4.")
    return parsed


def _validate_directory(details: os.stat_result) -> None:
    if not stat.S_ISDIR(details.st_mode):
        raise IdentityInitializationError("State directory must be a private directory.")
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
        raise IdentityInitializationError(
            "State directory must be owned by the current user with mode 0700."
        )


def _read_private_file(directory_descriptor: int, name: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise IdentityInitializationError("Agent state contains an unsafe file.")
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o600:
            raise IdentityInitializationError(
                "Agent state files must be owned by the current user with mode 0600."
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _write_exclusive(directory_descriptor: int, name: str, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _verify_directory_identity(path: Path, expected: os.stat_result) -> None:
    actual = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != (
        expected.st_dev,
        expected.st_ino,
    ):
        raise IdentityInitializationError("State directory changed during initialization.")


def _fingerprint(public_key: str) -> str:
    parts = public_key.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise IdentityInitializationError("Agent public key is not valid Ed25519 OpenSSH material.")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as exception:
        raise IdentityInitializationError(
            "Agent public key is not valid Ed25519 OpenSSH material."
        ) from exception
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"
