"""Strict local SFTP configuration and connectivity verification."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

import paramiko

from jaxon_agent.identity import (
    PRIVATE_KEY_NAME,
    IdentityInitializationError,
    InitializationResult,
    _inspect_identity_descriptor,
    _read_private_file,
    _validate_directory,
    _verify_directory_identity,
    _write_exclusive,
)

CONFIG_NAME = "sftp.json"


class SftpConfigurationError(RuntimeError):
    """A safe local SFTP configuration failure."""


class SftpVerificationError(RuntimeError):
    """A safe SFTP verification failure."""


@dataclass(frozen=True)
class SftpConfigurationResult:
    agentId: str
    changed: bool
    configPath: str
    host: str
    hostKeyFingerprint: str
    port: int
    username: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class SftpVerificationResult:
    agentId: str
    host: str
    hostKeyFingerprint: str
    port: int
    publicKeyFingerprint: str
    status: str
    username: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class LoadedSftpState:
    identity: InitializationResult
    config: dict[str, object]
    privateKey: paramiko.Ed25519Key
    hostKey: paramiko.PKey


def configure_sftp(
    state_dir_value: str, host: str, port: int, username: str, host_key_value: str
) -> SftpConfigurationResult:
    host = _plain_value(host, "host")
    username = _plain_value(username, "username")
    if type(port) is not int or not 1 <= port <= 65535:
        raise SftpConfigurationError("port must be an integer between 1 and 65535.")
    host_key, parsed_host_key = _parse_host_key(host_key_value)
    fingerprint = _fingerprint(parsed_host_key)
    config = {
        "formatVersion": 1,
        "host": host,
        "hostKey": host_key,
        "hostKeyFingerprint": fingerprint,
        "port": port,
        "username": username,
    }
    content = (json.dumps(config, separators=(",", ":"), sort_keys=True) + "\n").encode()
    state_dir = Path(state_dir_value).expanduser().absolute()
    descriptor, details = _open_state(state_dir)
    changed = False
    try:
        identity = _inspect_identity_descriptor(state_dir, descriptor)
        try:
            existing = _read_private_file(descriptor, CONFIG_NAME)
        except FileNotFoundError:
            _write_exclusive(descriptor, CONFIG_NAME, content)
            os.fsync(descriptor)
            changed = True
        else:
            if existing != content:
                raise SftpConfigurationError(
                    "SFTP configuration already exists with different values."
                )
        _verify_directory_identity(state_dir, details)
    except IdentityInitializationError as exception:
        raise SftpConfigurationError(str(exception)) from exception
    except OSError as exception:
        raise SftpConfigurationError(
            "SFTP configuration could not be stored safely."
        ) from exception
    finally:
        os.close(descriptor)
    return SftpConfigurationResult(
        identity.agentId,
        changed,
        str(state_dir / CONFIG_NAME),
        host,
        fingerprint,
        port,
        username,
    )


def verify_sftp(
    state_dir_value: str,
    client_factory=paramiko.SSHClient,
) -> SftpVerificationResult:
    state = load_sftp_state(state_dir_value)
    with open_sftp_session(state, client_factory):
        pass
    return SftpVerificationResult(
        state.identity.agentId,
        state.config["host"],
        state.config["hostKeyFingerprint"],
        state.config["port"],
        state.identity.publicKeyFingerprint,
        "verified",
        state.config["username"],
    )


def load_sftp_state(state_dir_value: str) -> LoadedSftpState:
    state_dir = Path(state_dir_value).expanduser().absolute()
    descriptor, details = _open_state(state_dir)
    try:
        identity = _inspect_identity_descriptor(state_dir, descriptor)
        config = _load_config(_read_private_file(descriptor, CONFIG_NAME))
        private_bytes = _read_private_file(descriptor, PRIVATE_KEY_NAME)
        _verify_directory_identity(state_dir, details)
    except (IdentityInitializationError, FileNotFoundError) as exception:
        raise SftpVerificationError(
            "SFTP configuration or Agent identity is not valid."
        ) from exception
    finally:
        os.close(descriptor)

    try:
        private_key = paramiko.Ed25519Key.from_private_key(
            io.StringIO(private_bytes.decode("ascii"))
        )
        host_key, parsed_host_key = _parse_host_key(config["hostKey"])
        if _fingerprint(parsed_host_key) != config["hostKeyFingerprint"]:
            raise ValueError
    except (
        OSError,
        UnicodeError,
        ValueError,
        SftpConfigurationError,
        paramiko.SSHException,
    ) as exception:
        raise SftpVerificationError(
            "SFTP configuration or Agent identity is not valid."
        ) from exception

    return LoadedSftpState(identity, config, private_key, parsed_host_key)


@contextmanager
def open_sftp_session(state: LoadedSftpState, client_factory=paramiko.SSHClient):
    client = client_factory()
    sftp_client = None
    config = state.config
    lookup_name = config["host"] if config["port"] == 22 else f"[{config['host']}]:{config['port']}"
    try:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add(lookup_name, state.hostKey.get_name(), state.hostKey)
        client.connect(
            hostname=config["host"],
            port=config["port"],
            username=config["username"],
            pkey=state.privateKey,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            channel_timeout=60,
        )
        sftp_client = client.open_sftp()
        sftp_client.get_channel().settimeout(60)
        yield sftp_client
    except (TimeoutError, OSError, paramiko.SSHException) as exception:
        raise SftpVerificationError(
            "SFTP connection could not be verified securely."
        ) from exception
    finally:
        if sftp_client is not None:
            sftp_client.close()
        client.close()


def _open_state(path: Path) -> tuple[int, os.stat_result]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise SftpConfigurationError("SFTP configuration requires POSIX no-follow support.")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        details = os.fstat(descriptor)
        _validate_directory(details)
        return descriptor, details
    except (OSError, IdentityInitializationError) as exception:
        raise SftpConfigurationError("State directory is not safe.") from exception


def _load_config(content: bytes) -> dict:
    try:
        value = json.loads(content)
        if set(value) != {
            "formatVersion",
            "host",
            "hostKey",
            "hostKeyFingerprint",
            "port",
            "username",
        }:
            raise ValueError
        if type(value["formatVersion"]) is not int or value["formatVersion"] != 1:
            raise ValueError
        _plain_value(value["host"], "host")
        _plain_value(value["username"], "username")
        if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
            raise ValueError
        canonical, key = _parse_host_key(value["hostKey"])
        if canonical != value["hostKey"] or _fingerprint(key) != value["hostKeyFingerprint"]:
            raise ValueError
        return value
    except (UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exception:
        raise SftpVerificationError(
            "SFTP configuration or Agent identity is not valid."
        ) from exception


def _parse_host_key(value: str) -> tuple[str, paramiko.PKey]:
    try:
        parts = value.strip().split()
        if len(parts) != 2 or parts[0] != "ssh-ed25519":
            raise ValueError
        blob = base64.b64decode(parts[1], validate=True)
        key = paramiko.PKey.from_type_string("ssh-ed25519", blob)
        canonical = f"ssh-ed25519 {key.get_base64()}"
        return canonical, key
    except (AttributeError, ValueError, paramiko.SSHException) as exception:
        raise SftpConfigurationError(
            "host-key must be valid Ed25519 OpenSSH material."
        ) from exception


def _fingerprint(key: paramiko.PKey) -> str:
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def _plain_value(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise SftpConfigurationError(f"{name} is not valid.")
    return value
