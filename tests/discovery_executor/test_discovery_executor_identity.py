import base64
import hashlib
import json
import os
import stat
from uuid import uuid1, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jaxon_discovery_executor.identity import (
    ExecutorIdentityInitializationError,
    initialize_identity,
)
from jaxon_discovery_executor.ledger import DiscoveryLedger, DiscoveryRunLock


def test_generates_separate_private_identity_and_safe_output(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    executor_id = uuid4()

    result = initialize_identity(str(executor_id), str(state_dir))

    private_path = state_dir / "executor_ed25519"
    public_path = state_dir / "executor_ed25519.pub"
    metadata_path = state_dir / "executor.json"
    assert isinstance(
        serialization.load_ssh_private_key(private_path.read_bytes(), password=None),
        Ed25519PrivateKey,
    )
    assert public_path.read_text().strip() == result.publicKey
    public_blob = base64.b64decode(result.publicKey.split()[1], validate=True)
    digest = base64.b64encode(hashlib.sha256(public_blob).digest()).decode().rstrip("=")
    assert result.publicKeyFingerprint == f"SHA256:{digest}"
    assert json.loads(metadata_path.read_text()) == {
        "executorId": str(executor_id),
        "formatVersion": 1,
        "keyAlgorithm": "ssh-ed25519",
        "publicKeyFingerprint": result.publicKeyFingerprint,
    }
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in state_dir.iterdir())
    assert "OPENSSH PRIVATE KEY" not in result.to_json()


def test_is_idempotent_without_rewriting_files(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    executor_id = str(uuid4())
    first = initialize_identity(executor_id, str(state_dir))
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in state_dir.iterdir()
    }

    second = initialize_identity(executor_id, str(state_dir))

    assert second == first
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in state_dir.iterdir()
    } == before


def test_accepts_only_the_optional_sftp_configuration(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    executor_id = str(uuid4())
    identity = initialize_identity(executor_id, str(state_dir))
    config = state_dir / "sftp.json"
    config.write_text("{}")
    os.chmod(config, 0o600)

    assert initialize_identity(executor_id, str(state_dir)) == identity

    unexpected = state_dir / "unexpected"
    unexpected.write_text("unexpected")
    os.chmod(unexpected, 0o600)
    with pytest.raises(ExecutorIdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(executor_id, str(state_dir))


def test_accepts_private_runner_state_only(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    executor_id = str(uuid4())
    identity = initialize_identity(executor_id, str(state_dir))
    with DiscoveryRunLock(str(state_dir)), DiscoveryLedger(str(state_dir)):
        pass

    assert initialize_identity(executor_id, str(state_dir)) == identity
    assert stat.S_IMODE((state_dir / "run.lock").stat().st_mode) == 0o600
    assert stat.S_IMODE((state_dir / "discovery-ledger").stat().st_mode) == 0o700


@pytest.mark.parametrize("executor_id", [str(uuid1()), "not-a-uuid"])
def test_rejects_non_v4_ids_without_creating_state(tmp_path, executor_id) -> None:
    state_dir = tmp_path / "executor-state"
    with pytest.raises(ExecutorIdentityInitializationError, match="UUIDv4"):
        initialize_identity(executor_id, str(state_dir))
    assert not state_dir.exists()


def test_rejects_different_id_without_modifying_state(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    initialize_identity(str(uuid4()), str(state_dir))
    before = {path.name: path.read_bytes() for path in state_dir.iterdir()}

    with pytest.raises(ExecutorIdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(str(uuid4()), str(state_dir))

    assert {path.name: path.read_bytes() for path in state_dir.iterdir()} == before


@pytest.mark.parametrize("missing", ["executor_ed25519", "executor_ed25519.pub", "executor.json"])
def test_rejects_partial_state(tmp_path, missing) -> None:
    state_dir = tmp_path / "executor-state"
    executor_id = str(uuid4())
    initialize_identity(executor_id, str(state_dir))
    (state_dir / missing).unlink()

    with pytest.raises(ExecutorIdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(executor_id, str(state_dir))


def test_rejects_unexpected_file_and_agent_state(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    state_dir.mkdir(mode=0o700)
    unexpected = state_dir / "unexpected"
    unexpected.write_text("unexpected")
    os.chmod(unexpected, 0o600)

    with pytest.raises(ExecutorIdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(str(uuid4()), str(state_dir))

    agent_state = tmp_path / "agent-state"
    agent_state.mkdir(mode=0o700)
    agent_metadata = agent_state / "agent.json"
    agent_metadata.write_text("{}")
    os.chmod(agent_metadata, 0o600)
    with pytest.raises(ExecutorIdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(str(uuid4()), str(agent_state))


def test_rejects_symlink_and_insecure_modes(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    executor_id = str(uuid4())
    initialize_identity(executor_id, str(state_dir))
    public_path = state_dir / "executor_ed25519.pub"
    public_copy = tmp_path / "public-copy"
    public_copy.write_bytes(public_path.read_bytes())
    os.chmod(public_copy, 0o600)
    public_path.unlink()
    public_path.symlink_to(public_copy)

    with pytest.raises(ExecutorIdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(executor_id, str(state_dir))

    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(state_dir, target_is_directory=True)
    with pytest.raises(ExecutorIdentityInitializationError, match="private directory"):
        initialize_identity(executor_id, str(linked_dir))

    public_path.unlink()
    public_path.write_bytes(public_copy.read_bytes())
    os.chmod(public_path, 0o644)
    with pytest.raises(ExecutorIdentityInitializationError, match="mode 0600"):
        initialize_identity(executor_id, str(state_dir))

    os.chmod(public_path, 0o600)
    os.chmod(state_dir, 0o755)
    with pytest.raises(ExecutorIdentityInitializationError, match="mode 0700"):
        initialize_identity(executor_id, str(state_dir))


def test_rejects_inconsistent_private_and_public_keys(tmp_path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    executor_id = str(uuid4())
    initialize_identity(executor_id, str(first_dir))
    initialize_identity(str(uuid4()), str(second_dir))
    (first_dir / "executor_ed25519.pub").write_bytes(
        (second_dir / "executor_ed25519.pub").read_bytes()
    )

    with pytest.raises(ExecutorIdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(executor_id, str(first_dir))


def test_enforces_modes_under_restrictive_umask(tmp_path) -> None:
    state_dir = tmp_path / "executor-state"
    previous_umask = os.umask(0o777)
    try:
        initialize_identity(str(uuid4()), str(state_dir))
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in state_dir.iterdir())
