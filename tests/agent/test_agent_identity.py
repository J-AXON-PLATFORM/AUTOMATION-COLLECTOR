import base64
import hashlib
import json
import os
import stat
from uuid import uuid1, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jaxon_agent.identity import IdentityInitializationError, initialize_identity


def test_generates_private_ed25519_identity_and_safe_public_output(tmp_path) -> None:
    state_dir = tmp_path / "agent-state"
    agent_id = uuid4()

    result = initialize_identity(str(agent_id), str(state_dir))

    private_path = state_dir / "id_ed25519"
    public_path = state_dir / "id_ed25519.pub"
    metadata_path = state_dir / "agent.json"
    private_key = serialization.load_ssh_private_key(private_path.read_bytes(), password=None)
    assert isinstance(private_key, Ed25519PrivateKey)
    assert public_path.read_text().strip() == result.publicKey
    assert result.publicKey.startswith("ssh-ed25519 ")
    public_blob = base64.b64decode(result.publicKey.split()[1], validate=True)
    expected_digest = base64.b64encode(hashlib.sha256(public_blob).digest()).decode().rstrip("=")
    assert result.publicKeyFingerprint == f"SHA256:{expected_digest}"
    assert result.publicKeyPath == str(public_path)
    assert json.loads(metadata_path.read_text())["agentId"] == str(agent_id)
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    for path in (private_path, public_path, metadata_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    output = result.to_json()
    assert "OPENSSH PRIVATE KEY" not in output
    assert private_path.read_text().strip() not in output


def test_initialization_is_idempotent_without_rewriting_keys(tmp_path) -> None:
    state_dir = tmp_path / "agent-state"
    agent_id = str(uuid4())
    first = initialize_identity(agent_id, str(state_dir))
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in state_dir.iterdir()
    }

    second = initialize_identity(agent_id, str(state_dir))

    after = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in state_dir.iterdir()
    }
    assert second == first
    assert after == before


def test_rejects_different_agent_without_modifying_state(tmp_path) -> None:
    state_dir = tmp_path / "agent-state"
    initialize_identity(str(uuid4()), str(state_dir))
    before = {path.name: path.read_bytes() for path in state_dir.iterdir()}

    with pytest.raises(IdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(str(uuid4()), str(state_dir))

    assert {path.name: path.read_bytes() for path in state_dir.iterdir()} == before


@pytest.mark.parametrize("missing", ["id_ed25519", "id_ed25519.pub", "agent.json"])
def test_rejects_partial_state(tmp_path, missing) -> None:
    state_dir = tmp_path / "agent-state"
    initialize_identity(str(uuid4()), str(state_dir))
    (state_dir / missing).unlink()

    with pytest.raises(IdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(str(uuid4()), str(state_dir))


def test_rejects_corrupt_or_overpermissive_state(tmp_path) -> None:
    state_dir = tmp_path / "agent-state"
    agent_id = str(uuid4())
    initialize_identity(agent_id, str(state_dir))
    (state_dir / "id_ed25519.pub").write_text("ssh-rsa invalid\n")

    with pytest.raises(IdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(agent_id, str(state_dir))


def test_rejects_symlinked_state_file(tmp_path) -> None:
    state_dir = tmp_path / "agent-state"
    agent_id = str(uuid4())
    initialize_identity(agent_id, str(state_dir))
    public_path = state_dir / "id_ed25519.pub"
    public_copy = tmp_path / "public-copy"
    public_copy.write_bytes(public_path.read_bytes())
    os.chmod(public_copy, 0o600)
    public_path.unlink()
    public_path.symlink_to(public_copy)

    with pytest.raises(IdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(agent_id, str(state_dir))


def test_enforces_modes_under_restrictive_umask(tmp_path) -> None:
    state_dir = tmp_path / "agent-state"
    previous_umask = os.umask(0o777)
    try:
        initialize_identity(str(uuid4()), str(state_dir))
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in state_dir.iterdir())


@pytest.mark.parametrize("agent_id", [str(uuid1()), "not-a-uuid"])
def test_rejects_non_v4_agent_ids(tmp_path, agent_id) -> None:
    with pytest.raises(IdentityInitializationError, match="UUIDv4"):
        initialize_identity(agent_id, str(tmp_path / "agent-state"))


def test_rejects_boolean_metadata_version(tmp_path) -> None:
    state_dir = tmp_path / "agent-state"
    agent_id = str(uuid4())
    initialize_identity(agent_id, str(state_dir))
    metadata_path = state_dir / "agent.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["formatVersion"] = True
    metadata_path.write_text(json.dumps(metadata))
    os.chmod(metadata_path, 0o600)

    with pytest.raises(IdentityInitializationError, match="incomplete or incompatible"):
        initialize_identity(agent_id, str(state_dir))

    os.chmod(state_dir / "id_ed25519.pub", 0o644)
    with pytest.raises(IdentityInitializationError, match="mode 0600"):
        initialize_identity(agent_id, str(state_dir))


def test_rejects_symlink_and_unsafe_state_directory(tmp_path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)

    with pytest.raises(IdentityInitializationError, match="private directory"):
        initialize_identity(str(uuid4()), str(linked_dir))

    os.chmod(real_dir, 0o755)
    with pytest.raises(IdentityInitializationError, match="mode 0700"):
        initialize_identity(str(uuid4()), str(real_dir))
