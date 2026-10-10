from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from jaxon_agent.contracts import (
    AgentContractValidator,
    ContractError,
    ContractIssue,
    ContractSizeError,
    ContractValidationError,
    UnsupportedContractVersion,
    UnsupportedMessageType,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts" / "agent"
EXAMPLES = CONTRACT_ROOT / "1.0" / "examples"


@pytest.fixture(scope="module")
def validator() -> AgentContractValidator:
    return AgentContractValidator(CONTRACT_ROOT)


@pytest.mark.parametrize(
    "filename",
    ["snapshot.json", "result-succeeded.json", "result-failed.json", "result-rejected.json"],
)
def test_agent_emitted_fixtures_are_valid(validator: AgentContractValidator, filename: str) -> None:
    document = (EXAMPLES / "valid" / filename).read_bytes()
    assert validator.validate_before_emit(document)["contractVersion"] == "1.0"


@pytest.mark.parametrize(
    "filename",
    [
        "task-collect-snapshot.json",
        "task-collect-network-state.json",
        "task-collect-software-inventory.json",
    ],
)
def test_agent_received_fixtures_are_valid(
    validator: AgentContractValidator, filename: str
) -> None:
    document = (EXAMPLES / "valid" / filename).read_bytes()
    assert validator.validate_after_receive(document)["contractVersion"] == "1.0"


@pytest.mark.parametrize(
    "filename,direction",
    [
        ("snapshot-forbidden-field.json", "emit"),
        ("snapshot-invalid-uuid.json", "emit"),
        ("snapshot-non-utc-time.json", "emit"),
        ("snapshot-wrong-message-type.json", "emit"),
        ("task-arbitrary-payload.json", "receive"),
        ("task-unknown-type.json", "receive"),
        ("result-expired-status.json", "emit"),
        ("result-failed-without-error.json", "emit"),
        ("result-succeeded-with-error.json", "emit"),
    ],
)
def test_invalid_fixtures_are_rejected(
    validator: AgentContractValidator, filename: str, direction: str
) -> None:
    document = (EXAMPLES / "invalid" / filename).read_bytes()
    validate = (
        validator.validate_before_emit if direction == "emit" else validator.validate_after_receive
    )
    with pytest.raises((ContractValidationError, UnsupportedMessageType)):
        validate(document)


def test_unknown_version_is_rejected(validator: AgentContractValidator) -> None:
    document = (EXAMPLES / "invalid" / "snapshot-unknown-version.json").read_bytes()
    with pytest.raises(UnsupportedContractVersion):
        validator.validate_before_emit(document)


def test_direction_is_enforced(validator: AgentContractValidator) -> None:
    task = (EXAMPLES / "valid" / "task-collect-snapshot.json").read_bytes()
    snapshot = (EXAMPLES / "valid" / "snapshot.json").read_bytes()
    with pytest.raises(UnsupportedMessageType):
        validator.validate_before_emit(task)
    with pytest.raises(UnsupportedMessageType):
        validator.validate_after_receive(snapshot)


def test_size_is_checked_before_json_parse(validator: AgentContractValidator) -> None:
    with pytest.raises(ContractSizeError):
        validator.validate_after_receive(b"{" + b"x" * (5 * 1024 * 1024))


def test_errors_do_not_expose_payload(validator: AgentContractValidator) -> None:
    secret = "never-log-this-value"
    document = json.dumps(
        {
            "contractVersion": "1.0",
            "messageType": "AGENT_TASK",
            "messageId": "e527ac83-4c62-42d0-ae3b-a5a48312a715",
            "agentId": "b74f39ce-e229-4a0f-9da3-42e28f96377f",
            "createdAt": "2026-10-09T10:20:00Z",
            "taskId": "3405710d-52db-44a2-825a-0da389ccbc7f",
            "taskType": "COLLECT_SNAPSHOT",
            "expiresAt": "2026-10-09T10:35:00Z",
            "payload": {"command": secret},
        }
    ).encode()
    with pytest.raises(ContractValidationError) as captured:
        validator.validate_after_receive(document)
    assert secret not in str(captured.value)
    assert all(isinstance(issue, ContractIssue) for issue in captured.value.issues)


def test_remote_and_traversal_references_are_rejected(tmp_path: Path) -> None:
    for reference in ("https://example.com/schema.json", "../secret.schema.json"):
        copied = tmp_path / reference.replace("/", "_").replace(":", "_")
        shutil_root = copied / "1.0"
        shutil.copytree(CONTRACT_ROOT / "1.0", shutil_root)
        schema_path = shutil_root / "snapshot.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["allOf"][0]["$ref"] = reference
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        with pytest.raises(ContractError):
            AgentContractValidator(copied)
