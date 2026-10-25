from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from jaxon_discovery_executor.contracts import (
    DiscoveryContractError,
    DiscoveryContractSizeError,
    DiscoveryContractValidationError,
    DiscoveryJobContractValidator,
    UnsupportedDiscoveryContractVersion,
    UnsupportedDiscoveryMessageType,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts" / "discovery"
EXAMPLES = CONTRACT_ROOT / "1.0" / "examples"


@pytest.fixture(scope="module")
def validator() -> DiscoveryJobContractValidator:
    return DiscoveryJobContractValidator(CONTRACT_ROOT)


def test_valid_job_fixture_is_accepted(validator: DiscoveryJobContractValidator) -> None:
    document = (EXAMPLES / "valid" / "job-basic.json").read_bytes()
    assert validator.validate_after_receive(document)["schemaVersion"] == "1.0"


@pytest.mark.parametrize(
    "filename",
    [
        "job-extra-property.json",
        "job-invalid-expiry.json",
        "job-invalid-uuid.json",
        "job-non-utc-time.json",
        "job-noncanonical-cidr.json",
    ],
)
def test_invalid_job_fixtures_are_rejected(
    validator: DiscoveryJobContractValidator, filename: str
) -> None:
    with pytest.raises(DiscoveryContractValidationError):
        validator.validate_after_receive((EXAMPLES / "invalid" / filename).read_bytes())


def test_unknown_version_is_rejected(validator: DiscoveryJobContractValidator) -> None:
    with pytest.raises(UnsupportedDiscoveryContractVersion):
        validator.validate_after_receive(
            (EXAMPLES / "invalid" / "job-unknown-version.json").read_bytes()
        )


def test_wrong_message_type_is_rejected(validator: DiscoveryJobContractValidator) -> None:
    with pytest.raises(UnsupportedDiscoveryMessageType):
        validator.validate_after_receive(
            (EXAMPLES / "invalid" / "job-wrong-message-type.json").read_bytes()
        )


def test_requires_bytes_and_checks_size_first(validator: DiscoveryJobContractValidator) -> None:
    with pytest.raises(TypeError):
        validator.validate_after_receive("{}")  # type: ignore[arg-type]
    with pytest.raises(DiscoveryContractSizeError):
        validator.validate_after_receive(b"{" + b"x" * (64 * 1024))


def test_errors_do_not_expose_payload(validator: DiscoveryJobContractValidator) -> None:
    secret = "never-log-this-value"
    document = json.dumps(
        {"schemaVersion": "1.0", "messageType": "DISCOVERY_JOB", "secret": secret}
    ).encode()
    with pytest.raises(DiscoveryContractValidationError) as captured:
        validator.validate_after_receive(document)
    assert secret not in str(captured.value)


def test_remote_and_traversal_references_are_rejected(tmp_path: Path) -> None:
    for reference in ("https://example.com/schema.json", "../secret.schema.json"):
        copied = tmp_path / reference.replace("/", "_").replace(":", "_")
        bundle = copied / "1.0"
        shutil.copytree(CONTRACT_ROOT / "1.0", bundle)
        schema_path = bundle / "job.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["properties"]["jobId"]["$ref"] = reference
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        with pytest.raises(DiscoveryContractError):
            DiscoveryJobContractValidator(copied)
