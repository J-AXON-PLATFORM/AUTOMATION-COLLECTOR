from __future__ import annotations

import json
from pathlib import Path

import pytest

from jaxon_discovery_executor.contracts import (
    MAX_RESULT_BYTES,
    DiscoveryContractEncodingError,
    DiscoveryContractSizeError,
    DiscoveryContractValidationError,
    DiscoveryResultContractValidator,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts" / "discovery"
EXAMPLES = CONTRACT_ROOT / "1.0" / "examples"
SCOPE = "192.0.2.0/24"


@pytest.fixture(scope="module")
def validator() -> DiscoveryResultContractValidator:
    return DiscoveryResultContractValidator(CONTRACT_ROOT)


@pytest.mark.parametrize(
    ("filename", "scope"),
    [
        ("result-basic-failed.json", SCOPE),
        ("result-basic-scope-too-large.json", "192.0.0.0/16"),
        ("result-basic-succeeded.json", SCOPE),
    ],
)
def test_valid_result_fixtures_are_accepted(validator, filename, scope) -> None:
    document = (EXAMPLES / "valid" / filename).read_bytes()
    assert validator.validate_before_emit(document, scope)["messageType"] == "DISCOVERY_RESULT"


@pytest.mark.parametrize(
    "filename",
    [
        "result-extra-property.json",
        "result-failed-with-observation.json",
        "result-success-with-failure.json",
    ],
)
def test_invalid_result_fixtures_are_rejected(validator, filename) -> None:
    with pytest.raises(DiscoveryContractValidationError):
        validator.validate_before_emit((EXAMPLES / "invalid" / filename).read_bytes(), SCOPE)


def test_result_semantics_enforce_time_counts_scope_and_order(validator) -> None:
    source = json.loads((EXAMPLES / "valid" / "result-basic-succeeded.json").read_bytes())
    mutations = [
        (lambda value: value.update(completedAt="2026-10-25T12:09:59Z")),
        (lambda value: value["summary"].update(targetsConsidered=1)),
        (lambda value: value["summary"].update(observationsFound=0)),
        (lambda value: value["summary"].update(targetsScanned=255)),
        (lambda value: value["observations"][0].update(ipAddress="198.51.100.10")),
        (lambda value: value["observations"][0].update(openTcpPorts=[443, 22])),
        (lambda value: value["observations"][0].update(openTcpPorts=[21])),
    ]
    for mutate in mutations:
        value = json.loads(json.dumps(source))
        mutate(value)
        with pytest.raises(DiscoveryContractValidationError):
            validator.validate_before_emit(json.dumps(value).encode(), SCOPE)


def test_result_rejects_duplicate_members_and_checks_size_first(validator) -> None:
    with pytest.raises(DiscoveryContractEncodingError):
        validator.validate_before_emit(b'{"schemaVersion":"1.0","schemaVersion":"1.0"}', SCOPE)
    with pytest.raises(DiscoveryContractSizeError):
        validator.validate_before_emit(b"{" + b"x" * MAX_RESULT_BYTES, SCOPE)
