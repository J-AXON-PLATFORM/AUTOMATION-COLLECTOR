"""Offline validation for J-AXON Discovery Job messages."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import RFC_4122, UUID

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

SCHEMA_BASE = "https://schemas.j-axon.invalid/discovery/1.0/"
SUPPORTED_VERSION = "1.0"
MAX_JOB_BYTES = 64 * 1024


@dataclass(frozen=True)
class ContractIssue:
    path: str
    keyword: str


class DiscoveryContractError(Exception):
    """Base class for safe errors that never includes message payloads."""


class DiscoveryContractSizeError(DiscoveryContractError):
    pass


class DiscoveryContractEncodingError(DiscoveryContractError):
    pass


class UnsupportedDiscoveryContractVersion(DiscoveryContractError):
    pass


class UnsupportedDiscoveryMessageType(DiscoveryContractError):
    pass


class DiscoveryContractValidationError(DiscoveryContractError):
    def __init__(self, issues: tuple[ContractIssue, ...]) -> None:
        self.issues = issues
        super().__init__(f"Discovery Job failed contract validation ({len(issues)} issue(s))")


def _is_uuid_v4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError, AttributeError:
        return False
    return parsed.version == 4 and parsed.variant == RFC_4122 and str(parsed) == value


def _is_utc_datetime(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _is_canonical_cidr(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    return str(network) == value


def _format_checker() -> FormatChecker:
    checker = FormatChecker()
    checker.checks("uuid")(_is_uuid_v4)
    checker.checks("date-time")(_is_utc_datetime)
    checker.checks("cidr")(_is_canonical_cidr)
    return checker


def _default_contract_root() -> Path:
    packaged = files("jaxon_discovery_executor").joinpath("contracts", "discovery")
    if packaged.is_dir():
        return Path(str(packaged))
    return Path(__file__).resolve().parents[2] / "contracts" / "discovery"


class DiscoveryJobContractValidator:
    def __init__(self, contract_root: Path | None = None) -> None:
        root = (contract_root or _default_contract_root()).resolve() / SUPPORTED_VERSION
        schemas: dict[str, dict[str, Any]] = {}
        for filename in ("common.schema.json", "job.schema.json"):
            schema = json.loads((root / filename).read_text(encoding="utf-8"))
            schema_id = schema.get("$id")
            if schema_id != SCHEMA_BASE + filename:
                raise DiscoveryContractError("Discovery schema identity is not approved")
            self._reject_unsafe_references(schema)
            schemas[schema_id] = schema
        registry = Registry(retrieve=self._reject_remote_resource).with_resources(
            (schema_id, Resource.from_contents(schema)) for schema_id, schema in schemas.items()
        )
        self._validator = Draft202012Validator(
            schemas[SCHEMA_BASE + "job.schema.json"],
            registry=registry,
            format_checker=_format_checker(),
        )

    def validate_after_receive(self, document: bytes) -> dict[str, Any]:
        if not isinstance(document, bytes):
            raise TypeError("Discovery contract validation requires bytes")
        if len(document) > MAX_JOB_BYTES:
            raise DiscoveryContractSizeError("Discovery Job exceeds the maximum supported size")
        try:
            instance = json.loads(document.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DiscoveryContractEncodingError("Discovery Job is not valid UTF-8 JSON") from error
        if not isinstance(instance, dict):
            raise DiscoveryContractValidationError((ContractIssue(path="/", keyword="type"),))
        if instance.get("schemaVersion") != SUPPORTED_VERSION:
            raise UnsupportedDiscoveryContractVersion("Discovery contract version is not supported")
        if instance.get("messageType") != "DISCOVERY_JOB":
            raise UnsupportedDiscoveryMessageType(
                "Discovery message type is not allowed at this boundary"
            )

        errors = sorted(
            self._validator.iter_errors(instance),
            key=lambda error: (list(error.absolute_path), error.validator or ""),
        )
        if errors:
            raise DiscoveryContractValidationError(
                tuple(
                    ContractIssue(
                        path="/" + "/".join(str(part) for part in error.absolute_path),
                        keyword=error.validator or "unknown",
                    )
                    for error in errors
                )
            )
        created_at = datetime.fromisoformat(instance["createdAt"].removesuffix("Z") + "+00:00")
        expires_at = datetime.fromisoformat(instance["expiresAt"].removesuffix("Z") + "+00:00")
        if expires_at <= created_at:
            raise DiscoveryContractValidationError(
                (ContractIssue(path="/expiresAt", keyword="exclusiveMinimum"),)
            )
        return instance

    @staticmethod
    def _reject_remote_resource(uri: str) -> Resource[Any]:
        raise NoSuchResource(ref=uri)

    @classmethod
    def _reject_unsafe_references(cls, node: object) -> None:
        if isinstance(node, dict):
            reference = node.get("$ref")
            if isinstance(reference, str) and (
                ".." in reference
                or (not reference.startswith("#") and not reference.startswith(SCHEMA_BASE))
            ):
                raise DiscoveryContractError(
                    "Discovery schema contains a remote or unsafe reference"
                )
            for value in node.values():
                cls._reject_unsafe_references(value)
        elif isinstance(node, list):
            for value in node:
                cls._reject_unsafe_references(value)
