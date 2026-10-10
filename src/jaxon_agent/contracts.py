"""Offline validation for versioned J-AXON Agent messages."""

from __future__ import annotations

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

SCHEMA_BASE = "https://schemas.j-axon.invalid/agent/1.0/"
SUPPORTED_VERSION = "1.0"
SCHEMA_FILES = {
    "AGENT_SNAPSHOT": "snapshot.schema.json",
    "AGENT_TASK": "task.schema.json",
    "AGENT_RESULT": "result.schema.json",
}
OUTBOUND_TYPES = frozenset({"AGENT_SNAPSHOT", "AGENT_RESULT"})
INBOUND_TYPES = frozenset({"AGENT_TASK"})
MAX_TASK_BYTES = 64 * 1024
MAX_OBSERVATION_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class ContractIssue:
    path: str
    keyword: str


class ContractError(Exception):
    """Base class for safe contract errors that never includes message payloads."""


class ContractSizeError(ContractError):
    pass


class ContractEncodingError(ContractError):
    pass


class UnsupportedContractVersion(ContractError):
    pass


class UnsupportedMessageType(ContractError):
    pass


class ContractValidationError(ContractError):
    def __init__(self, issues: tuple[ContractIssue, ...]) -> None:
        self.issues = issues
        super().__init__(f"Agent message failed contract validation ({len(issues)} issue(s))")


def _is_uuid_v4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError, AttributeError:
        return False
    return parsed.version == 4 and parsed.variant == RFC_4122


def _is_utc_datetime(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _format_checker() -> FormatChecker:
    checker = FormatChecker()
    checker.checks("uuid")(_is_uuid_v4)
    checker.checks("date-time")(_is_utc_datetime)
    return checker


def _default_contract_root() -> Path:
    packaged = files("jaxon_agent").joinpath("contracts", "agent")
    if packaged.is_dir():
        return Path(str(packaged))
    return Path(__file__).resolve().parents[2] / "contracts" / "agent"


class AgentContractValidator:
    def __init__(self, contract_root: Path | None = None) -> None:
        root = (contract_root or _default_contract_root()).resolve() / SUPPORTED_VERSION
        schemas: dict[str, dict[str, Any]] = {}
        for filename in ("common.schema.json", *SCHEMA_FILES.values()):
            schema = json.loads((root / filename).read_text(encoding="utf-8"))
            schema_id = schema.get("$id")
            if schema_id != SCHEMA_BASE + filename:
                raise ContractError("Agent schema identity is not approved")
            self._reject_unsafe_references(schema)
            schemas[schema_id] = schema

        resources = [
            (schema_id, Resource.from_contents(schema)) for schema_id, schema in schemas.items()
        ]
        registry = Registry(retrieve=self._reject_remote_resource).with_resources(resources)
        checker = _format_checker()
        self._validators = {
            message_type: Draft202012Validator(
                schemas[SCHEMA_BASE + filename], registry=registry, format_checker=checker
            )
            for message_type, filename in SCHEMA_FILES.items()
        }

    def validate_before_emit(self, document: bytes) -> dict[str, Any]:
        return self._validate(document, OUTBOUND_TYPES)

    def validate_after_receive(self, document: bytes) -> dict[str, Any]:
        return self._validate(document, INBOUND_TYPES)

    def _validate(self, document: bytes, allowed_types: frozenset[str]) -> dict[str, Any]:
        if not isinstance(document, bytes):
            raise TypeError("Agent contract validation requires bytes")
        if len(document) > MAX_OBSERVATION_BYTES:
            raise ContractSizeError("Agent message exceeds the maximum supported size")
        try:
            instance = json.loads(document.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ContractEncodingError("Agent message is not valid UTF-8 JSON") from error
        if not isinstance(instance, dict):
            raise ContractValidationError((ContractIssue(path="/", keyword="type"),))

        version = instance.get("contractVersion")
        if version != SUPPORTED_VERSION:
            raise UnsupportedContractVersion("Agent contract version is not supported")
        message_type = instance.get("messageType")
        if message_type not in allowed_types:
            raise UnsupportedMessageType("Agent message type is not allowed at this boundary")
        if message_type == "AGENT_TASK" and len(document) > MAX_TASK_BYTES:
            raise ContractSizeError("Agent task exceeds the maximum supported size")

        errors = sorted(
            self._validators[message_type].iter_errors(instance),
            key=lambda error: (list(error.absolute_path), error.validator or ""),
        )
        if errors:
            issues = tuple(
                ContractIssue(
                    path="/" + "/".join(str(part) for part in error.absolute_path),
                    keyword=error.validator or "unknown",
                )
                for error in errors
            )
            raise ContractValidationError(issues)
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
                raise ContractError("Agent schema contains a remote or unsafe reference")
            for value in node.values():
                cls._reject_unsafe_references(value)
        elif isinstance(node, list):
            for value in node:
                cls._reject_unsafe_references(value)
