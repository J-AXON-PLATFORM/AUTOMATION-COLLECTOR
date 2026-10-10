#!/usr/bin/env python3
"""Synchronize and verify the vendored J-AXON Agent contract bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPOSITORY_ROOT / "contracts" / "agent" / "1.0"
MANIFEST_NAME = "manifest.json"


class BundleError(Exception):
    """Raised when a contract bundle is incomplete or has been modified."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bundle_files(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.rglob("*") if path.is_file() and path.name != MANIFEST_NAME),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def verify_bundle(root: Path) -> str:
    root = root.resolve()
    manifest_path = root / MANIFEST_NAME
    if not root.is_dir() or not manifest_path.is_file() or manifest_path.is_symlink():
        raise BundleError("Contract bundle or manifest is missing")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError("Contract manifest is not valid JSON") from error

    expected_header = {
        "manifestVersion": "1.0",
        "contractFamily": "agent",
        "contractVersion": "1.0",
        "schemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "sourceRepository": "J-AXON-PLATFORM/BACKEND",
        "sourcePath": "doc/contracts/agent/1.0",
    }
    if any(manifest.get(key) != value for key, value in expected_header.items()):
        raise BundleError("Contract manifest metadata is not approved")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise BundleError("Contract manifest file list is empty")

    manifest_paths: list[str] = []
    canonical_lines: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise BundleError("Contract manifest contains an invalid entry")
        relative = entry.get("path")
        expected_hash = entry.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            raise BundleError("Contract manifest entry is incomplete")
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != relative
            or relative == MANIFEST_NAME
        ):
            raise BundleError("Contract manifest contains an unsafe path")
        path = (root / relative_path).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
            raise BundleError("Contract manifest references a missing or unsafe file")
        actual_hash = sha256_bytes(path.read_bytes())
        if actual_hash != expected_hash:
            raise BundleError("Contract file checksum mismatch")
        manifest_paths.append(relative)
        canonical_lines.append(f"{actual_hash}  {relative}\n")

    if manifest_paths != sorted(manifest_paths) or len(manifest_paths) != len(set(manifest_paths)):
        raise BundleError("Contract manifest paths are not unique and sorted")

    disk_paths = [path.relative_to(root).as_posix() for path in bundle_files(root)]
    if disk_paths != manifest_paths:
        raise BundleError("Contract bundle file set differs from the manifest")

    bundle_hash = sha256_bytes("".join(canonical_lines).encode())
    if manifest.get("bundleSha256") != bundle_hash:
        raise BundleError("Contract bundle checksum mismatch")
    return bundle_hash


def bundles_equal(source: Path, target: Path) -> bool:
    source_files = sorted(
        (path for path in source.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(source).as_posix(),
    )
    target_files = sorted(
        (path for path in target.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(target).as_posix(),
    )
    source_names = [path.relative_to(source).as_posix() for path in source_files]
    target_names = [path.relative_to(target).as_posix() for path in target_files]
    return source_names == target_names and all(
        source_path.read_bytes() == target_path.read_bytes()
        for source_path, target_path in zip(source_files, target_files, strict=True)
    )


def sync_bundle(source: Path, target: Path = TARGET) -> bool:
    source = source.resolve()
    target = target.resolve()
    verify_bundle(source)
    if (
        target.is_dir()
        and verify_bundle(target) == verify_bundle(source)
        and bundles_equal(source, target)
    ):
        return False

    if target.exists():
        if target.is_symlink() or not target.is_dir():
            raise BundleError("Contract target is not a safe directory")
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for source_path in sorted(source.rglob("*")):
        relative = source_path.relative_to(source)
        destination = target / relative
        if source_path.is_symlink():
            raise BundleError("Contract source cannot contain symbolic links")
        if source_path.is_dir():
            destination.mkdir(exist_ok=True)
        elif source_path.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, destination)
    verify_bundle(target)
    if not bundles_equal(source, target):
        raise BundleError("Synchronized contract bundle differs from its source")
    return True


def check_bundle(source: Path, target: Path = TARGET) -> str:
    source = source.resolve()
    target = target.resolve()
    source_hash = verify_bundle(source)
    target_hash = verify_bundle(target)
    if source_hash != target_hash or not bundles_equal(source, target):
        raise BundleError("Vendored contract bundle differs from its canonical source")
    return target_hash


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("sync", "check"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--source", required=True, type=Path)
    subparsers.add_parser("verify")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "sync":
            changed = sync_bundle(args.source)
            bundle_hash = verify_bundle(TARGET)
            state = "updated" if changed else "already synchronized"
            print(f"Agent contract bundle {state}: {bundle_hash}")
        elif args.command == "check":
            print(f"Agent contract bundles are identical: {check_bundle(args.source)}")
        else:
            print(f"Agent contract bundle is valid: {verify_bundle(TARGET)}")
    except BundleError as error:
        print(f"Agent contract verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
