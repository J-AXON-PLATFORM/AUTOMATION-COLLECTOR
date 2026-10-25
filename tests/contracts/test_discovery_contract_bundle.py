from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts.sync_discovery_contracts import BundleError, check_bundle, sync_bundle, verify_bundle

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "contracts" / "discovery" / "1.0"


def test_discovery_manifest_verifies_expected_bundle() -> None:
    manifest = json.loads((BUNDLE / "manifest.json").read_text(encoding="utf-8"))
    assert verify_bundle(BUNDLE) == manifest["bundleSha256"]


@pytest.mark.parametrize("change", ["added", "removed", "modified"])
def test_discovery_manifest_detects_changes(tmp_path: Path, change: str) -> None:
    target = tmp_path / "bundle"
    shutil.copytree(BUNDLE, target)
    if change == "added":
        (target / "unexpected.json").write_text("{}\n", encoding="utf-8")
    elif change == "removed":
        (target / "examples" / "valid" / "job-basic.json").unlink()
    else:
        (target / "common.schema.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(BundleError):
        verify_bundle(target)


def test_discovery_sync_is_idempotent_and_byte_exact(tmp_path: Path) -> None:
    target = tmp_path / "target"
    assert sync_bundle(BUNDLE, target) is True
    assert sync_bundle(BUNDLE, target) is False
    assert check_bundle(BUNDLE, target) == verify_bundle(BUNDLE)
