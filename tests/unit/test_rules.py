from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from aimw.policy.rules import load_ruleset


def test_load_ruleset_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.yaml"
    with pytest.raises(FileNotFoundError):
        load_ruleset(missing)


def test_load_ruleset_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("allowed_tools: [\n  - search_tool\n  this is not valid yaml: [", encoding="utf-8")
    with pytest.raises(yaml.YAMLError):
        load_ruleset(path)


def test_load_ruleset_schema_validation_failure_missing_required(tmp_path: Path) -> None:
    path = tmp_path / "incomplete.yaml"
    # allowed_tools and tools are required on PolicyRuleSet
    path.write_text("identity_required_fields: [user_id]\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_ruleset(path)


def test_load_ruleset_schema_validation_failure_wrong_types(tmp_path: Path) -> None:
    path = tmp_path / "wrong_types.yaml"
    path.write_text(
        "allowed_tools: not-a-list\ntools: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_ruleset(path)
