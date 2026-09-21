"""Evidence exporter — hermetic zip/manifest with verify_chain."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from aimw.audit.worm_log import HashChainedJSONLLogger, verify_chain
from aimw.evidence.exporter import EvidenceExporter, build_manifest, export_evidence_pack
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest


def _write_audit(path: Path) -> Path:
    logger = HashChainedJSONLLogger(path)
    ctx = ExecutionContext(
        user_id="u1",
        agent_id="a1",
        session_id="s1",
        roles=["operator"],
        delegated_scopes=[],
    )
    req = ToolRequest(
        tool_name="shell", function_name="run", parameters={"cmd": "ls"}, call_id="c1"
    )
    logger.log_call(ctx, req, PolicyDecision(allowed=True, reason="ok"))
    logger.log_call(
        ctx,
        ToolRequest(
            tool_name="shell", function_name="rm", parameters={}, call_id="c2"
        ),
        PolicyDecision(allowed=False, reason="deny"),
    )
    return path


def test_build_manifest_verifies_chain(tmp_path: Path) -> None:
    audit = _write_audit(tmp_path / "events.jsonl")
    chain = verify_chain(audit)
    assert chain.valid is True
    manifest = build_manifest(audit)
    assert manifest["schema_version"] == "aimw.evidence.v1"
    assert manifest["chain_verification"]["valid"] is True
    assert manifest["audit_record_count"] == 2
    assert manifest["signal_counts"]["deny"] >= 1
    assert manifest["signal_counts"]["worm_verify"] == 1


def test_export_evidence_pack_zip(tmp_path: Path) -> None:
    audit = _write_audit(tmp_path / "events.jsonl")
    controls = tmp_path / "soc2.yaml"
    controls.write_text("control: CC6.1\nmapped: deny\n", encoding="utf-8")
    out = tmp_path / "pack.zip"
    result = export_evidence_pack(audit, out, controls_paths=[controls])
    assert result == out
    assert out.exists()
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "audit/events.jsonl" in names
        assert "controls/soc2.yaml" in names
        assert "README.txt" in names
        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["chain_verification"]["valid"] is True
        assert "controls/soc2.yaml" in manifest["control_maps"]


def test_evidence_exporter_class(tmp_path: Path) -> None:
    audit = _write_audit(tmp_path / "events.jsonl")
    out = tmp_path / "via-class.zip"
    EvidenceExporter(audit_path=audit).export_zip(out)
    assert out.exists()
