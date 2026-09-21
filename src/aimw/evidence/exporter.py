"""Evidence exporter — JSONL audit → zip/manifest (Phase 3).

Fully working hermetic API:

    export_evidence_pack(audit_path, out_zip, controls_paths=None)

Reads an audit JSONL path, calls ``verify_chain``, builds a manifest dict,
and writes a zip containing ``manifest.json``, a copy of the audit, and
optional control-mapping YAML files.

This is an auditor packaging stepping stone — not a full GRC product.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _try_verify_chain(audit_path: Path) -> dict[str, Any]:
    """Call Phase 0 ``verify_chain`` if aimw audit is available; else stub."""
    try:
        from aimw.audit.worm_log import verify_chain

        result = verify_chain(audit_path)
        return {
            "valid": bool(result.valid),
            "record_count": int(result.record_count),
            "first_broken_index": result.first_broken_index,
            "source": "aimw.audit.worm_log.verify_chain",
        }
    except Exception as exc:  # ImportError or runtime — keep hermetic
        count = 0
        if audit_path.exists():
            with audit_path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        count += 1
        return {
            "valid": None,
            "record_count": count,
            "first_broken_index": None,
            "source": "stub",
            "stub_reason": f"{type(exc).__name__}: {exc}",
        }


def _count_signals(audit_path: Path) -> dict[str, int]:
    """Best-effort signal tallies from JSONL decision fields."""
    counts = {"deny": 0, "hitl": 0, "worm_verify": 0, "identity_fail": 0}
    if not audit_path.exists():
        return counts
    with audit_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            decision = rec.get("decision") or {}
            if isinstance(decision, dict):
                outcome = str(
                    decision.get("outcome") or decision.get("action") or ""
                ).lower()
                allowed = decision.get("allowed")
                if outcome in {"deny", "denied"} or allowed is False:
                    counts["deny"] += 1
                if outcome in {"hitl", "needs_approval", "approval_required"} or decision.get(
                    "requires_approval"
                ):
                    counts["hitl"] += 1
                if outcome in {"identity_fail", "auth_failed"} or decision.get("identity_fail"):
                    counts["identity_fail"] += 1
    return counts


def build_manifest(
    audit_path: str | Path,
    *,
    control_maps: list[str] | None = None,
    producer: dict[str, str] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """Build the auditor manifest dict from an audit JSONL path."""
    path = Path(audit_path)
    chain = _try_verify_chain(path)
    signals = _count_signals(path)
    if chain.get("valid") is True:
        signals["worm_verify"] = 1
    return {
        "schema_version": "aimw.evidence.v1",
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audit_source_path": str(path.resolve()) if path.exists() else str(path),
        "audit_record_count": chain.get("record_count", 0),
        "chain_verification": {
            "valid": chain.get("valid"),
            "record_count": chain.get("record_count"),
            "first_broken_index": chain.get("first_broken_index"),
            "source": chain.get("source"),
            **(
                {"stub_reason": chain["stub_reason"]}
                if "stub_reason" in chain
                else {}
            ),
        },
        "signal_counts": signals,
        "control_maps": list(
            control_maps
            or [
                "controls/soc2_cc_mapping.yaml",
                "controls/nist_ai_rmf_mapping.yaml",
            ]
        ),
        "producer": producer
        or {"component": "aimw.evidence.exporter", "version": "0.2.0-hermetic"},
        "notes": notes
        or (
            "Hermetic evidence pack — re-verify chain independently; "
            "not a full compliance product"
        ),
    }


@dataclass
class EvidenceExporter:
    """Write a minimal auditor zip from an audit path + optional control maps."""

    audit_path: Path
    control_map_paths: list[Path] | None = None

    def __post_init__(self) -> None:
        self.audit_path = Path(self.audit_path)
        if self.control_map_paths is not None:
            self.control_map_paths = [Path(p) for p in self.control_map_paths]

    def export_zip(self, dest_zip: str | Path) -> Path:
        dest = Path(dest_zip)
        dest.parent.mkdir(parents=True, exist_ok=True)
        rel_maps: list[str] = []
        if self.control_map_paths:
            for p in self.control_map_paths:
                rel_maps.append(f"controls/{p.name}")
        manifest = build_manifest(
            self.audit_path,
            control_maps=rel_maps or None,
        )
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "manifest.json",
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            )
            if self.audit_path.exists():
                zf.write(self.audit_path, arcname="audit/events.jsonl")
            else:
                zf.writestr("audit/events.jsonl", "")
            if self.control_map_paths:
                for p in self.control_map_paths:
                    if p.exists():
                        zf.write(p, arcname=f"controls/{p.name}")
            zf.writestr(
                "README.txt",
                "aimw evidence package\n"
                "1. Read manifest.json\n"
                "2. Re-verify hash chain on audit/events.jsonl\n"
                "3. Cross-check controls/*.yaml\n",
            )
        return dest


def export_evidence_pack(
    audit_path: str | Path,
    out_zip: str | Path,
    controls_paths: list[str | Path] | None = None,
) -> Path:
    """CLI-less API: verify chain, build manifest, write zip evidence pack.

    Parameters
    ----------
    audit_path:
        Path to the hash-chained JSONL audit log.
    out_zip:
        Destination zip path (created/overwritten).
    controls_paths:
        Optional list of control-mapping YAML paths to include under
        ``controls/`` in the zip.
    """
    maps = [Path(p) for p in controls_paths] if controls_paths else None
    exporter = EvidenceExporter(audit_path=Path(audit_path), control_map_paths=maps)
    return exporter.export_zip(out_zip)
