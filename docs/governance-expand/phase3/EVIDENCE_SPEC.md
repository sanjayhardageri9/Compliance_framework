# Evidence Package Spec (Auditor Zip)

What an aimw auditor export contains. Produced by
`aimw.evidence.exporter` (Phase 3 skeleton).

## Purpose

Give an external auditor a self-contained, verifiable snapshot of runtime
governance activity for a time window — without granting live system access.

## Zip layout

```
aimw-evidence-YYYYMMDDTHHMMSSZ.zip
├── manifest.json           # package metadata + chain verification summary
├── audit/
│   └── events.jsonl        # copy (or filtered slice) of HashChainedJSONLLogger
├── controls/
│   ├── soc2_cc_mapping.yaml
│   └── nist_ai_rmf_mapping.yaml
├── policies/
│   └── active_policy.json  # optional: promoted policy body at export time
├── decisions/
│   └── explain_index.json  # optional: decision_id → rule_trace stubs
└── README.txt              # human summary of how to verify
```

## `manifest.json` (required fields)

| Field | Type | Meaning |
|-------|------|---------|
| `schema_version` | string | e.g. `"aimw.evidence.v1"` |
| `exported_at` | ISO-8601 | UTC export timestamp |
| `audit_source_path` | string | Original path on producing host |
| `audit_record_count` | int | Lines/records included |
| `chain_verification` | object | `{valid, record_count, first_broken_index}` from `verify_chain` |
| `signal_counts` | object | Counts for `deny`, `hitl`, `worm_verify`, `identity_fail` (best-effort) |
| `control_maps` | list | Relative paths of included mapping YAMLs |
| `producer` | object | `{component, version}` e.g. sidecar / SDK version |
| `notes` | string | Free-form caveats |

## Verification steps (auditor)

1. Unzip; open `manifest.json`.
2. Confirm `chain_verification.valid == true`.
3. Independently re-run hash-chain verify over `audit/events.jsonl`
   (same algorithm as `aimw.audit.worm_log.verify_chain`).
4. Spot-check deny/HITL/identity_fail samples against SOC2/NIST YAML maps.
5. If `valid` is false, treat package as compromised / incomplete — do not
   rely on signal_counts alone.

## Non-goals

- Legal hold / e-discovery formats
- Full Presidio redaction proofs
- Live SIEM correlation IDs (optional future field)

## Privacy

Export should honor `Settings.redact_audit_parameters` semantics already
applied in the JSONL. Do not re-hydrate raw PII into the zip.
