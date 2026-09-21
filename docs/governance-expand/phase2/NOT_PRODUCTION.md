# NOT PRODUCTION

All modules under `phase2/src/aimw/` are **design-alignment stubs**.

- They raise `NotImplementedError` or are marked Placeholder.
- Do not import them from production configs.
- Do not publish as part of a release until ADR-002 adapters are implemented,
  tested, and the `aimw[enterprise]` extra is documented.
- Hermetic L1/L2 classes in the Phase 0 SDK remain the supported defaults.
