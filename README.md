# Sentinel engine-improvement subnet

Public research code, independent of the private review product. MIT.
Status: **initial implementation; not network-ready and not an active subnet**.

## Available

- Bun 1.4.2; `bun test` executes trusted synthetic bug/control programs and release-boundary rejection checks.
- `bun run benchmark` reports precision/recall against an empty baseline and a template-aware reference.
- `src/benchmark.ts`: seeded, independently synthetic multi-file unit-contract defects, including defects outside the changed file. One family is a bootstrap fixture, not broad engine coverage. The public reference has template knowledge; its score is not generalization evidence.
- `src/release.ts`: Ed25519 release verification with exact artifact digest, independently supplied manual approval, trusted keys, expiry, ABI and revocation checks. Fixed-order domain-separated payload defined in code. Signature validity is not execution safety or permission to activate.

## Required before network readiness

Versioned submission formats and sandboxed artifact evaluation; independent private synthetic families and labels held outside this repository and outside candidate execution; miner/hotkey identity; validator independence; anti-copy/Sybil and leakage controls; calibrated marginal utility and deterministic score reconciliation; actual SDK/runtime-compatible weight planning; empty-cohort policy; crash recovery and operator instructions. No numerical production thresholds or network identity are selected.

No customer code, metadata, derivatives, telemetry, feedback or customer-derived synthetic cases may enter research storage, validators, training, scoring or public releases. Hidden inputs must be independently synthetic or appropriately licensed public material. A local score is not a finalized chain weight or a reward.

## Promotion

The private product selects versions manually after its own evaluation. Network rank never activates a release. Product-controlled trust roots, artifact digest approval, ABI compatibility, expiration/revocation and rollback are mandatory. Do not put signing keys, unreleased holdouts or customer material in this public repository.

This repository is intentionally separate: do not vendor or publish private product files here.
