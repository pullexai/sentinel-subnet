# Sentinel engine-improvement subnet

Public research code, independent of the private review product. MIT.
Status: **initial implementation; not network-ready and not an active subnet**.

## Available

- Bun 1.4.2; `bun test` executes trusted synthetic bug/control programs and release-boundary rejection checks.
- `bun run benchmark` reports precision/recall against an empty baseline and a template-aware reference.
- `src/benchmark.ts`: seeded, independently synthetic multi-file unit-contract defects, including defects outside the changed file. One family is a bootstrap fixture, not broad engine coverage. The public reference has template knowledge; its score is not generalization evidence.
- `src/release.ts`: Ed25519 release verification with exact artifact digest, independently supplied manual approval, trusted keys, expiry, ABI and revocation checks. Fixed-order domain-separated payload defined in code. Signature validity is not execution safety or permission to activate.

## Reproducible practice competition

`src/corpus.ts` adds four authored synthetic families: cross-file amount units, tenant cache-key collisions, filesystem prefix boundaries and token-expiry boundaries. Every fixture contains an injected defect or clean control plus a corrected program and an executable oracle. Evaluation executes the trusted original/corrected programs and rejects a fixture unless the defect and repair are observed. These runners are **not hostile-code sandboxes** and never run submitted programs.

```sh
bun install --frozen-lockfile
bun run check
bun run practice:export aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2 > practice.jsonl
bun run miner:practice examples/reference.json < practice.jsonl > findings.jsonl
bun run practice:evaluate aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2 examples/reference.json
bun run validator:practice aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2 examples/reference.json
```

The count is bug/control pairs **per family**: `2` yields 16 programs. Export includes files, changed-file list and opaque case ID; family labels, gold, oracle and corrected source remain outside miner input. All templates are public, so a different seed does **not** produce independently hidden evaluation. Participants can recover template behavior; report this as practice, never independent generalization. Customer data or derivatives must not be used as seeds, fixture inputs or private evaluations.

`src/miner.ts` supplies a bounded JSONL reference miner; `src/validator.ts` freezes a cohort, groups exact execution clones independent of rule names/order, validates trusted fixture oracles, measures candidates against the template-aware reference and emits deterministic Pareto tiers. Higher TP, lower FP and fewer lost baseline detections define dominance; ties remain ties. No invented quality weights, chain rewards or economic policy. Participant names are local labels, **not verified Bittensor hotkeys**. The data-only `sentinel-literal-miner/v1` submission allows printable literal matches only, with bounded rule count/length and no commands, dependencies or callbacks. This is a compatibility lane, not the complete semantic contribution protocol.

Reports include TP/FP/FN, clean-case false positives, precision/recall, per-family counts, recovered/lost baseline detections, wall time, CPU usage and whole-process RSS. Resource observations are noisy local measurements, not candidate-isolated peak memory or production capacity. Duplicate findings at one file do not multiply a single fixture defect's credit. Clone grouping does not solve semantic copying or Sybil identities. Ranking never imports or activates anything in the private product.

## Required before network readiness

Closed cohorts can be exported and recalculated without the coordinator database using `bun run validator:replay <snapshot.json> <trusted-expectations.json>`. [REPLAY.md](REPLAY.md) specifies bounded validation, separate expected-digest/scope authority and actual separate-process reproducibility evidence.

Signed score agreement is available in `src/attestations.ts`: deterministic report targets, domain-separated sr25519 attestations and strict verification against an operator-selected key set/threshold. `src/vote-journal.ts` durably retains observed votes/conflict proofs and excludes equivocators without lowering that threshold, including after restart. Duplicate, conflicting and untrusted signatures fail certificate verification. [ATTESTATIONS.md](ATTESTATIONS.md) specifies bytes, use and limits; key agreement alone is not independent-validator consensus or network finality.

### Authenticated contribution increment

`src/protocol.ts` now provides signed sr25519 validator challenges and miner contribution verification, canonical SS58 hotkeys, exact artifact-digest binding and a persistent transactional replay fence. `practiceContract`/`practiceRound` commit the benchmark before `registerPractice` permits challenges. `ContributionInbox.closePractice(seed,pairs,salt)` verifies that commitment, durably freezes the eligible cohort and refuses later admissions; `evaluatePractice()` revalidates that snapshot and integrates admitted hotkeys with the practice evaluator, reproducibly after restart. Actual Bun/native-Python crypto interoperability passed. See [PROTOCOL.md](PROTOCOL.md) for signature bytes, custody boundary, use and evidence. This is an operator-eligible authenticated lane, not verified Bittensor registration or Axon/Dendrite transport. The existing label-only practice CLI remains available.

Broader versioned submission formats and sandboxed artifact evaluation; independent private synthetic families and labels held outside this repository and outside candidate execution; chain-bound miner/hotkey registration and SDK transport; validator independence; anti-copy/Sybil and leakage controls; calibrated marginal utility and deterministic score reconciliation; actual SDK/runtime-compatible weight planning; empty-cohort policy; full crash recovery and operator instructions. No numerical production thresholds or network identity are selected.

No customer code, metadata, derivatives, telemetry, feedback or customer-derived synthetic cases may enter research storage, validators, training, scoring or public releases. Hidden inputs must be independently synthetic or appropriately licensed public material. A local score is not a finalized chain weight or a reward.

## Promotion

The private product selects versions manually after its own evaluation. Network rank never activates a release. Product-controlled trust roots, artifact digest approval, ABI compatibility, expiration/revocation and rollback are mandatory. Do not put signing keys, unreleased holdouts or customer material in this public repository.

This repository is intentionally separate: do not vendor or publish private product files here.
