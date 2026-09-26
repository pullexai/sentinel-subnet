# Closed practice snapshot exchange

`ContributionInbox.exportPractice()` returns exact compact JSON snapshot bytes identified by `cohortSha256`. `evaluateSnapshot(bytes, expectations)` verifies and recomputes them without opening the coordinator database. Local `evaluatePractice()` uses the same validation path.

## Workflow

Export after committing, admitting and closing a practice round. Write returned bytes without newline/formatting. Transfer through your authorized research channel. The file contains research hotkeys, signed submissions and revealed synthetic seed/salt; no customer material or derivatives may be included. No private-product files, arbitrary corpus source, keys or complete inbox database are exported.

The receiving operator supplies separately trusted expectations:

```json
{"cohortSha256":"<approved snapshot SHA-256>","scope":{"genesis":"<genesis hex>","netuid":7,"round":"<committed round digest>","validator":"<coordinator SS58-42>"},"eligible":["<eligible miner SS58-42>"]}
```

Replace placeholders; use compact `JSON.stringify` bytes without newline. Expected digest, network, round, coordinator and full eligible set must come from the receiver's trusted contract/witness process, not merely from the received snapshot. File transfer authentication and coordinator trust are external requirements.

```sh
bun run validator:replay /private/research/snapshot.json /private/research/expected.json
```

Output is `{target,report}`. Target feeds score attestations; custody/signing remains separate. No weights, transactions or product promotion are emitted.

## Boundaries

- CLI reads regular non-symlink files up to limit plus one byte, including growing files. Snapshot ceiling 8 MiB; expectations ceiling 1 MiB. These are wire/parser bounds, not capacity objectives. API checks snapshot size before parsing.
- Expected scope/canonical SS58 identities, 1–10,000 distinct eligible identities, exact snapshot schema/scope, matching sorted eligibility and 1–100 distinct contributions are required. Existing artifact/rule limits apply.
- Exact-byte digest precedes JSON parsing. Roundtrip JSON rejects whitespace/duplicate-key ambiguity. Seed/salt/pair reveal, generator/scorer, baseline and regenerated full fixture digest must match.
- Contributions require exact fields, unique eligible miner/nonce, coordinator/network/round binding, admitted literal-artifact digest and valid miner signature. Snapshot v2 additionally requires retained validator challenge signature and coordinator-signed admission timestamp within the challenge window and no later than closure. All signatures are checked before fixture execution. [ADMISSION.md](ADMISSION.md) specifies bytes and migration; these are authenticated clock claims, not independent time proofs.
- Corpus source/oracles are regenerated from shipped synthetic templates. No supplied program, path, dependency or command executes. Trusted template oracles execute normally; this is not a hostile-code sandbox.

API copies bytes/expectations before asynchronous verification. Replay preserves cohort digest and deterministic scores, measures resources anew. Separate local processes using the same code prove reproducibility, not independent validators/models/benchmarks. No build attestation, remote isolation, chain permits or hidden holdout qualification.

## Compatibility and evidence

No new dependency. The admission-proof upgrade adds a SQLite table and v2 wire schema; see ADMISSION.md before migrating. Local evaluation uses strict portable checks. Eligible-list ceiling applies to new inbox instances; larger historical lists need explicitly selected supported rounds, never silent omission. Closure/export refuses oversized snapshots.

`bun run check`: **9 tests / 243 assertions**. A real signed committed cohort is exported and recalculated by a separate `bun src/replay.ts` process from `/tmp/opencode`; its score target exactly matches local evaluation. Tests reject size overflow, wrong digest/network/eligibility, extra fields, duplicate contributions/JSON keys, forged signatures, challenge-scope mismatch, altered artifact/fixtures/salt and pre-challenge closure. Prior admission, commitment, quorum and equivocation tests remain passing.

Authenticated transport, witness approval, completeness, independently administered validators, off-instance recovery, cross-version reproducibility and independent hidden-case ownership remain required before network readiness.
