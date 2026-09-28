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
- Exact-byte digest precedes JSON parsing. Roundtrip JSON rejects whitespace/duplicate-key ambiguity; fatal UTF-8 decoding retains a BOM for rejection rather than silently stripping it. The same BOM rule covers trusted expectations, signing-policy files and v3 embedded chain evidence. Seed/salt/pair reveal, generator/scorer, baseline and regenerated full fixture digest must match.
- Contributions require exact fields, unique eligible miner/nonce, coordinator/network/round binding, admitted literal-artifact digest and valid miner signature. Snapshot v2 additionally requires retained validator challenge signature and coordinator-signed admission timestamp within the challenge window and no later than closure. All signatures are checked before fixture execution. [ADMISSION.md](ADMISSION.md) specifies bytes and migration; these are authenticated clock claims, not independent time proofs.
- Corpus source/oracles are regenerated from shipped synthetic templates. No supplied program, path, dependency or command executes. Trusted template oracles execute normally; this is not a hostile-code sandbox.

API copies bytes/expectations and the admitted baseline before asynchronous verification. It passes that same validated baseline into cohort scoring rather than rereading a mutable module export after crypto readiness. The shipped family inventory is runtime-frozen so it cannot change between fixture-digest validation, fixture regeneration and per-family scoring. Replay preserves cohort digest and deterministic scores, measures resources anew. Separate local processes using the same code prove reproducibility, not independent validators/models/benchmarks. No build attestation, remote isolation, chain permits or hidden holdout qualification.

Stored compact JSON must roundtrip unchanged before export. Matching the stored digest alone does not permit duplicate-key/whitespace normalization. Complete-input validation covers every contribution, including exact execution clones: a valid first miner cannot mask a later invalid digest, signature or admission proof. Omission changes the independently expected whole-snapshot digest; a receiver that independently approves a different subset has changed its trust input. This is not witnessed admission-log completeness.

## Compatibility and evidence

No new dependency. The admission-proof upgrade adds a SQLite table and v2 wire schema; see ADMISSION.md before migrating. Local evaluation uses strict portable checks. Eligible-list ceiling applies to new inbox instances; larger historical lists need explicitly selected supported rounds, never silent omission. Closure/export refuses oversized snapshots.

`bun run check`: **9 tests / 243 assertions**. A real signed committed cohort is exported and recalculated by a separate `bun src/replay.ts` process from `/tmp/opencode`; its score target exactly matches local evaluation. Tests reject size overflow, wrong digest/network/eligibility, extra fields, duplicate contributions/JSON keys, forged signatures, challenge-scope mismatch, altered artifact/fixtures/salt and pre-challenge closure. Prior admission, commitment, quorum and equivocation tests remain passing.

Input-integrity increment: `bun run check`, **14 tests / 733 assertions**, Bun 1.4.2. Actual corpus-export/miner CLI output matches signed evaluation counts; two local signer processes and portable replay agree on the target. Both replay/signing CLIs reject ambiguous JSON/UTF-8, changed digests, altered later-clone artifacts/signatures/admission proofs, duplicate entries and fixture substitutions, including deliberately recomputed outer digests. Rejected input leaves the SQLite signing/vote tables empty. A valid request with unavailable key material retains its target lock across process exit; the next process refuses a conflicting snapshot and subsequently recovers the original target. API tests mutate input objects/bytes/baseline across awaits and reopen noncanonical stored snapshots. This verifies the practice flow, not hidden-lineage or independent-operator qualification.

Authenticated transport, witness approval, completeness, independently administered validators, off-instance recovery, cross-version reproducibility and independent hidden-case ownership remain required before network readiness.
# Chain-bound replay v3

Chain-qualified inboxes now export `sentinel-frozen-practice/v3` with exact approved observation envelope, acceptance policy and approval. Supply independently trusted `chain: {policy, approval}` alongside `cohortSha256`, `scope`, `eligible` in replay expectations. Missing chain expectations reject v3; chain expectations reject legacy v2. Evidence bytes are covered by cohort SHA-256 and the existing score-attestation target. See `chain/README.md` for exact fields, freshness semantics and migration. Legacy `sentinel-frozen-practice/v2` remains explicitly unqualified operator-list practice.

## Historical evidence after local revocation

`inbox.revokeChainApproval()` permanently blocks further live activity for that database's round scope, including pending admission and closure. It does not invalidate or rewrite an already frozen cohort. Local export/evaluation and portable replay retain the original bytes, digest and independently supplied v3 expectations after revocation or expiry, including reopening an exact existing binding after restart. Approval replacement remains forbidden; refresh requires a new round.

V3 replay reports `authentication.evidenceUse: "historical-replay"`, `currentEligibility: "not-assessed"` and `revocationStatus: "not-assessed"`. The existing `eligibility` label describes recorded operator-approved RPC evidence only. Freshness is checked at recorded issuance, acceptance and closure times, not replay wall time. Portable evidence contains no local revocation ledger: successful replay neither proves current eligibility nor absence of revocation, and cannot independently establish whether a coordinator honored its local revocation. Revocation timestamps are local operator clock claims. Historical replay is deliberately nonretroactive; no current-admission authorization follows from it. V2 validation and mandatory external v3 expectations remain unchanged.
