# Validator score attestations

`src/attestations.ts` verifies an explicitly selected set of sr25519 keys agreeing on the **same locally expected result target**. This is a certificate verifier, not distributed consensus, validator independence, chain eligibility, score correctness or finality.

## Use

Each reviewer must obtain and independently verify the same closed inbox snapshot and recompute it with the qualified implementation. [REPLAY.md](REPLAY.md) provides export and database-independent replay against separately trusted expectations. Tests recompute in separate local processes using the same code; they do not qualify independent validator operators.

```ts
const report = await inbox.evaluatePractice();
const target = scoreTarget(report);
const policy = { validators: approvedValidatorAddresses, threshold: operatorSelectedThreshold };
const policySha256 = quorumPolicyDigest(policy);
const bytes = scoreAttestationPayload(target, policySha256, myValidatorAddress);
// Existing operator custody signs bytes; no key loader is provided here.
const attestation = {
  schema: 'sentinel-score-attestation/v1', target, policySha256,
  validator: myValidatorAddress, signature: rawSr25519SignatureHex
};
const certificate = await verifyScoreQuorum(collectedAttestations, target, policy);
```

Import functions from `src/attestations.ts`. Never derive the expected target or eligible policy solely from an untrusted received certificate. `scoreTarget` is for a locally recomputed report; it hashes a deterministic projection, not a proof that arbitrary supplied report data is true. Transport must impose its own byte/rate bounds before parsing JSON. The verifier is stateless; optional durable observation is described below. No endpoint, key custody or chain call is added.

## Bound data

Target fields are exactly `genesis`, `netuid`, `round`, `cohortSha256`, `resultSha256`. SHA-256 values are lowercase 64-hex, netuid is an integer in 0–65535. Cohort identifies one exact coordinator snapshot, including its submitted signatures. Reviewers attest that same snapshot rather than comparing separately admitted cohorts with different nonces.

Result hash input: UTF-8 `sentinel/deterministic-practice-score/v1\n` followed by canonical JSON of report `schema`, `comparisonId`, `generator`, `seed`, `pairs`, `cases`, `tiers`, `results` projected to `digest`/`participants`/`comparison`, `commitment`, `reveal`, `weights`, `rewards`. Canonical JSON sorts object keys lexically, preserves array order and refuses nonfinite/non-JSON values. Existing result arrays are already deterministically ordered by the evaluator. Resource observations, display limitation text and closing time are excluded. Scores/family metrics/rank changes affect the digest; CPU/RSS/wall-time variation does not. This certificate does not attest resource measurements.

Policy is exactly `{validators,threshold}`: 1–100 unique canonical SS58-42 addresses, integer threshold between 1 and their count. No threshold is selected by the library; a threshold of one is valid input, not an independence claim. Policy hash input is `sentinel/quorum-policy/v1\n` plus compact JSON `[sortedValidators,threshold]`.

Signature payload is UTF-8 `sentinel/score-attestation/sr25519/v1\n` followed by compact JSON:

```text
[genesis,netuid,round,cohortSha256,resultSha256,policySha256,validator]
```

Attestation schema is `sentinel-score-attestation/v1`; signature is raw sr25519 encoded as 128 lowercase hex characters. Verification requires exact envelope fields, exact expected target/policy hash, trusted unique signer and valid signature. It refuses the entire provided set if any entry is invalid, duplicated or conflicting, even when other entries meet threshold. It never chooses a winning score among disagreements. Fewer unique signatures than threshold fail. Input copies freeze the caller's expectations and attestations before asynchronous crypto readiness.

Returned `sentinel-score-quorum/v1` contains target, policy digest, threshold, sorted signers, `weights:null` and `rewards:null`. It is a verification receipt; retain original attestations to permit another verifier to check the signatures. No product import/promotion hook exists. Keys and quorum policy remain research/operator authority, separate from private-product release trust.

## Evidence and remaining work

### Recompute and sign with a persistent conflict lock

`VoteJournal.evaluateAndSign(snapshotBytes, trustedExpectations, validatorAddress, signer)` evaluates the frozen cohort through `evaluateSnapshot` before constructing the signing target. It commits an immutable `(network, round, policy, validator)` lock with SQLite FULL synchronization **before** calling the signer. A failed/lost signer response leaves the lock intact. A conflicting cohort/result is refused after restart; the identical target may retry. The first verified signed vote is retained, returned on replay and added to the observation journal. Separate concurrent connections cannot sign two distinct targets through this path. Deleting the database or changing policy identity is not a supported recovery procedure.

Local practice command:

```sh
bun run validator:attest SNAPSHOT.json EXPECTATIONS.json POLICY.json VALIDATOR_ADDRESS PRIVATE_SEED JOURNAL_DIRECTORY
```

`POLICY.json` is compact JSON `{ "validators": [...], "threshold": ... }` without spaces in the actual file; policy/expectations are independently trusted inputs, not copied blindly from a peer. `PRIVATE_SEED` contains exactly 32 raw bytes in a regular, non-symlink, single-link mode-0600 file. It must be an independently created disposable **practice key**, never a funded wallet, coldkey or product release key. The key is loaded only after successful evaluation and durable lock creation, cleared afterward, and not needed to recover an already stored vote. Stdout contains `{target,vote,report}`; no key material. Retain the private directory and WAL together. Signed score output remains public-template practice only.

The actual two-process fixture recomputes the same closed synthetic cohort in two Bun processes with separate SQLite journals and practice keys, verifies identical targets and verifies the original explicit threshold. It also exercises signer response loss, restart, conflicting snapshots, concurrent conflict, immutable locks, key-file permission rejection and keyless signature recovery. This is independent local execution, not independent operators, hidden evaluation, EC-08 transcript-set agreement, hardware key custody or network readiness. Network deployment still requires an isolated authorized signer and the full committed-window protocol.

### Durable observed-vote journal

`src/vote-journal.ts` adds `VoteJournal(privateDirectory, policy)` using Bun SQLite/WAL with FULL synchronization. It requires a private real directory and rejects symlink/nonregular/hardlinked database files; the directory's parents and storage remain trusted. Existing inbox storage is untouched; votes use `votes.sqlite`. Keep DB and WAL together under your recovery policy.

`await journal.observe(attestation)` cryptographically validates and copies a trusted-policy vote before any write. An IMMEDIATE transaction retains the first vote and, if observed, the first distinct conflicting target for that signer. Scope is `(genesis, netuid, round, policySha256)`; target is `(cohortSha256, resultSha256)`. Same-target retransmission, including a different valid randomized signature, is idempotent. A second cohort or result under the same scope marks the signer equivocal. Further conflicts remain refused for certification but are not stored beyond the two sufficient signed proofs, bounding per-signer/per-scope storage. Round/policy growth still needs operator retention/admission limits.

`await journal.equivocations(target)` returns retained pairs, reverifying signatures and row identity. `await journal.certify(locallyRecomputedTarget)` reads the recorded votes, rechecks their signatures, excludes every observed equivocator and evaluates the **original unchanged threshold** against remaining exact-target votes. Insufficient support fails. It returns `{certificate, attestations, evidence, journalRevision}`. A transaction compares row IDs after asynchronous cryptographic verification and refuses if another connection added a vote meanwhile. This gives a local point-in-time verification receipt, not distributed finality. A later conflict can invalidate future certification; previously exported receipts are not automatically recalled. Consumers must refresh the journal and reverify before relying on it.

Invalid signatures cannot frame a validator or poison the journal. Votes under another round or policy do not count as conflicts here. Policy replacement therefore requires external governance, not deleting evidence or silently lowering a threshold. Evidence withheld from this journal cannot be detected. Storage hashes/constraints/signatures do not protect against a privileged operator deleting conflict rows or rolling back the database; off-instance witnessing and recovery consistency remain required.

Expanded `bun run check`: **9 tests / 225 assertions**. Journal tests cover invalid-signature nonadmission, concurrent replay, valid same-target re-signing, conflicting cohort/result retention, reopen/reordered-policy persistence, two-proof storage ceiling, immutable threshold, alternate nonconflicting signers, round separation, conflict arrival during certification and altered row-identity rejection. One corruption fixture initially collided with the uniqueness constraint; limiting corruption to a single row exercised the intended integrity check in the final passing run.

`bun run check`: **8 tests / 204 assertions**. Attestation tests cover unique signer threshold, order invariance, insufficient/empty sets, duplicate/untrusted keys, invalid signatures, extra fields, every digest scope substitution, netuid mismatch, policy threshold/validator-set changes, malformed policy and concurrent caller mutation. A real closed, committed practice cohort is evaluated twice; resource variation leaves the target stable, changed TP changes it, and two generated sr25519 keys sign/verify the result.

No independent validator fleet, chain permits, remote snapshot exchange, slashing, quorum policy governance, hidden-case authority or adversarial network test is claimed. The optional journal detects only valid conflicting signatures it observes; no global equivocation discovery exists. Threshold selection, membership provenance, off-instance evidence recovery and finality require independent qualification. Do not use this receipt as chain weights, financial reward approval or product-release approval.
