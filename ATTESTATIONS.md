# Validator score attestations

`src/attestations.ts` verifies an explicitly selected set of sr25519 keys agreeing on the **same locally expected result target**. This is a certificate verifier, not distributed consensus, validator independence, chain eligibility, score correctness or finality.

## Use

Each reviewer must obtain and independently verify the same closed inbox snapshot and recompute it with the qualified implementation. Current tests recompute with the same local code; they do not qualify independent validator operators.

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

Import functions from `src/attestations.ts`. Never derive the expected target or eligible policy solely from an untrusted received certificate. `scoreTarget` is for a locally recomputed report; it hashes a deterministic projection, not a proof that arbitrary supplied report data is true. Transport must impose its own byte/rate bounds before parsing JSON. No endpoint, key custody, storage or chain call is added.

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

`bun run check`: **8 tests / 204 assertions**. Attestation tests cover unique signer threshold, order invariance, insufficient/empty sets, duplicate/untrusted keys, invalid signatures, extra fields, every digest scope substitution, netuid mismatch, policy threshold/validator-set changes, malformed policy and concurrent caller mutation. A real closed, committed practice cohort is evaluated twice; resource variation leaves the target stable, changed TP changes it, and two generated sr25519 keys sign/verify the result.

No independent validator fleet, chain permits, remote snapshot exchange, equivocation/slashing detection, durable vote journal, quorum policy governance, hidden-case authority or adversarial network test is claimed. The same key may sign conflicting targets elsewhere; this stateless verifier rejects conflicts in the supplied set but does not detect withheld conflicting signatures. Threshold selection, membership provenance and finality require independent qualification. Do not use this receipt as chain weights, financial reward approval or product-release approval.
