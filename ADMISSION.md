# Coordinator-signed admission receipts

After a contribution has been accepted, call:

```ts
const proof = await inbox.attestAdmission(signedChallenge, async payload => {
  return custodySignSr25519(payload); // lowercase 128-hex; operator-owned implementation
});
```

The supplied `{challenge,signature}` is the original validator-signed challenge. The library verifies its signature and exact stored challenge, reads the committed artifact digest/miner signature/admission time, calls custody and verifies its returned signature. An IMMEDIATE transaction persists the proof only if admission is unchanged and the round remains open. Exact retries return the existing proof without another signing request. Custody failure leaves the accepted contribution available for retry. No private keys/mnemonics are loaded by this API.

Closure requires a proof for every included contribution; unsigned accepted rows are not silently dropped. Snapshot `sentinel-frozen-practice/v2` adds `admission: {challengeSignature,acceptedAt,receiptSignature}` per contribution. Local and portable replay verify challenge, admission and miner signatures before executing fixtures. `acceptedAt` must satisfy `issuedAt <= acceptedAt < expiresAt` and `acceptedAt <= closedAt`.

## Exact signature bytes

`admissionPayload(challenge, artifactSha256, minerSignature, acceptedAt)` returns UTF-8 `sentinel/admission/sr25519/v1\n` plus compact JSON:

```text
[schema,genesis,netuid,round,validator,miner,nonce,issuedAt,expiresAt,artifactSha256,minerSignature,acceptedAt]
```

Schema in the array is `sentinel-challenge/v1`. The receipt binds the exact miner signature, artifact, challenge and coordinator-stated admission time. Times are safe integer Unix milliseconds. A receipt may be signed after expiry only for an already-recorded in-window admission; it is not a new admission. A mutated custody payload cannot bypass verification, which reconstructs the expected bytes. Concurrent receipt attempts retain the first stored valid proof.

This proves key-authenticated coordinator statements, **not independent clock accuracy or historical delivery**. A coordinator controlling its signing key may backdate claims. External witnessing, trusted time, authenticated transport, independent validation and chain finality remain required. Preserve original challenge signatures; do not fabricate evidence of past transmission.

## Upgrade

Stop old writers before upgrading. An additive `admission_proofs` table retains proofs; admission/challenge tables remain intact. Existing open admissions can be attested from their recorded time and retained challenge signature using explicit custody. Closed v1 snapshots remain stored but are refused by v2 replay; retain their earlier-release evidence and select a new qualified round. No silent relabeling/re-signing of old closed evidence. Score targets change with the v2 cohort digest; old quorum certificates cannot approve new snapshot bytes.

Call sequence is now register contract, issue/sign challenge, accept contribution, attest admission, close practice, evaluate/export/replay. No network writes, weights or product promotion introduced.

## Evidence

`bun run check`: **9 tests / 257 assertions**. Tests cover missing receipt at closure, forged challenge, unavailable/wrong signer, concurrent admission mutation with no proof saved, idempotent stored receipt recovery, expired/before-issue admission claims, receipt/challenge signature tampering, missing proof and v1 refusal. Full exported v2 snapshot recalculates successfully in a separate Bun process with the same deterministic score target. Initial bad-signature test exposed a raw crypto-library error; public verification now classifies it as `Invalid sr25519 signature`. No independent clock/validator fleet qualification is claimed.
