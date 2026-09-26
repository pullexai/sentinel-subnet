# Signed contribution admission v1

`src/protocol.ts` is a Bun library for authenticated **data-only practice contributions**. It verifies possession of canonical SS58-format-42 sr25519 keys, the hotkey primitive used in the Bittensor ecosystem. It is not an Axon/Dendrite wire implementation, chain-membership verifier, weight publisher or active network service.

## Flow

1. An operator provides the genesis hash (64 lowercase hex characters, without `0x`), netuid, validator SS58 address, eligible miner SS58 addresses and positive challenge lifetime in milliseconds. Before admitting contributions, generate independent synthetic seed and random 32-byte salt, retain them privately, and call `practiceContract(seed,salt,pairs)`. Set `scope.round = practiceRound(contract)`. No defaults select a network, seed or economic policy. No customer-derived seed is permitted.
2. Construct `ContributionInbox(privateDirectory, scope, eligibleHotkeys, lifetimeMs)`. Keep its SQLite DB/WAL in a dedicated private directory. It rejects exposed directories and symlink/nonregular DB files. Parents and storage remain operator-trusted. Preserve this storage on restart; deleting/restoring stale storage loses replay history.
3. Call `registerPractice(contract)` before `issue(miner)`. Registration stores only the commitment and public benchmark configuration, not seed/salt. It must match the scope's round hash and cannot occur retroactively once challenges exist. `issue(miner)` persists one random 32-byte nonce per scope/miner before returning. Repeated issue returns the same challenge, including its original expiration. A consumed/expired challenge is not renewed within the round.
4. Validator custody signs `challengePayload(challenge)` with sr25519; send `{challenge, signature}` with lowercase 128-hex signature plus the public practice contract. Miner derives the expected round via `practiceRound(contract)` and calls `verifyChallenge` against its independently expected scope/address, clock and maximum lifetime before signing. A transport adapter must authenticate/rate-limit challenge requests; no listener is shipped.
5. Miner encodes its admitted literal submission as exact UTF-8 `JSON.stringify({schema, rules: rules.map(({id,literal}) => ({id,literal}))})`, without BOM, whitespace or newline. SHA-256 binds these exact bytes. Canonical roundtrip rejects duplicate-key/noncanonical artifacts. Limit: 65,536 bytes and existing rule bounds. No executable artifact is accepted.
6. Miner signs `contributionPayload(challenge, artifactSha256)` and submits `{schema:"sentinel-contribution/v1", challenge, artifactSha256, signature}` plus artifact bytes. Signing remains outside the inbox; no mnemonic, private key file or network wallet is loaded by it.
7. `accept` verifies shape, key possession, eligibility, artifact digest/admission, exact stored challenge and exclusive expiry (`issuedAt <= now < expiresAt`). One SQLite IMMEDIATE transaction consumes the nonce and persists artifact/signature/acceptance time. Invalid requests do not consume it. Concurrent/restarted replay fails. A lost acknowledgement can be reconciled from the operator inbox; identical retries do not get another acceptance.
8. `closePractice(seed,pairs,salt)` verifies the reveal against the pre-admission contract, atomically closes admission and stores a durable snapshot. `evaluatePractice()` then uses only that snapshot, with SS58 addresses as participants, invoking executable-oracle/clone-group/Pareto evaluation. Reports include `commitment` and `reveal` for independent recomputation. Authentication/operator eligibility remain distinct from unverified chain registration. No weight, reward or product promotion occurs.

## Practice commitment bytes

Inputs `seed` and `salt` are each exactly 64 lowercase hex characters. Use an independently random salt; the library validates its shape, not entropy. Commitment is SHA-256 over UTF-8 `sentinel/practice-reveal/v1\n` followed by compact JSON `[seed,salt,pairs]`. Public contract is exactly `{schema:"sentinel-practice-contract/v1",commitment,pairs,generator:"sentinel-corpus/v1",baseline,scorer:"sentinel-pareto/v1"}`, where baseline is the current reference execution identity. Round is SHA-256 over `sentinel/practice-contract/v1\n` followed by compact JSON `[schema,commitment,pairs,generator,baseline,scorer]`. The existing signature already covers round, so it binds miner and validator signatures to this contract without changing signature domains.

Unknown fields, invalid bounds and incompatible baseline/generator/scorer are refused. Seed, salt and pair substitutions cannot close an existing round. Contract registration and challenge creation use serialized transactions; restart retains the same commitment. A failed reveal leaves admission open. After closure both snapshot and report expose seed/salt; this is auditability for public-template practice, not secrecy or independent holdouts. An operator can still abandon rounds, preselect favorable benchmarks or fork its own DB; external witnessing, fixed cohort schedules, independent benchmark ownership and multi-validator agreement remain necessary.

## Durable practice closure

Closure takes the same SQLite IMMEDIATE write transaction as admission. Whichever commits first determines whether a pending contribution is included. Once closed, `issue` and `accept` refuse the scope on every connection/restart, including requests signed before closure. Identical closure retries return the same receipt; a changed seed, pair count or current eligible-hotkey set conflicts. Eligible-key ordering and JavaScript scope-property ordering do not change identity. An empty or oversized cohort fails closure and stays open; no fallback weights or automatic next round are invented.

The snapshot stores scope, sorted eligible list, closing timestamp, exact contribution signatures/challenges/artifact digests/canonical artifacts, practice seed/pair count, generator/scorer version, complete generated-fixture digest and baseline execution identity. Its exact JSON bytes are SHA-256 bound; report `cohortSha256` identifies this snapshot, separate from the older execution-group `comparisonId`. The snapshot remains usable if operational challenge rows are unavailable. Evaluation rechecks snapshot digest, fixture/baseline compatibility, exact artifact digest and miner signatures before running the public fixtures. Eligibility changes after closure fail rather than silently producing a different ranking: reconcile them through a separately selected round. No automated round rotation or policy is supplied.

Evaluation after restart recomputes scores and preserves deterministic comparison fields and Pareto tiers. Resource observations are intentionally measured anew. A crash during evaluation leaves the closure available for replay; no score is published by this library. Caller must keep the scorer version synchronized with semantic scorer changes; version labels are not reproducible-build attestations. Snapshot integrity protects accidental alteration, not an operator who can replace both DB contents and hashes. Validator-signed quorum receipts and multi-host finalization remain open.

Compatibility: the inbox creates additive `frozen_practice` and `practice_contracts` tables; existing rows remain intact. Stop older writers before upgrading: earlier code ignores the new gates. Callers now derive round from `practiceContract`, register it before challenges and pass salt to `closePractice(seed,pairs,salt)`, then call `evaluatePractice()`. Previously admitted uncommitted rounds cannot be retroactively committed or evaluated by this path; retain their evidence under the earlier release, label it uncommitted practice and select a new committed round. No old contribution is silently relabeled as committed.

## Signature bytes

Both payload functions return UTF-8 with no trailing newline. Challenge domain prefix is `sentinel/challenge/sr25519/v1\n`; contribution prefix is `sentinel/contribution/sr25519/v1\n`. Both append compact JSON arrays with this fixed order:

```text
[schema, genesis, netuid, round, validator, miner, nonce, issuedAt, expiresAt]
```

Contribution appends `artifactSha256` as the final array item. `schema` inside that array is `sentinel-challenge/v1`. Timestamps are nonnegative safe integer Unix milliseconds. Signature is raw sr25519 (Substrate signing context supplied by the crypto library), not wrapped `<Bytes>` text, Ed25519, a multi-signature discriminator or a transaction signature. Cross-role/domain/network/round/validator/miner substitution fails. Only canonical SS58 42 strings are accepted, preventing alternate address encodings from splitting replay identity.

## Verification and dependencies

Public registry `latest` for `@polkadot/util-crypto` checked before installation: **14.0.3**, pinned exactly; transitives resolved by `bun.lock`. It supplies established sr25519/SS58 cryptography missing from Bun/Node crypto. Application and tests run on Bun 1.4.2. Dependency license Apache-2.0; retain dependency LICENSE/NOTICE files when distributing it. This repository's original source stays MIT. This increment does not constitute a full transitive SBOM/license audit.

`bun run check`: 7 tests, 173 assertions. Protocol tests exercise real randomized sr25519 signatures, both domain signatures, scope/timestamp/address/expiry mismatch, artifact tampering, duplicate JSON fields, invalid signatures, concurrent consumption, reopen/replay, eligible-list removal and signed-candidate scoring against executable public fixtures. Closure tests cover no evaluation before closure, empty-cohort refusal, closure-versus-pending-admission, two-connection idempotence, late issue/submission denial, contract/eligibility conflict, reordered reopen inputs, restart score equality, retained snapshot independence and tamper refusal. Commitment checks cover pre-issue registration, same-contract replay, unknown fields, invalid inputs, seed/salt/pair conflict, no seed/salt persistence before reveal, refusal to commit existing challenge rows retroactively and report-to-signed-round recomputation.

Optional independent implementation check:

```sh
python3 -m venv /private/test-sr25519
/private/test-sr25519/bin/pip install py-sr25519-bindings==0.2.4
SR25519_PYTHON=/private/test-sr25519/bin/python bun test ./tests/sr25519.interop.ts
```

Ran successfully: native Python verifies a Bun signature, Bun verifies an independently generated Python signature (2 assertions). Python is only an optional crypto interoperability oracle, not an application/runtime dependency. No real account key, chain RPC or transaction used.

## Remaining boundaries

Hotkey possession is not current subnet registration, validator permit, stake, independence or Sybil resistance. Eligibility is an operator list frozen per inbox instance; reconstruct it to apply removals before closure, or select a separately reconciled round afterward. Chain snapshot/finality binding, metagraph discovery, SDK wire adapters, signed score reconciliation, custody, challenge transport, DoS admission quotas, durable-storage recovery/retention, multi-host consensus and independent hidden evaluation remain unimplemented. Scope/round values are explicit caller inputs, not on-chain receipts. The scoring seed is still public-template practice. External eligibility provenance and multi-validator cohort finalization must be qualified before network use.

Never place customer source or any derivative in this inbox. Submission signatures authenticate their signer; they do not prove independent synthetic provenance or safety. The private product imports only independently manually approved signed releases through its separate trust roots.
