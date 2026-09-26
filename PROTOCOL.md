# Signed contribution admission v1

`src/protocol.ts` is a Bun library for authenticated **data-only practice contributions**. It verifies possession of canonical SS58-format-42 sr25519 keys, the hotkey primitive used in the Bittensor ecosystem. It is not an Axon/Dendrite wire implementation, chain-membership verifier, weight publisher or active network service.

## Flow

1. An operator provides the genesis hash (64 lowercase hex characters, without `0x`), netuid, round digest, validator SS58 address, eligible miner SS58 addresses and positive challenge lifetime in milliseconds. No defaults select a network, round or economic policy. Round digest must identify an independently frozen competition contract; this library does not prove that provenance.
2. Construct `ContributionInbox(privateDirectory, scope, eligibleHotkeys, lifetimeMs)`. Keep its SQLite DB/WAL in a dedicated private directory. It rejects exposed directories and symlink/nonregular DB files. Parents and storage remain operator-trusted. Preserve this storage on restart; deleting/restoring stale storage loses replay history.
3. `issue(miner)` persists one random 32-byte nonce per scope/miner before returning. Repeated issue returns the same challenge, including its original expiration. A consumed/expired challenge is not renewed within the round.
4. Validator custody signs `challengePayload(challenge)` with sr25519; send `{challenge, signature}` with lowercase 128-hex signature. Miner calls `verifyChallenge` against its independently expected scope/address, clock and maximum lifetime before signing. A transport adapter must authenticate/rate-limit challenge requests; no listener is shipped.
5. Miner encodes its admitted literal submission as exact UTF-8 `JSON.stringify({schema, rules: rules.map(({id,literal}) => ({id,literal}))})`, without BOM, whitespace or newline. SHA-256 binds these exact bytes. Canonical roundtrip rejects duplicate-key/noncanonical artifacts. Limit: 65,536 bytes and existing rule bounds. No executable artifact is accepted.
6. Miner signs `contributionPayload(challenge, artifactSha256)` and submits `{schema:"sentinel-contribution/v1", challenge, artifactSha256, signature}` plus artifact bytes. Signing remains outside the inbox; no mnemonic, private key file or network wallet is loaded by it.
7. `accept` verifies shape, key possession, eligibility, artifact digest/admission, exact stored challenge and exclusive expiry (`issuedAt <= now < expiresAt`). One SQLite IMMEDIATE transaction consumes the nonce and persists artifact/signature/acceptance time. Invalid requests do not consume it. Concurrent/restarted replay fails. A lost acknowledgement can be reconciled from the operator inbox; identical retries do not get another acceptance.
8. `evaluatePractice(seed,pairs)` freezes current accepted candidates, uses SS58 addresses as participants and invokes existing executable-oracle/clone-group/Pareto evaluation. Its report labels authentication and operator-supplied eligibility separately from unverified chain registration. No weight, reward or product promotion occurs.

## Signature bytes

Both payload functions return UTF-8 with no trailing newline. Challenge domain prefix is `sentinel/challenge/sr25519/v1\n`; contribution prefix is `sentinel/contribution/sr25519/v1\n`. Both append compact JSON arrays with this fixed order:

```text
[schema, genesis, netuid, round, validator, miner, nonce, issuedAt, expiresAt]
```

Contribution appends `artifactSha256` as the final array item. `schema` inside that array is `sentinel-challenge/v1`. Timestamps are nonnegative safe integer Unix milliseconds. Signature is raw sr25519 (Substrate signing context supplied by the crypto library), not wrapped `<Bytes>` text, Ed25519, a multi-signature discriminator or a transaction signature. Cross-role/domain/network/round/validator/miner substitution fails. Only canonical SS58 42 strings are accepted, preventing alternate address encodings from splitting replay identity.

## Verification and dependencies

Public registry `latest` for `@polkadot/util-crypto` checked before installation: **14.0.3**, pinned exactly; transitives resolved by `bun.lock`. It supplies established sr25519/SS58 cryptography missing from Bun/Node crypto. Application and tests run on Bun 1.4.2. Dependency license Apache-2.0; retain dependency LICENSE/NOTICE files when distributing it. This repository's original source stays MIT. This increment does not constitute a full transitive SBOM/license audit.

`bun run check`: 6 tests, 140 assertions. Protocol tests exercise real randomized sr25519 signatures, both domain signatures, scope/timestamp/address/expiry mismatch, artifact tampering, duplicate JSON fields, invalid signatures, concurrent consumption, reopen/replay, eligible-list removal and signed-candidate scoring against executable public fixtures.

Optional independent implementation check:

```sh
python3 -m venv /private/test-sr25519
/private/test-sr25519/bin/pip install py-sr25519-bindings==0.2.4
SR25519_PYTHON=/private/test-sr25519/bin/python bun test ./tests/sr25519.interop.ts
```

Ran successfully: native Python verifies a Bun signature, Bun verifies an independently generated Python signature (2 assertions). Python is only an optional crypto interoperability oracle, not an application/runtime dependency. No real account key, chain RPC or transaction used.

## Remaining boundaries

Hotkey possession is not current subnet registration, validator permit, stake, independence or Sybil resistance. Eligibility is an operator list frozen per inbox instance; reconstruct it to apply removals. Chain snapshot/finality binding, metagraph discovery, SDK wire adapters, signed score reconciliation, custody, challenge transport, DoS admission quotas, durable-storage recovery/retention, multi-host consensus and independent hidden evaluation remain unimplemented. Scope/round values are explicit caller inputs, not on-chain receipts. The scoring seed is still public-template practice. External eligibility provenance and cohort finalization must be qualified before network use.

Never place customer source or any derivative in this inbox. Submission signatures authenticate their signer; they do not prove independent synthetic provenance or safety. The private product imports only independently manually approved signed releases through its separate trust roots.
