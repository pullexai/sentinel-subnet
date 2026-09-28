# Engine contribution envelope v1 (EC-02)

`src/engine-contribution.ts` implements the EC-02 wire contract: media type `application/vnd.sentinel.engine-contribution+json`, discriminator `sentinel-engine-contribution/v1`. It is a library only: no listener, chain query, fetch or artifact execution.

## Canonicalization

`src/jcs.ts` implements RFC 8785 (JCS) without a new dependency: ECMAScript number serialization (`-0` becomes `0`, NaN/Infinity rejected), ECMAScript string escaping, recursive property sort by UTF-16 code units, UTF-8 output, lone surrogates rejected. `parseJson` is a bounded strict parser (fatal UTF-8, no BOM, duplicate keys rejected, including escaped duplicates, depth limit, `__proto__` kept as data). `parseCanonical` additionally requires the received bytes to equal `JCS(value)`, so each value has exactly one accepted encoding: unsorted keys, whitespace, unnecessary escapes, `1.0` and `-0` are rejected.

Vectors: RFC 8785 §3.2.3 sort sample, §3.2.4 byte sample, all Appendix B number samples, plus the six `testdata` input/output pairs copied from the author's reference repository `cyberphone/json-canonicalization` at `19d51d7fe467d4706a3ff08adf8a748f29fc21e0` (Apache-2.0) into `tests/fixtures/jcs/`.

## Envelope

Wire bytes are `JCS({payload, signature})`, with `signature = {scheme:"sr25519", public_key, value}`: 64-hex raw public key, 128-hex signature, lowercase. `public_key` must equal `payload.submitter.hotkey_public_key`. SS58 is not used on this wire.

- Signing bytes: `UTF8("sentinel-engine-contribution/v1\n") || UTF8(JCS(payload))`, signed directly with sr25519 (the SDK's `substrate` signing context), no extra prehash.
- `contribution_id = SHA-256(signing bytes)`; the signature is excluded, so re-signing does not create a new identity.
- Payload fields are exactly those in EC-02. Unknown keys, unknown enums/format IDs/lanes, non-string integers, leading zeros, signs, values above u64 (netuid above 65535, mechanism above 255), RFC 3339 timestamps, invalid digests, unsorted or duplicate set-like arrays, case-colliding or traversal paths, entrypoint/license/origin paths not listed in `artifact.files`, a wrong `files_sha256 = SHA256(JCS(files))`, `replaces_sha256` inconsistent with `operation`, and a training statement on non-model formats are all rejected.
- Order of checks in `verifyContribution(bytes, expectation)`: byte limit and canonical parse, then schema, then signature, then trusted binding (network domain object, window, policy, baseline, validity window using `now`, maximum lifetime and skew as bigint seconds). Registration/lineage from finalized chain state is the caller's next step and is not implemented here.
- `ContributionNonceLedger` records `(network domain, hotkey, nonce) -> contribution_id` in SQLite. Exact replay returns `replay`; a different contribution under the same nonce throws `nonce_conflict`.

Transport authentication (`btauth/1`) is separate and not implemented; an envelope signature proves key control and byte binding only, not authorship, license ownership or benign behavior.

## Legacy formats

The practice lane (`sentinel-contribution/v1`, `sentinel/challenge/sr25519/v1`, `sentinel/admission/sr25519/v1`, score attestations, transcripts) is **legacy practice-only** and unchanged: its signature domains, journals and snapshots remain byte-compatible. Those formats are never accepted as EC-02 envelopes; a legacy signature cannot verify under the EC-02 domain. `canonical()` in `src/attestations.ts` now delegates to `jcs()`, which produces identical bytes for all previously accepted values and additionally rejects lone surrogates.

## Not covered

Registration/lineage verification, origin fetching, policy resolution (EC-01/03), `btauth/1`, attestation/release envelopes (EC-08/12) and cross-language vectors beyond the optional native-Python check in `tests/sr25519.interop.ts` (`SR25519_PYTHON=... bun test ./tests/sr25519.interop.ts`).
