# Read-only chain identity observer

`observe.py` uses official Bittensor SDK v11 native SCALE decoding. It reads one finalized block, verifies explicit operator policy, then emits an observation plus SHA-256. No keys, wallet loading, signatures, extrinsics, weights or reward actions. An observed subnet is **not** evidence of Sentinel registration or economic permission.

## Isolated runtime

Python 3.12.14 is a deliberate exception to this repository's Bun implementation: the official SDK supplies runtime metadata and native storage decoding. Reimplementing SCALE in TypeScript would create an additional consensus-sensitive decoder. Python stays in this optional observer; the existing practice protocol remains Bun-only.

```sh
uv venv --python 3.12.14 /tmp/opencode/sentinel-bittensor
uv pip sync --python /tmp/opencode/sentinel-bittensor/bin/python --require-hashes chain/requirements.lock
/tmp/opencode/sentinel-bittensor/bin/python -B chain/check.py
```

The lock contains all 33 installed distributions with exact versions and artifact hashes, including `bittensor==11.1.0`, `bittensor-core==0.1.3`, and `websockets==16.1.1`. These SDK versions were verified against PyPI stable releases during qualification. Refresh deliberately using `uv pip compile chain/requirements.in --python 3.12.14 --generate-hashes --no-header --no-annotate --output-file chain/requirements.lock`; rerun qualification after changes. Hash locking is dependency integrity, not a supply-chain audit.

## Private operator policy

Keep endpoint selection, policy and observations outside this public repository. Never provide product/customer files. The endpoint is a required **trusted operator CLI argument**, not a contribution field; only TLS WebSocket or plaintext numeric loopback endpoints are accepted. Credentials, URL queries/fragments, paths and implicit/default endpoints are refused. Endpoint host authorization belongs to the invoking operator; do not expose this CLI as an untrusted URL-fetch service.

Stdin must be exactly one JSON object with these fields:

| Field | Value |
| --- | --- |
| `genesis` | Expected lowercase 64-hex genesis hash, without `0x` |
| `netuid` | Integer 0–65535 |
| `creationHeight`, `creationHash` | Expected subnet creation height and lowercase 64-hex block hash |
| `owner`, `ownerHotkey` | Expected current subnet coldkey/hotkey SS58 strings |
| `runtime` | Exact expected runtime `specVersion` |
| `metadataSha256` | SHA-256 of raw runtime metadata bytes, lowercase 64-hex |
| `hotkeys` | 1–100 distinct SS58 hotkeys to observe |
| `validator` | One listed hotkey requiring a current validator permit |

Unknown/duplicate fields, boolean integers and oversized input are refused. Input ceiling: 64 KiB. CLI Linux process deadline: 60 seconds including stdin; async observation deadline: 45 seconds. RPC metadata response ceiling: 16 MiB. Errors return nonzero without emitting a successful observation or private provider error text.

```sh
umask 077
/tmp/opencode/sentinel-bittensor/bin/python -B chain/observe.py \
  --endpoint "$OPERATOR_RPC" < "$PRIVATE_POLICY" > "$PRIVATE_OBSERVATION"
```

Policy must be approved separately; do not auto-approve whatever an endpoint reports. Output `sha256` covers the `observation` object serialized as UTF-8, sorted keys recursively, compact separators, no newline. The envelope digest is an integrity identifier, not a signature or independent verification.

## Identity bound

All storage queries use the same finalized block hash: `NetworksAdded`, `NetworkRegisteredAt`, `SubnetOwner`, `SubnetOwnerHotkey`, `SubnetworkN`, `Uids`, `Keys`, `BlockAtRegistration`, `Owner`, `ValidatorPermit`. Bidirectional hotkey/UID binding prevents absent-key default confusion; UID uniqueness, registration bounds and validator permit are enforced. Creation and registration heights are resolved to block hashes.

The pinned SDK transport profile replaces the SDK connection factory and runtime manager, retaining its native codec and storage APIs. Both preliminary and SDK connections reject every HTTP redirect, disable ambient proxies, cap received messages at 16 MiB and use explicit timeouts. The SDK connection has zero reconnect retries and no fallbacks. Unsupported installed SDK/core/websockets versions fail closed. This deliberately depends on v11.1.0 private SDK interfaces; SDK upgrades require review and requalification.

The actual decoder loads fresh metadata over its own SDK session, checks genesis, compares finalized-block and parent runtime versions **and metadata bytes**, checks the approved metadata digest, then passes those exact bytes into the SDK native codec. It bypasses SDK disk metadata caches and speculative head codecs. Upgrade boundaries fail closed rather than decoding using a different parent's runtime. No SCALE decoder is reimplemented. Independent RPC truth/finality is still not established.

Owner values describe state **at the observed finalized block**, not necessarily ownership at creation. Historical creation-state proof is not attempted; the local node prunes old state. Genesis plus creation height/hash protects against ordinary netuid reuse. Same-block destruction/recreation, dishonest RPC, runtime semantic changes and independent finality verification require additional operator qualification. The node's finalized-head statement is trusted; this is not a light client or storage-proof verifier.

## Admission integration boundary

`ContributionInbox.chainQualified(directory, {bytes, policy, approval}, lifetimeMs, clock)` verifies the Python envelope before opening admission. Import types and `chainDigest` from `src/chain-admission.ts`. `bytes` is the exact observer stdout, with an optional trailing newline. Duplicate JSON keys, noncanonical encoding and inputs over 128 KiB are refused.

`policy` contains `{scope, eligible, creationHeight, creationHash, owner, ownerHotkey, runtime, metadataSha256}`. `scope` is the existing `{genesis, netuid, round, validator}`; `round` must still match the committed practice contract. `eligible` is the independently approved miner list, not the received members list. Every approved miner must have an observed registration; the scope validator must have an observed registration and validator permit. This validates observed identity, not economic eligibility.

`approval` contains `{snapshotSha256, policySha256, observedAt, maxAgeMs, finalizedHeight, finalizedHash}`. Obtain it through a separate trusted operator channel. `snapshotSha256` pins the canonical observation, `policySha256` pins `chainDigest(policy)`, and finalized height/hash must match exactly. Never populate expected digests from an untrusted envelope. `observedAt` is the operator-approved local observation time in Unix milliseconds, not a claimed chain timestamp. `maxAgeMs` must be positive; admission refuses clock rollback before `observedAt` and expires when age reaches the maximum. The approval is rechecked on challenge issue, contribution acceptance, receipt attestation and practice mutations, including after asynchronous signing. No independent clock accuracy or finality proof is implied.

An additive SQLite `chain_bindings` table stores the exact approved policy and approval per round scope in an IMMEDIATE transaction. Reopening requires identical binding. Legacy handles check the binding before mutation, so a handle opened before qualification cannot bypass it. Existing legacy rounds with contracts, challenges or frozen state cannot be retroactively qualified. Expired approvals require a new round; this increment has no in-place approval refresh. Stop older library writers before upgrading: older binaries do not enforce the new table.

The original `new ContributionInbox(...)` remains explicitly **legacy, unqualified operator-list practice**. It cannot reopen a chain-bound scope. Legacy snapshots retain `sentinel-frozen-practice/v2`. Chain-bound snapshots use **`sentinel-frozen-practice/v3`**, adding `chain: {policy, approval, observation}`; `observation` is the exact accepted observer envelope string. These bytes enter the cohort SHA-256 and therefore the score-attestation target.

Portable replay requires separate trusted expectations `{cohortSha256, scope, eligible, chain: {policy, approval}}` for v3. The chain policy and approval must match the external expectations exactly; the verifier checks observation digest, policy digest, incarnation/owners/runtime, finalized height/hash and participant registrations. Freshness is checked at recorded issuance, acceptance and closure times, not the later replay wall clock. Admission times remain coordinator-signed claims, not independent timestamps. A v3 snapshot without chain expectations is rejected; a v2 snapshot with chain expectations is rejected. Removing, replacing or relabeling evidence cannot satisfy the original external digest and chain expectations.

`bun src/replay.ts <snapshot.json> <trusted-expectations.json>` supports both schemas. Keep expectations independent of the received snapshot; copying its assertions into expectations defeats operator approval. Legacy replay reports `legacy-operator-supplied-hotkey-list`; v3 reports `operator-approved-rpc-observed-registration`, never economic eligibility or independent consensus verification.

Migration: pre-publication chain bindings that omitted `observation` cannot reopen under this binding format. Retain old evidence; use a new practice round. Existing v2 legacy snapshots and operator-list rounds remain v2. No retroactive qualification or v2-to-v3 relabeling is supported. Stop old writers before upgrading.

Remaining gates: independently witnessed observation provenance/finality; external revocation/refresh policy; authenticated transport; independently operated validators. Registration, network activation and economic execution remain separate work.

## Qualification evidence

Offline `chain/check.py` covers malformed policy/URLs, duplicates, absent subnet/UID, boolean UID, UID range/reverse mismatch, incarnation/owner mismatch, invalid registration heights, missing permit/owner, and genesis/runtime/metadata/creation-hash mismatch. These fixtures are **not real chain qualification**.

Real SDK read-only check passed against the already-running unrelated local chain at finalized height **547002**, runtime **424**, netuid **2**. CLI passed at height **547007**; observation digest `632d88a1238403de45ebe769b332a867cc7ee446d86b2500481a0d8ea92f2eb0`. One existing member, UID 0, registration height 93, validator permit true. No container lifecycle or chain mutation commands were issued. These are local compatibility observations, not Sentinel registration or production readiness. Private policy/observation files are not committed.

Repeat against an explicitly authorized node:

```sh
/tmp/opencode/sentinel-bittensor/bin/python -B chain/check.py \
  --endpoint "$OPERATOR_RPC" < "$PRIVATE_POLICY"
```

Bun integration qualification: actual Python observer stdout passed `verifyChainAdmission` at local finalized height **547901**, digest `be4b42b7b6bed2d94049c2bd325669a216a92caa0a5c95f04d1b28a5bd9e4dfe`. The harness separately supplied expected policy, digest, observation time and finalized identity; this demonstrates cross-language compatibility, not independent operator governance. `bun run check`: **10 tests / 282 assertions**, including adversarial digest, scope/incarnation/owner, UID, permit, registration bounds, freshness, restart binding and legacy downgrade/retroactive qualification rejection.

Subsequent hardening: actual pinned-decoder SDK read passed at finalized height **548809**. Local HTTP redirect servers verified both connection paths refuse redirection without reaching the target. Decoder fixtures reject parent-runtime and metadata-digest mismatches. Portable v3 evidence tamper/removal/replacement, downgrade and independent-process replay checks pass. Overall check including the asynchronous candidate-mutation regression: **11 tests / 296 assertions**. Earlier observer checks predate transport/decoder hardening and are not evidence for those protections.

Independent follow-up confirmed the three decoder/redirect/response-bound findings closed and reran offline transport controls. Final Bun check: **11 tests / 299 assertions**, including nested candidate mutation and exported baseline mutation while oracle execution is pending; baseline scoring and comparison identity remain bound to the original data. No production or public-network request was performed by these checks.
