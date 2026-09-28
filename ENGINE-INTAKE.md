# Engine contribution intake, local part (EC-03)

`src/engine-intake.ts` (`bun run engine:intake serve|work CONFIG`) implements the local, network-free part of EC-03 on top of the EC-02 envelope (`src/engine-contribution.ts`) and the sealed holdout (`src/holdout.ts`). It listens on `127.0.0.1` only. No chain, wallet, btauth or customer data is involved.

## Processes

1. **Intake** (`serve`): `Bun.serve` with a 256 KiB body ceiling (413), a per-request body deadline (408), and `Content-Type: application/vnd.sentinel.engine-contribution+json` (415).
2. **Worker** (`work`): trusted process that opens the sealed holdout bank, fetches and seals artifacts, runs the artifact in a sandbox and records the outcome.
3. **Sandbox**: a separate `bwrap` process (`--unshare-all`, uid 65534, all capabilities dropped, empty environment) that sees only the Bun binary, system libraries, the adapter code (`src/engine-sandbox.ts`) and the sealed artifact read-only. `sentinel-engine-case/v1` bundles arrive on stdin; gold, oracles, lineage labels, the bank file, the SQLite queue and the receipt key are not mounted. Wall-clock timeout and stdout size are bounded; a violation consumes the attempt and yields a report with no score.

## Order of checks (`EngineStore.submit`)

Bounded canonical JCS parse and EC-02 schema, then sr25519 signature, then lookup of an existing receipt (an exact replay returns the identical receipt bytes, even after expiry), then trusted binding (network domain, window, policy, baseline, validity window), then policy resolution and registration, then one immediate SQLite transaction that writes nonce, receipt, attempt counters and queue entry together. The same nonce with another contribution ID is `409 nonce_conflict`. Attempt quotas are counted per EC-10 execution-content identity (`contentId`: format, files, entrypoint, components, change, capabilities, profiles; not nonce or time) and per hotkey, so a fresh nonce does not reset them (`429`).

## Receipts

`sentinel-engine-receipt/v1` = `{schema, contribution_id, hotkey, nonce, state, reason, unverified}` signed with Ed25519 over `UTF8("sentinel-engine-receipt/v1\n") || JCS(payload)`, wrapped as `{payload, signature:{scheme:"ed25519", key_id, value}}` where `key_id` is SHA-256 of the SPKI DER. Receipts are derived from durable state only, so they are byte-identical across restarts. They never contain scores, per-case errors or timing. States: `received`, `admitted`, `rejected`, `policy_unresolved`. Only queued entries reserve an attempt.

## Queue

Leases carry a random token and expiry. A crash leaves the entry leased; after expiry it is re-leased, counting `infra_retries`, never a miner attempt. Completion is fenced by the token, so a stale worker cannot write a second outcome.

## Fetcher

Only manifest-listed files, each mapped by `origins` to an operator-approved `origin_id`. Revisions must be full 40 or 64 hex commit IDs. Base URLs must be HTTPS without credentials, query or fragment. The host is resolved once, every address is checked against a deny list (loopback, private, link-local, CGNAT, multicast, reserved, NAT64/6to4, IPv4-mapped), and the connection is pinned to the checked address (no rebinding window). Every non-200 response, including redirects, fails. Length is checked against the declared `bytes` before and while buffering, SHA-256 is computed while streaming, and files are written exclusively (`wx`, mode 0444) into a per-contribution directory that is then made read-only. Before execution the sealed set is listed and re-hashed; an extra or changed file fails. `insecure_loopback_origins` exists only for tests.

## Holdout and lineage

The worker verifies the owner's commitment and opens the bank with `admitHoldoutBank`, which rejects lineages that span families, missing defective/clean polarity and public-template families, and proves every oracle before use. Each holdout case is converted by the trusted worker into a `sentinel-engine-case/v1` bundle (below) keyed with the bank salt; gold stays in the worker. Scoring is the EC-05 retrieval oracle below; `weights` and `rewards` are always `null`. Reports are stored in `engine_evaluations` with `report_sha256 = SHA-256("sentinel-engine-evaluation/v1\n" || JCS(report))`.

## Explicitly `unverified`

Every receipt and report lists these; none is simulated as passed:

- `finalized_registration_lineage`: no finalized chain query. `registration: null` keeps contributions `received`; `local_allowlist` is an operator stand-in.
- `btauth_transport`: no transport authentication.
- `signed_engine_policy`: no `sentinel-engine-policy/v1` resolution. Unset `limits`, `origins` or `holdout` yields `policy_unresolved`; `GET /engine/v1/policies/{sha256}` answers `policy_unresolved`.
- `independent_operators`: one local operator holds holdout, queue and receipt key.
- `execution_profile_qualification`: bubblewrap is a local isolation layer, not a qualified EX profile (no cgroup memory/CPU limits here).

`GET /engine/v1/windows/{id}/replay` always answers `{state:"unavailable"}` (EC-08/11 not implemented).

## Evaluation input: `sentinel-engine-case/v1` (EC-03)

`src/engine-case.ts`. A bundle is `{case, file_table, blobs}`; the artifact sees nothing else.

- `case` has exactly `{case_input_id, repository_family_commitment, base_tree_sha256, head_tree_sha256, file_table_sha256, task, query, allowed_context_sha256, build_profile_sha256}`. `task` is one of `detection|retrieval|fix|test`. `query` is `{text, changed_file_ids}`: fixed synthetic task text (at most 2048 characters, no control characters) and the sorted opaque IDs of head files whose content differs from base. It never carries expected answers or evidence IDs.
- `file_table` entries are `{file_id, revision, path_bytes_hex, path_encoding, content_sha256, bytes, language}`, sorted by `JCS([revision, file_id])` without duplicates. Paths are raw bytes (hex, no NUL, at most 1024 bytes) with `utf-8` (validated) or `opaque` encoding, so repository names are not forced into the manifest grammar. One `file_id` denotes one path across revisions; each revision has unique paths.
- Base and head are complete snapshots: unchanged files appear in both, so they stay addressable. `*_tree_sha256 = SHA-256("sentinel-engine-tree/v1\n" || JCS(entries sorted by path bytes, without file_id/revision))`; `file_table_sha256 = SHA-256("sentinel-engine-file-table/v1\n" || JCS(file_table))`; `allowed_context_sha256` binds the sorted set of file IDs; `case_input_id = SHA-256("sentinel-engine-case/v1\n" || JCS(case without case_input_id))`.
- `blobs` are `{content_sha256, base64}`, sorted, exactly the referenced digests, each re-hashed and length-checked. Bounds: 1000 entries, 1 MiB per file, 8 MiB per case.
- `build_profile_sha256` is the fixed `none` profile: no build runs in v1. `repository_family_commitment` is a salted commitment to the lineage, not the family label.

The practice `sentinel-practice-input/v1` remains the **legacy** input for the practice lane (`competition.ts`, `holdout.ts`); the EC-03 sandbox no longer accepts it or `sentinel-literal-miner/v1`.

## Formats (EC-04..EC-07)

| Format | Status | Reason |
|---|---|---|
| `retrieval-profile/v1` (EC-05), lexical subset | implemented end to end | pure data, trusted operators, no external engine |
| `retrieval-profile/v1` with `embedding_component_sha256` ≠ null, `embedding_rank` or `resolved_symbol_neighbors` | `unqualified-engine` | needs a qualified embedding model or symbol resolver |
| `structural-rule/v1` (EC-04) | `unqualified-engine` | needs a qualified ast-grep engine and grammars |
| `taint-rule/v1` (EC-04) | `unqualified-engine` | needs a qualified Opengrep analysis profile |
| `tensor-model/v1`, `lora-adapter/v1` (EC-06) | `unqualified-engine` | need a qualified model runtime/ABI |
| `fix-template/v1` (EC-07) | `unqualified-engine` | needs a qualified structural matcher and `challenge-fix-test/v1` profile |

`unqualified-engine` formats are rejected by the worker without fetching or executing anything; the stored report carries the reason. None is simulated.

### `retrieval-profile/v1` (lexical subset)

`src/engine-retrieval.ts`. Entrypoint `{schema, chunker_component_sha256, index_schema_sha256, embedding_component_sha256, stages, output_limit_ref}` parsed with the strict bounded parser (64 KiB, depth 16, duplicate keys rejected). Component digests must equal the registry descriptors (`sentinel-line-chunker/v1`: 20-line head chunks; `sentinel-lexical-index/v1`: ASCII identifier tokens, lower-cased, length ≥ 2; `sentinel-context-envelope/v1`: at most 16 ranges and 16384 bytes). `stages` is ordered, 2..8 entries:

- `lexical_bm25 {query_source: query_text|changed_files, k1, b, top_k}`; `k1 ∈ [0,10]`, `b ∈ [0,1]` as reduced rationals, `top_k` 1..1000. Two or more require `fuse_rrf`.
- `fuse_rrf {k}` sums exact `1/(k+rank)`, ranks from 1.
- `deduplicate {}` drops ranges overlapping an earlier range in the same file.
- `pack_context {max_ranges}` last; stops at the envelope.

Unknown operators or parameters fail admission (`artifact_invalid`). Scores are integers: BM25 uses a fixed-point `log2` with 32 fractional bits and floor division, so outputs are identical across hosts. Ties break by `(revision, file_id, start_byte, end_byte)`. A head file that is not valid UTF-8 is skipped and the output says `coverage: partial`.

Output is the retrieval branch of `sentinel-engine-output/v1`: exactly `{case_input_id, status, coverage, retrieval}`, `retrieval = [{file_id, revision, start_byte, end_byte, rank}]`. The worker revalidates every output against the verified file table: known file and revision, half-open byte range within length, ranks 1..n, no overlap, envelope bounds, no extra fields (for example `findings`). Any violation is `sandbox_output_invalid`.

Oracle (worker only): required evidence for a defective case is the byte span where the head file differs from its independently corrected version, both proven by the executable fixture oracle; clean cases require none. Report fields per side: `required, covered, missed, ranges, relevant_ranges, packed_bytes, partial`, plus `evidence_recall` and `range_precision` as `{numerator, denominator}` or `null`, and `regressed` (cases the fixed lexical baseline covered and the candidate did not). A missing output is a miss. Downstream detection gain (EC-05 requires it) is not measured: no detector consumes the context yet.

## Tests

`tests/engine-intake.test.ts` runs intake and worker as separate processes: size, timeout, media type, invalid envelope, tampered signature, replay, nonce conflict, content quota, wrong hash, redirect, fetch timeout, restart with byte-identical receipts, no re-evaluation, crash lease recovery with stale-worker fencing, a hostile artifact that tries to read the bank, database, receipt key, `/etc/passwd` and source, write the artifact, open a socket, hang and flood stdout, and `unqualified-engine`/`artifact_invalid` rejections. `tests/engine-case.test.ts` covers case tampering (digests, order, NUL paths, invalid UTF-8, forged blobs, dropped unchanged base files, reused file IDs), profile admission, exact determinism, output revalidation, the oracle, and hostile profiles and bundles through the sandbox process.
