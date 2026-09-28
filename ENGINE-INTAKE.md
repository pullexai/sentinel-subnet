# Engine contribution intake, local part (EC-03)

`src/engine-intake.ts` (`bun run engine:intake serve|work CONFIG`) implements the local, network-free part of EC-03 on top of the EC-02 envelope (`src/engine-contribution.ts`) and the sealed holdout (`src/holdout.ts`). It listens on `127.0.0.1` only. No chain, wallet, btauth or customer data is involved.

## Processes

1. **Intake** (`serve`): `Bun.serve` with a 256 KiB body ceiling (413), a per-request body deadline (408), and `Content-Type: application/vnd.sentinel.engine-contribution+json` (415).
2. **Worker** (`work`): trusted process that opens the sealed holdout bank, fetches and seals artifacts, runs the artifact in a sandbox and records the outcome.
3. **Sandbox**: a separate `bwrap` process (`--unshare-all`, uid 65534, all capabilities dropped, empty environment) that sees only the Bun binary, system libraries, the adapter code (`src/engine-sandbox.ts`) and the sealed artifact read-only. Case inputs arrive on stdin; gold, oracles, lineage labels, the bank file, the SQLite queue and the receipt key are not mounted. Wall-clock timeout and stdout size are bounded; a violation consumes the attempt and yields a report with no score.

## Order of checks (`EngineStore.submit`)

Bounded canonical JCS parse and EC-02 schema, then sr25519 signature, then lookup of an existing receipt (an exact replay returns the identical receipt bytes, even after expiry), then trusted binding (network domain, window, policy, baseline, validity window), then policy resolution and registration, then one immediate SQLite transaction that writes nonce, receipt, attempt counters and queue entry together. The same nonce with another contribution ID is `409 nonce_conflict`. Attempt quotas are counted per EC-10 execution-content identity (`contentId`: format, files, entrypoint, components, change, capabilities, profiles; not nonce or time) and per hotkey, so a fresh nonce does not reset them (`429`).

## Receipts

`sentinel-engine-receipt/v1` = `{schema, contribution_id, hotkey, nonce, state, reason, unverified}` signed with Ed25519 over `UTF8("sentinel-engine-receipt/v1\n") || JCS(payload)`, wrapped as `{payload, signature:{scheme:"ed25519", key_id, value}}` where `key_id` is SHA-256 of the SPKI DER. Receipts are derived from durable state only, so they are byte-identical across restarts. They never contain scores, per-case errors or timing. States: `received`, `admitted`, `rejected`, `policy_unresolved`. Only queued entries reserve an attempt.

## Queue

Leases carry a random token and expiry. A crash leaves the entry leased; after expiry it is re-leased, counting `infra_retries`, never a miner attempt. Completion is fenced by the token, so a stale worker cannot write a second outcome.

## Fetcher

Only manifest-listed files, each mapped by `origins` to an operator-approved `origin_id`. Revisions must be full 40 or 64 hex commit IDs. Base URLs must be HTTPS without credentials, query or fragment. The host is resolved once, every address is checked against a deny list (loopback, private, link-local, CGNAT, multicast, reserved, NAT64/6to4, IPv4-mapped), and the connection is pinned to the checked address (no rebinding window). Every non-200 response, including redirects, fails. Length is checked against the declared `bytes` before and while buffering, SHA-256 is computed while streaming, and files are written exclusively (`wx`, mode 0444) into a per-contribution directory that is then made read-only. Before execution the sealed set is listed and re-hashed; an extra or changed file fails. `insecure_loopback_origins` exists only for tests.

## Holdout and lineage

The worker verifies the owner's commitment and opens the bank with `admitHoldoutBank`, which rejects lineages that span families, missing defective/clean polarity and public-template families, and proves every oracle before use. Scoring reuses `compare` against the reference baseline; `weights` and `rewards` are always `null`. Reports are stored in `engine_evaluations` with `report_sha256 = SHA-256("sentinel-engine-evaluation/v1\n" || JCS(report))`.

## Explicitly `unverified`

Every receipt and report lists these; none is simulated as passed:

- `finalized_registration_lineage`: no finalized chain query. `registration: null` keeps contributions `received`; `local_allowlist` is an operator stand-in.
- `btauth_transport`: no transport authentication.
- `signed_engine_policy`: no `sentinel-engine-policy/v1` resolution. Unset `limits`, `origins` or `holdout` yields `policy_unresolved`; `GET /engine/v1/policies/{sha256}` answers `policy_unresolved`.
- `independent_operators`: one local operator holds holdout, queue and receipt key.
- `execution_profile_qualification`: bubblewrap is a local isolation layer, not a qualified EX profile (no cgroup memory/CPU limits here).

`GET /engine/v1/windows/{id}/replay` always answers `{state:"unavailable"}` (EC-08/11 not implemented). The sandbox adapter scores the practice `sentinel-literal-miner/v1` entrypoint as a stand-in for real EC-04..07 format adapters. Case inputs use `sentinel-practice-input/v1`, not `sentinel-engine-case/v1`.

## Tests

`tests/engine-intake.test.ts` runs intake and worker as separate processes: size, timeout, media type, invalid envelope, tampered signature, replay, nonce conflict, content quota, wrong hash, redirect, fetch timeout, restart with byte-identical receipts, no re-evaluation, crash lease recovery with stale-worker fencing, and a hostile artifact that tries to read the bank, database, receipt key, `/etc/passwd` and source, write the artifact, open a socket, hang and flood stdout.
