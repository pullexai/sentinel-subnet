# Engine evaluation journal and scoring, local part (EC-08, EC-09, EC-10)

`src/engine-journal.ts` and `src/engine-scoring.ts` implement the parts of EC-08/09/10 that one validator can do alone, offline. No chain, beacon, peer transport or customer data is involved. `bun run engine:journal verify EXPORT ISSUER_HEX WINDOW_ID` verifies an exported journal with no database or network.

## Journal (EC-08)

- One SQLite file per validator and window. `events` and `blobs` are append-only (update/delete triggers). The content-addressed blob and the event that references it are written in one immediate transaction.
- Event `sentinel-engine-journal-event/v1` = `{schema, issuer, window_id, sequence, previous_event_sha256, kind, subject_sha256, issued_at}`. `sequence` is a decimal string starting at `0`; `previous_event_sha256` is `null` only for genesis (`window_open`). The event hash is `SHA-256("sentinel-engine-journal-event/v1\n" || JCS(event))` and excludes the sr25519 signature, which covers the same bytes. Window root = `SHA-256("sentinel-engine-window-root/v1\n" || JCS(ordered event hashes))`. Rejection, abort, retry, quarantine, incomplete and appeal events are all in the root; dropping any breaks the chain.
- One state machine (`apply`) runs before every append and during offline verification: header chain, blob hash, signature, then kind-specific transitions.
- Leases: `window_open` fixes the tuple schedule and `max_infra_retries`. A lease is valid only for a scheduled tuple with no outcome and no live lease. After expiry the same tuple is re-leased as an infrastructure retry; beyond the bound the tuple is recorded `incomplete` and the round status is `incomplete`. An outcome requires a live lease. A duplicate identical completion is idempotent; a different output is journaled as `quarantine` and the round becomes `disputed`. A second transcript commitment for the same round is rejected (equivocation).
- Crash recovery: `open` re-verifies the full chain before signing anything new.
- Checkpoints `sentinel-engine-journal-checkpoint/v1` sign `{issuer, window_id, sequence, head_sha256, window_root}`. `detectForks` reports two different heads at one position from one issuer.
- Seeds: `trialSeed` hashes `{beacon, window_id, round_index, case_input_id, trial_index}`; never hotkey, nonce or candidate digest. A `null` beacon throws `policy_unresolved` (`beacon_unavailable`): no fallback seed. `scheduleRound` aliases exact-content duplicates, always includes the paired baseline and derives `round_id` from the full tuple list.
- `transcriptCommitment` is the EC-08 step 2 formula with domain `sentinel-engine-transcript-commit/v1`.
- `sentinel-engine-attestation/v1` (sr25519, challenge roles): role/key/type authority from a role registry, predicate bound by hash. A `null` registry is `role_registry_unresolved`; `release`/`revocation` need the separate Ed25519 product trust root and `weight_plan`/`weight_observation` need finalized chain state: both are rejected as `policy_unresolved`, never accepted.

## Scoring (EC-08 aggregation, EC-09 losses)

Exact reduced `bigint` rationals. `cellLoss` sums policy costs times missed/positives, false comments/cleans, invalid and mandatory failures over the cell; a cell missing either polarity is `insufficient_evidence`, never zero loss; unset costs are `policy_unresolved`. Precision with no predictions is `undefined`. `rosterMean` averages scheduled trials per validator, then validators equally; any missing validator or trial throws `incomplete_transcript`. `disagreement` blocks on any metric whose max pairwise difference exceeds its bound or whose values are missing; unset bounds are `policy_unresolved`. `pairedGain` returns only the point estimate: `q(c|B)` stays `null` until the bootstrap/PRNG/quantile/multiplicity policy exists.

## Clone classes (EC-10)

`clonePartition` unions by exact execution-content identity and by exactly equal full behavior vectors `(validator, case, trial, canonical_output, status, coverage)` hashed with the profile; candidate identity, signatures, salts, timing and confidence are excluded. No tolerance, rounding or chained similarity. Only a `certified` transcript set yields behavior classes; otherwise, or when any scheduled tuple is missing for an execution, that execution stays in its exact-content class. Members sort by receipt sequence; a duplicate sequence is `class_disputed`. The class ID binds window, profile, transcript-set root and member executions; the result is independent of input order. `transcriptSetRoot` sorts by raw key bytes, then numeric trial index, and rejects duplicate tuples.

## Journaled window (`src/engine-window.ts`)

- `openWindow` freezes the queued intake contributions (fetch, seal, profile admission), schedules `(execution_content_id, case_input_id, trial_index)` tuples with `scheduleRound` (baseline included, exact-content duplicates aliased) and writes `window_open`, `intake`, `rejection` and `freeze` events. A null beacon throws `policy_unresolved` before anything is written.
- `workTuple` leases one tuple, runs the sealed artifact in the existing sandbox on that single case, re-validates the output and records it with `complete`. Artifact failures are recorded as `rejected` outputs; a crashed worker leaves its lease to expire and the next worker re-leases it, up to `max_infra_retries`, after which the tuple is `incomplete`.
- `windowReport` reports only journal outcomes: window root, `roundStatus`, per-trial EC-09 loss inputs (loss stays `policy_unresolved` without signed costs), point gain against the baseline, and EC-10 classes by exact content (behavior classes need a quorum-certified transcript set).
- `tests/engine-window.test.ts` kills a worker process during a lease and resumes it, verifies the export offline (library and CLI), detects a forged output, and gets the same root from two independent runs.

## Explicitly not verified here

Beacon availability, witness confirmation of checkpoints and receipt order, quorum certificates and commitment/opening exchange between roster validators, independent operators, finalized chain state, signed policy values (costs, bounds, retries, roster), bootstrap uncertainty and lane shares, product release keys, public reveal. Each surfaces as `policy_unresolved` or `unverified_*`, never as success.
