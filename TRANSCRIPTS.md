# Complete-roster practice transcript agreement v2

This is a separate **public-template, deterministic practice lane**. `src/transcripts.ts` and `src/validator-transcript.ts` connect signed transcript commitment/opening to the existing frozen-snapshot evaluator. V1 `validator:attest`, score targets and vote journals remain available unchanged. A v2 transcript-set certificate is not interchangeable with a v1 score quorum.

## Bounded contract

`sentinel-practice-transcript-policy/v2` contains exactly:

- `schema`, `profile: "sentinel-literal-single-trial/v1"`;
- `expected`: the separately trusted snapshot digest/scope/full eligible set, including chain expectations when using snapshot v3;
- `validators`: 1–8 distinct canonical SS58-42 addresses, **sorted by decoded raw 32-byte public key**;
- `tuples`: 1–4,096 exact `{role, executionIdentity, caseId, trialIndex}` entries;
- `commitDeadline`, `openingDeadline`: safe integer Unix milliseconds, with opening strictly later than commitment.

Every exact-content candidate identity and the baseline are scheduled over every case. `role` distinguishes paired baseline execution from candidate execution even when content identities match. `trialIndex` is exactly `0`; ordering is `(executionIdentity, caseId, trialIndex, role)`. The round, common corpus seed, case bytes, admitted submissions, generator and scorer are bound through the full frozen-snapshot expectation. No candidate selects its own cases. The policy is rechecked against authenticated snapshot content at every command; omitted/extra/duplicate tuples cannot be blessed by editing the policy.

The execution roster is also the certifier roster, with **unanimity and an explicit zero-fault practice assumption**. There is no surviving-subset quorum, alternative certifier roster, stochastic tolerance or retry tuning. One withholding member blocks this round. These bounds and the 16 MiB wire ceiling are implementation limits, not chosen production parameters.

`plan` derives configuration without running the evaluator. Each journal seals exactly one policy/validator identity before execution. Configuration changes conflict on reopening; another policy requires a separately authorized round/journal, never treating policy replacement or deleting the old journal as recovery. This locally freezes the roster before execution/opening, but does not provide witnessed pre-intake policy publication.

## Actual execution and disclosure gates

1. **Commit:** `execute` invokes `evaluateSnapshot`, including existing fixture oracle checks and actual baseline/candidate `mine` calls. A capture hook records the very outputs consumed by comparison. Each transcript tuple adds `paths`, the sorted unique finding paths used by the current file-level scorer. Empty paths explicitly represent a completed clean/no-finding run, not a missing tuple. Rule labels are excluded because they do not affect this scorer. The report's deterministic `ScoreTarget` accompanies the complete ordered tuples. No supplied transcript or score is accepted as local execution.
2. The journal stores complete execution bytes plus a random 32-byte salt before signing. It signs the transcript, retains the exact signed bytes, then signs its salted commitment. `commit` stdout contains only that commitment envelope: no salt, transcript, output or score.
3. **Freeze:** each validator verifies exactly one valid commitment from every policy member and its own retained commitment. It permanently stores that complete ordered list and signs its root. Duplicate members fail; observed valid conflicting bodies quarantine the journal. All commitment reception, list freezing/signing and initial list-certificate acceptance must finish before `commitDeadline`.
4. **Open:** no local opening is returned before receiving distinct signatures from **every** roster member over the identical frozen-list root. Its `{schema, validator, salt, transcript}` opening then becomes available for exchange within the operator's chosen validator channel.
5. **Agree:** every validator receives all openings, verifies roster identity, both signatures/commitments, salt, exact tuple coverage/order and normalized output shape. This deterministic profile requires each complete transcript body—including target and outputs—to equal its retained local execution. No majority output, best sample, surviving subset or received aggregate is selected. The immutable set is stored before signing `{listRoot, root}`. Fresh set acceptance/signing must precede `openingDeadline`.
6. **Certify:** all roster signatures over that same set/list root are required before `openingDeadline`. The journal revalidates retained list certificates and every opening, then emits `sentinel-practice-transcript-set/v2`. Output contains policy/list/set roots, ordered authenticated descriptors, original signed set votes, the common locally recomputed target, `weights: null`, `rewards: null`.

Failed malformed/missing/duplicate requests emit no certificate. Invalid signatures cannot frame an identity. A valid signed conflicting body that is observed persists as equivocation and blocks subsequent signing/certification across restarts. A missed local deadline becomes a durable terminal marker; clock rollback cannot revive that journal. Already completed exact phases may be read historically after deadlines. Same-body randomized re-signing is not equivocation, but cannot replace already retained list/certificate bytes; replay the original arrays. Input array order is normalized by raw key. The CLI uses the real local clock, not a caller-supplied timestamp.

Within bounded, parsed vote/opening batches, every sibling is examined independently. Each verified signed item is observed durably before the batch can fail; an invalid sibling cannot suppress valid equivocation evidence in either order. Any item error still rejects the whole batch. Unverified items never enter the evidence journal. Malformed/oversized outer wire input remains rejected at the existing boundary.

## Bytes and roots

This lane reuses the repository's sorted-key JSON canonicalizer. It is **not an implementation or qualification of EC-02 JCS**. Unknown schema fields, nonfinite numbers and unsupported values fail. CLI files must be compact unambiguous JSON, with no BOM, trailing newline or duplicate keys; UTF-8 decoding is fatal. The CLI itself prints one newline-terminated JSON value; parse and reserialize stdout when preparing the next input file.

Every signed envelope is exactly `{schema:"sentinel-practice-signed/v2", phase, policySha256, validator, issuedAt, body, signature}`. Signature is raw sr25519, lowercase 128-hex, over UTF-8 `sentinel/practice-signature/v2\n` plus canonical JSON of the other six fields. Phase is `transcript`, `commit`, `list` or `set`; phase substitution fails. `issuedAt` is a safe integer Unix-millisecond local clock statement, not witnessed delivery time.

For a domain `D`, `H(D, value)` means SHA-256 of UTF-8 `sentinel/practice-D/v2\n` plus canonical JSON of `value`:

- Policy: `H("transcript-policy", policy)`.
- Transcript body: `H("transcript", {target, tuples})`.
- Signed transcript: `H("attestation", signedTranscript)`, including its exact signature.
- Commitment body: `{commitment: H("transcript-opening", {policySha256, validator, salt, transcriptSha256, attestationSha256})}`. Salt is 64 lowercase hex from OS randomness; received salt shape does not prove entropy.
- List root: `H("commitment-list", [{validator: rawPublicKeyHex, commitment}, ...])`, every member sorted by raw public-key bytes.
- Set root: `H("transcript-set", [{validator: rawPublicKeyHex, transcriptSha256, attestationSha256}, ...])`, every member in the same raw-key ordering.

The full policy digest scopes all signatures, including snapshot incarnation and deadlines. Transcript set identity includes exact canonical authenticated transcript bytes, not just matching aggregate counts. Retain policy, original commitments/list votes, openings and set votes to replay verification; a certificate alone does not prove execution.

## Commands

All paths refer to dedicated local public/synthetic practice storage. `ROSTER.json` is an independently selected JSON array of approved practice addresses; `EXPECTED.json` follows [REPLAY.md](REPLAY.md). Choose absolute future millisecond deadlines explicitly. `PRIVATE_SEED` is the existing raw 32-byte, private regular-file convention: disposable practice key only, never its contents in argv.

```sh
bun run validator:transcript plan SNAPSHOT.json EXPECTED.json ROSTER.json COMMIT_DEADLINE_MS OPENING_DEADLINE_MS
bun run validator:transcript commit SNAPSHOT.json POLICY.json VALIDATOR JOURNAL_DIRECTORY PRIVATE_SEED
bun run validator:transcript freeze SNAPSHOT.json POLICY.json VALIDATOR JOURNAL_DIRECTORY COMMITMENTS.json PRIVATE_SEED
bun run validator:transcript open SNAPSHOT.json POLICY.json VALIDATOR JOURNAL_DIRECTORY LIST_VOTES.json
bun run validator:transcript agree SNAPSHOT.json POLICY.json VALIDATOR JOURNAL_DIRECTORY OPENINGS.json PRIVATE_SEED
bun run validator:transcript certify SNAPSHOT.json POLICY.json VALIDATOR JOURNAL_DIRECTORY SET_VOTES.json
```

Parse `plan` stdout, write its compact JSON as the shared approved `POLICY.json`. Run `commit` independently on every roster validator with its own journal/key; collect the returned envelopes into compact `COMMITMENTS.json`. Repeat for freeze/list votes, open/openings and agree/set votes. For example, a local coordinator can use `JSON.stringify(await Promise.all(children.map(child => new Response(child.stdout).json())))` after checking every child exit status. Array assembly is byte relay, not authority to drop a participant or modify evidence. Missing data stops the phase.

## Journal and recovery

Each validator has its own `transcripts.sqlite` with SQLite WAL, `synchronous=FULL`, immutable rows and update/delete/replacement guards. Files live in a private real directory; nonregular/symlink/hardlinked DB files fail. Retain DB and WAL together. Hash checks and signature revalidation detect altered retained data. Parent directories, filesystem, process, clock and practice-key custody are trusted.

The journal records an execution-start marker before running, completed transcript/salt before any signer call, and a one-body-per-phase signing intent before signing. A lost signer response or process death after completion resumes the retained execution, salt and signing intent without reevaluation. A process interrupted before completed execution has no retry path: it fails closed and requires a separately governed abort/new round. This prevents favorable rerun selection; it is not a full lease/retry system. Returned signed bytes are retained unchanged across restart. The first pair of observed conflicting signed bodies terminally quarantines the round.

This is not a witnessed append-only event chain. A privileged operator can remove triggers, replace storage, create another journal or withhold conflict evidence. A certificate is local point-in-time agreement; later observed equivocation blocks future use but cannot recall previously exported bytes. Independent witnesses, mirrored checkpoints and rollback/fork recovery remain required.

## Qualification ceiling and remaining EC-08 obligations

Tests use separate real local Bun processes/journals and disposable keys on the same host, public template families and the same code. They demonstrate complete-roster mechanics, not independent operators or hidden generalization. Existing literal findings and Pareto practice scores remain unchanged. Every successful trial is implicit completed literal execution; failed/incomplete oracle/evaluation aborts the round rather than inventing an `invalid` detector outcome or omitting a case.

Executed check: Bun 1.4.2, `bun run check`, **15 tests / 911 assertions**. `tests/transcripts.test.ts` runs the plan/commit/freeze/open/agree/certify CLI in separate processes, verifies identical immutable roots across separate journals, refuses missing/duplicate members and tuple/digest/salt/signature tampering, persists observed equivocation, checks late-phase terminal recovery, kills a real process with SIGKILL after durable execution/signing intent and recovers without reexecution. Stored incomplete execution, changed policy and corrupted journal data fail closed. Existing v1 checks remain passing. Log: `/tmp/opencode/subnet-transcript-check.log` in the development environment.

Mixed-batch equivocation regression: `bun run check`, **15 tests / 1,095 assertions**, Bun 1.4.2. Actual CLI processes test signed conflicts plus invalid siblings in both orders across commitment, list-vote, set-vote and opening batches. Restarted processes refuse every phase after retained conflict; invalid-only control batches leave existing journal rows unchanged and still permit original certification. Log: `/tmp/opencode/subnet-transcript-equivocation-check.log`.

Original obligations still open: independent operators and hidden public/licensed or independently synthetic lineage; witnessed pre-intake policy/baseline/generator/oracle commitments and future beacon; full execution/dependency/profile pins; per-attempt outcomes, bounded leases, retries and abort/appeal histories; hash-chained signed checkpoints and off-instance recovery; authenticated confidential validator transport; delayed public reveal and chain concealment; independent certifier governance/fault bounds; stochastic repetitions, normalization, rational aggregation/disagreement and clone/marginal-round derivation; production clock/delivery accountability. File exchange does not supply confidential transport. Public templates never become hidden through salting or a different seed. Different keys never establish independent operators.

No customer source or derivatives, arbitrary corpus import, chain write, weight/reward computation, funded wallet, paid provider or product activation is part of this lane.
