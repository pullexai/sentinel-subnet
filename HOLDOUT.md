# Sealed independent holdout v1

`src/holdout.ts` (`bun run holdout`) adds a practice lane where candidates are ranked on a case bank that is **committed before intake, withheld from miners, and opened only after cohort closure**. It addresses part of EC-08 (salted bank commitment before intake, hidden scoring) and EC-03 (gold outside the artifact process, lineage holdout). It does not replace the public-template Pareto report, which is still computed and returned alongside.

## Roles and flow

1. **Holdout owner** (a key distinct from coordinator and validators) authors `sentinel-holdout-bank/v1`: `{schema, salt, cases}`. Each case is `{input, family, lineage, buggy, defectPath, fixedFiles, oracle}`; `input` uses the existing `sentinel-practice-input/v1` miner schema with flat file names. Owner runs `holdout commit BANK ROUND OWNER PRIVATE_SEED`. Stdout is only the signed commitment `{schema:"sentinel-holdout-commitment/v1", round, owner, bankSha256, cases, committedAt, signature}`; case bytes stay private.
2. **Miner** runs `holdout verify COMMITMENT ROUND OWNER` before contributing, confirming a sealed bank exists for its round under the expected owner key.
3. **Coordinator** runs the existing signed-admission/closure flow unchanged.
4. **Validators** receive the bank only after closure and each independently run `holdout evaluate SNAPSHOT EXPECTATIONS COMMITMENT BANK`, where `EXPECTATIONS` is `{snapshot: <REPLAY.md expectation>, owner}`. Output is a deterministic `sentinel-holdout-report/v1` with a `resultSha256`; separate processes produce identical bytes.

## Bytes

- Bank digest: SHA-256 of UTF-8 `sentinel/holdout-bank/v1\n` + sorted-key canonical JSON of the bank (salt included, so small banks cannot be guessed).
- Commitment signature: raw sr25519 over UTF-8 `sentinel/holdout-commitment/v1\n` + canonical JSON of the six unsigned fields.
- Report digest: `sentinel/holdout-report/v1\n` + canonical JSON of the report.
- Files must be compact JSON without BOM; 8 MiB ceiling. The canonicalizer is the repository's sorted-key JSON, not EC-02 JCS.

## Admission checks (fail closed)

- Commitment round/owner equal the frozen snapshot round and the independently expected owner; signature verifies.
- `committedAt` precedes every admitted challenge's `issuedAt`.
- Opened bank matches the committed digest and case count.
- Every family is distinct from public corpus families; no case ID or file bytes (buggy or fixed) equal any public fixture file for that round; one lineage never spans families; each family has defective and clean cases; IDs are unique.
- Each case's trusted oracle must demonstrate the defect (or clean control) and the repair, via the existing `proveFixture` runner. Holdout programs are owner-authored trusted code; that runner is **not a sandbox** for hostile code.

## Scoring and anti-memorization

Miner rules see only `input`. Candidates are grouped by exact execution identity, compared against the reference baseline on the holdout, and ranked by the same Pareto dominance (TP up, FP down, regressions down). Each result carries public and holdout counts and `memorizationSuspect = publicTP > 0 && holdoutTP === 0`, a deterministic signal for template overfitting, not a penalty weight. `weights` and `rewards` are always `null`.

## Evidence

`tests/holdout.test.ts` runs owner commit, miner verify and two concurrent validator evaluations as separate Bun processes. The two reports are identical; the public-template reference is flagged as memorizing (4/4 public, 0/4 holdout) and ranked below a general candidate (4/4 holdout). Rejections cover opened-bank tampering, forged and wrong-key signatures, commitment after intake, public-family overlap, public-byte leakage, single-polarity families, cross-family lineage, lying oracle labels and BOM input. `bun run check`: **16 tests / 1,150 assertions**, Bun 1.4.2.

## Limits

- `committedAt` is the owner's clock and `issuedAt` the coordinator's; there is no witnessed pre-intake publication or beacon. A colluding owner/coordinator can backdate.
- Bank distribution to validators after closure is out of band; no confidential transport is supplied.
- Owner independence is a governance assumption: a different key is not a different operator.
- Byte-equality leakage checks do not detect near-copies or semantic reuse of public templates.
- The test holdout families are small illustrative fixtures authored for this repository; a real bank must be independently authored and never published here. Revealed banks must be retired from future hidden scoring.
- No customer code or derivatives may enter a bank.
