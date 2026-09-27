# Practice miner input boundary

The JSONL practice miner accepts 1–100 source files and at most 100 distinct changed-file paths referring to those files. Source strings must contain well-formed Unicode. Source bytes are capped at 1,000,000 and each JSONL record at 1,100,000 bytes. UTF-8 decoding is fatal; unterminated final records fail. Invalid records produce no result for that record; earlier valid records remain independently emitted.

`tests/miner-cli.test.ts` exercises the real subprocess with valid multi-record input, duplicate paths, empty snapshots, oversized records, invalid Unicode/UTF-8 and truncated JSONL. This is practice protocol coverage, not independent hidden evaluation or network activation. `bun run check` passed 12 tests and 364 assertions after this change.
