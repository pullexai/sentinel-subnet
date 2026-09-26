import { expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generate, score } from '../src/benchmark';
import { releasePayload, verifyRelease, type Release } from '../src/release';

test('release import requires manual selection, trusted signature, validity and exact bytes', () => {
  const { publicKey,privateKey } = generateKeyPairSync('ed25519');
  const artifact = Buffer.from('{"rules":[]}');
  const r: Release = { schema:'sentinel-release/v1',version:'0.1.0',engineAbi:'ast/v1',keyId:'test',
    artifactSha256:createHash('sha256').update(artifact).digest('hex'),artifactBytes:artifact.length,
    issuedAt:'2026-01-01T00:00:00.000Z',expiresAt:'2027-01-01T00:00:00.000Z',signature:'' };
  r.signature = sign(null,releasePayload(r),privateKey).toString('base64');
  const policy = { trustedKeys:new Map([['test',publicKey.export({ type:'spki',format:'pem' }).toString()]]),
    approvedDigest:r.artifactSha256,engineAbi:'ast/v1',revokedDigests:new Set<string>(),maxArtifactBytes:1024,now:new Date('2026-09-26') };
  expect(verifyRelease(r,artifact,policy).version).toBe('0.1.0');
  expect(() => verifyRelease(r,artifact,{ ...policy,approvedDigest:'0'.repeat(64) })).toThrow('Manual approval');
  expect(() => verifyRelease(r,artifact,{ ...policy,revokedDigests:new Set([r.artifactSha256]) })).toThrow('Revoked');
  expect(() => verifyRelease(r,artifact,{ ...policy,trustedKeys:new Map() })).toThrow('Untrusted');
  expect(() => verifyRelease(r,Buffer.from('tampered'),policy)).toThrow('integrity');
  expect(() => verifyRelease({ ...r,version:'0.2.0' },artifact,policy)).toThrow('signature');
  expect(() => verifyRelease(r,artifact,{ ...policy,now:new Date('2027-01-01') })).toThrow('validity');
  expect(() => verifyRelease({ ...r,extra:true },artifact,policy)).toThrow('schema');
});

test('synthetic bugs execute across files; fixed controls pass, changed-file-only baseline misses defects', async () => {
  const cases = generate('1'.repeat(64),6);
  expect(generate('1'.repeat(64),6)).toEqual(cases);
  const directory = await mkdtemp(join(tmpdir(),'sentinel-synthetic-'));
  try {
    for (const [i,c] of cases.entries()) {
      const pricing = `pricing-${i}.js`;
      await writeFile(join(directory,pricing),c.files['pricing.js']);
      const invoice = join(directory,`invoice-${i}.js`);
      await writeFile(invoice,c.files['invoice.js'].replace('./pricing.js',`./${pricing}`));
      const source = `import { invoice } from ${JSON.stringify(invoice)}; console.log(invoice(${c.truth.expected/100}));`;
      // Only trusted generator output executes. No miner artifact execution here.
      const process = Bun.spawn(['bun','--eval',source],{ stdout:'pipe',stderr:'pipe' });
      const actual = Number(await new Response(process.stdout).text());
      expect(await process.exited).toBe(0);
      expect(actual).toBe(c.truth.observed);
      expect(actual !== c.truth.expected).toBe(c.truth.buggy);
      expect(c.changedFiles).not.toContain(c.truth.location);
    }
    expect(score(cases,new Map())).toMatchObject({ tp:0,fp:0,fn:3 });
    const outputs = new Map(cases.map(c => [c.id,c.truth.buggy ? ['invoice.js'] : []]));
    expect(score(cases,outputs)).toMatchObject({ tp:3,fp:0,fn:0 });
    expect(() => score(cases,new Map([['unknown',[]]]))).toThrow('cohort');
  } finally { await rm(directory,{ recursive:true,force:true }); }
});
