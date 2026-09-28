import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {ContributionInbox,challengePayload,contributionPayload,sha256,practiceContract,practiceRound,evaluateSnapshot,snapshotByteLimit,type Scope} from '../src/protocol';
import {reference} from '../src/competition';
import {scoreTarget,scoreAttestationPayload,quorumPolicyDigest,verifyScoreQuorum} from '../src/attestations';

test('cohort closure freezes contract, signatures and eligibility across concurrent admission and restart',async()=>{
  await cryptoWaitReady();
  const keys=Array.from({length:3},()=>sr25519PairFromSeed(randomBytes(32))),addresses=keys.map(k=>encodeAddress(k.publicKey,42));
  const salt='f'.repeat(64),contract=practiceContract('d'.repeat(64),salt,1);
  const scope:Scope={genesis:'a'.repeat(64),netuid:9,round:practiceRound(contract),validator:addresses[2]};
  const directory=await mkdtemp('/tmp/opencode/subnet-cohort-');
  let inbox=new ContributionInbox(directory,scope,addresses,1000,()=>100);
  const peer=new ContributionInbox(directory,scope,addresses,1000,()=>101);
  const bytes=Buffer.from(JSON.stringify(reference)),digest=sha256(bytes);
  const envelope=(i:number)=>{const challenge=inbox.issue(addresses[i]);return {schema:'sentinel-contribution/v1',challenge,artifactSha256:digest,
    signature:Buffer.from(sr25519Sign(contributionPayload(challenge,digest),keys[i])).toString('hex')};};
  try{
    expect(()=>inbox.issue(addresses[0])).toThrow('Commit practice');
    expect(inbox.registerPractice(contract)).toBe(scope.round);
    expect(peer.registerPractice(contract)).toBe(scope.round);
    expect(()=>inbox.registerPractice({...contract,pairs:2})).toThrow('mismatch');
    expect(()=>practiceRound({...contract,extra:true})).toThrow('Invalid');
    expect(()=>practiceContract('bad',salt,1)).toThrow('Invalid');
    await expect(inbox.evaluatePractice()).rejects.toThrow('Close practice');
    expect(()=>inbox.closePractice('d'.repeat(64),1,salt)).toThrow('1–100');
    const first=envelope(0),late=envelope(1);
    const inspector=new Database(join(directory,'inbox.sqlite'));
    try{
      const rows=inspector.query('SELECT body FROM practice_contracts').all() as {body:string}[];
      expect(rows[0].body).not.toContain('d'.repeat(64));expect(rows[0].body).not.toContain(salt);
      // Existing uncommitted challenge scopes from the previous release cannot be blessed retroactively.
      inspector.query('DELETE FROM practice_contracts').run();
      expect(()=>peer.registerPractice(contract)).toThrow('retroactively');
      inspector.query('INSERT INTO practice_contracts(scope,body) VALUES(?,?)').run(JSON.stringify([scope.genesis,scope.netuid,scope.round,scope.validator]),rows[0].body);
    }finally{inspector.close();}
    await inbox.accept(first,bytes);
    expect(()=>inbox.closePractice('d'.repeat(64),1,salt)).toThrow('receipt required');
    const signed={challenge:first.challenge,signature:Buffer.from(sr25519Sign(challengePayload(first.challenge),keys[2])).toString('hex')};
    await expect(inbox.attestAdmission({...signed,signature:'0'.repeat(128)},async()=>{throw new Error('must not sign');})).rejects.toThrow('signature');
    await expect(inbox.attestAdmission(signed,async()=>{throw new Error('signer unavailable');})).rejects.toThrow('signer unavailable');
    await expect(inbox.attestAdmission(signed,async payload=>Buffer.from(sr25519Sign(payload,keys[1])).toString('hex'))).rejects.toThrow('signature');
    const admissionDb=new Database(join(directory,'inbox.sqlite'));
    try{
      await expect(inbox.attestAdmission(signed,async payload=>{
        admissionDb.query('UPDATE challenges SET accepted_at=accepted_at+1 WHERE miner=?').run(addresses[0]);
        return Buffer.from(sr25519Sign(payload,keys[2])).toString('hex');
      })).rejects.toThrow('Admission changed');
      expect(admissionDb.query('SELECT * FROM admission_proofs').all()).toHaveLength(0);
      admissionDb.query('UPDATE challenges SET accepted_at=accepted_at-1 WHERE miner=?').run(addresses[0]);
    }finally{admissionDb.close();}
    const proof=await inbox.attestAdmission(signed,async payload=>Buffer.from(sr25519Sign(payload,keys[2])).toString('hex'));
    expect(proof.acceptedAt).toBe(100);
    expect(await peer.attestAdmission(signed,async()=>{throw new Error('replay must not sign');})).toEqual(proof);
    expect(()=>inbox.closePractice('e'.repeat(64),1,salt)).toThrow('reveal conflict');
    expect(()=>inbox.closePractice('d'.repeat(64),1,'e'.repeat(64))).toThrow('reveal conflict');
    // accept yields for crypto readiness; closure commits before its admission transaction.
    const pending=peer.accept(late,bytes).then(()=>null,error=>error);
    const closure=inbox.closePractice('d'.repeat(64),1,salt);
    expect(await pending).toBeInstanceOf(Error);
    expect((await pending as Error).message).toContain('closed');
    expect(closure.participants).toBe(1);
    expect(peer.closePractice('d'.repeat(64),1,salt)).toEqual(closure);
    expect(()=>peer.issue(addresses[2])).toThrow('closed');
    await expect(peer.accept(late,bytes)).rejects.toThrow('closed');
    for(const [seed,pairs] of [['e'.repeat(64),1],['d'.repeat(64),2]] as const)expect(()=>peer.closePractice(seed,pairs,salt)).toThrow('conflict');
    const report=await inbox.evaluatePractice();
    expect(report.cohortSha256).toBe(closure.cohortSha256);
    expect(practiceRound(report.commitment)).toBe(first.challenge.round);
    expect(practiceContract(report.reveal.seed,report.reveal.salt,report.pairs)).toEqual(contract);
    expect(report.results[0].participants).toEqual([addresses[0]]);
    const changed=new ContributionInbox(directory,scope,[addresses[0]],1000,()=>102);
    try{await expect(changed.evaluatePractice()).rejects.toThrow('eligibility');expect(()=>changed.closePractice('d'.repeat(64),1,salt)).toThrow('eligibility');}finally{changed.close();}
    inbox.close();
    inbox=new ContributionInbox(directory,{validator:scope.validator,round:scope.round,netuid:scope.netuid,genesis:scope.genesis},[...addresses].reverse(),1000,()=>9999);
    const replay=await inbox.evaluatePractice();
    expect(replay.cohortSha256).toBe(report.cohortSha256);
    expect(replay.comparisonId).toBe(report.comparisonId);expect(replay.tiers).toEqual(report.tiers);
    expect(replay.results.map(({resources,...stable})=>stable)).toEqual(report.results.map(({resources,...stable})=>stable));
    const target=scoreTarget(report);expect(scoreTarget(replay)).toEqual(target);
    const exported=inbox.exportPractice(),expected={cohortSha256:closure.cohortSha256,scope,eligible:addresses};
    expect(sha256(exported)).toBe(closure.cohortSha256);
    const callerBytes=Buffer.from(exported),callerExpected=structuredClone(expected),savedReference=structuredClone(reference);
    const pendingReplay=evaluateSnapshot(callerBytes,callerExpected);
    try{
      callerBytes.fill(0);callerExpected.scope.netuid++;callerExpected.eligible.length=0;callerExpected.cohortSha256='0'.repeat(64);
      reference.rules.splice(0,reference.rules.length,{id:'changed-baseline',literal:'absent-marker'});
      const sealed=await pendingReplay;
      expect(scoreTarget(sealed)).toEqual(target);
      expect(sealed.results[0].comparison.baseline).toMatchObject({tp:4,fp:0,fn:0});
    }finally{reference.rules=savedReference.rules;}
    await expect(evaluateSnapshot(Buffer.from('{}'),expected)).rejects.toThrow('digest');
    await expect(evaluateSnapshot(Buffer.alloc(snapshotByteLimit+1),expected)).rejects.toThrow('byte limit');
    for(const altered of [{...expected,scope:{...scope,netuid:10}},{...expected,eligible:[addresses[0]]},{...expected,extra:1}])await expect(evaluateSnapshot(exported,altered)).rejects.toThrow();
    const mutate=async(change:(value:any)=>void)=>{
      const value=JSON.parse(exported.toString());change(value);const bytes=Buffer.from(JSON.stringify(value));
      // Even when bytes are deliberately approved, malformed content must fail before fixture execution.
      await expect(evaluateSnapshot(bytes,{...expected,cohortSha256:sha256(bytes)})).rejects.toThrow();
    };
    await mutate(v=>v.extra=true);
    await mutate(v=>v.contributions.push(v.contributions[0]));
    await mutate(v=>v.contributions[0].signature='0'.repeat(128));
    await mutate(v=>v.contributions[0].challenge.netuid=10);
    await mutate(v=>v.contributions[0].submission.rules[0].literal='tampered');
    await mutate(v=>v.fixtureSha256='0'.repeat(64));
    await mutate(v=>v.salt='a'.repeat(64));
    await mutate(v=>v.closedAt=0);
    await mutate(v=>delete v.contributions[0].admission);
    await mutate(v=>v.contributions[0].admission.acceptedAt=v.contributions[0].challenge.expiresAt);
    await mutate(v=>v.contributions[0].admission.acceptedAt=99);
    await mutate(v=>v.contributions[0].admission.receiptSignature='0'.repeat(128));
    await mutate(v=>v.contributions[0].admission.challengeSignature='0'.repeat(128));
    await mutate(v=>v.schema='sentinel-frozen-practice/v1');
    const duplicate=Buffer.from(exported.toString().replace('{','{"schema":"sentinel-frozen-practice/v2",'));
    await expect(evaluateSnapshot(duplicate,{...expected,cohortSha256:sha256(duplicate)})).rejects.toThrow('noncanonical');
    const bom=Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),exported]);
    await expect(evaluateSnapshot(bom,{...expected,cohortSha256:sha256(bom)})).rejects.toThrow();
    const snapshotPath=join(directory,'snapshot.json'),expectedPath=join(directory,'expected.json');
    await writeFile(snapshotPath,exported,{mode:0o600});await writeFile(expectedPath,JSON.stringify(expected),{mode:0o600});
    const child=Bun.spawn(['bun',new URL('../src/replay.ts',import.meta.url).pathname,snapshotPath,expectedPath],{cwd:'/tmp/opencode',stdout:'pipe',stderr:'pipe'});
    const output=await new Response(child.stdout).text(),stderr=await new Response(child.stderr).text();
    expect(await child.exited).toBe(0);expect(stderr).toBe('');
    expect(JSON.parse(output).target).toEqual(target);
    const changedScore=structuredClone(replay);changedScore.results[0].comparison.candidate.tp--;
    expect(scoreTarget(changedScore).resultSha256).not.toBe(target.resultSha256);
    const quorum={validators:addresses.slice(1),threshold:2},policySha256=quorumPolicyDigest(quorum);
    const attestations=keys.slice(1).map((key,i)=>({schema:'sentinel-score-attestation/v1',target:scoreTarget(i ? replay : report),policySha256,validator:addresses[i+1],
      signature:Buffer.from(sr25519Sign(scoreAttestationPayload(target,policySha256,addresses[i+1]),key)).toString('hex')}));
    expect((await verifyScoreQuorum(attestations,target,quorum)).signers).toHaveLength(2);
    // Closure is an independent retained snapshot, not a later query of mutable admission rows.
    const db=new Database(join(directory,'inbox.sqlite'));
    try{
      db.exec('DELETE FROM challenges');
      expect((await inbox.evaluatePractice()).cohortSha256).toBe(closure.cohortSha256);
      // Even a matching stored hash cannot authorize normalizing ambiguous JSON on export.
      db.query('UPDATE frozen_practice SET body=?,digest=?').run(duplicate.toString(),sha256(duplicate));
      inbox.close();inbox=new ContributionInbox(directory,scope,addresses,1000,()=>9999);
      expect(()=>inbox.exportPractice()).toThrow('noncanonical');
      await expect(inbox.evaluatePractice()).rejects.toThrow('noncanonical');
      expect(()=>inbox.closePractice('d'.repeat(64),1,salt)).toThrow('noncanonical');
      db.query('UPDATE frozen_practice SET body=?,digest=?').run(exported.toString(),sha256(exported));
      expect(inbox.exportPractice()).toEqual(exported);
      db.exec("UPDATE frozen_practice SET body=body||' '");
      await expect(inbox.evaluatePractice()).rejects.toThrow('integrity');
    }finally{db.close();}
  }finally{inbox.close();peer.close();await rm(directory,{recursive:true,force:true});}
});
