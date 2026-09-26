import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {ContributionInbox,contributionPayload,sha256,practiceContract,practiceRound,type Scope} from '../src/protocol';
import {reference} from '../src/competition';

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
    // Closure is an independent retained snapshot, not a later query of mutable admission rows.
    const db=new Database(join(directory,'inbox.sqlite'));
    try{
      db.exec('DELETE FROM challenges');
      expect((await inbox.evaluatePractice()).cohortSha256).toBe(closure.cohortSha256);
      db.exec("UPDATE frozen_practice SET body=body||' '");
      await expect(inbox.evaluatePractice()).rejects.toThrow('integrity');
    }finally{db.close();}
  }finally{inbox.close();peer.close();await rm(directory,{recursive:true,force:true});}
});
