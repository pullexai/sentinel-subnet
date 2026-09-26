import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {Database} from 'bun:sqlite';
import {join} from 'node:path';
import {VoteJournal} from '../src/vote-journal';
import {quorumPolicyDigest,scoreAttestationPayload,verifyScoreQuorum,type ScoreTarget} from '../src/attestations';

test('durable vote journal preserves conflict proof and excludes equivocators without lowering threshold',async()=>{
  await cryptoWaitReady();
  const keys=Array.from({length:3},()=>sr25519PairFromSeed(randomBytes(32))),validators=keys.map(key=>encodeAddress(key.publicKey,42));
  const policy={validators,threshold:2},policySha256=quorumPolicyDigest(policy);
  const target:ScoreTarget={genesis:'a'.repeat(64),netuid:9,round:'b'.repeat(64),cohortSha256:'c'.repeat(64),resultSha256:'d'.repeat(64)};
  const sign=(i:number,t=target)=>({schema:'sentinel-score-attestation/v1',target:t,policySha256,validator:validators[i],signature:Buffer.from(sr25519Sign(scoreAttestationPayload(t,policySha256,validators[i]),keys[i])).toString('hex')});
  const directory=await mkdtemp('/tmp/opencode/subnet-votes-');let journal=new VoteJournal(directory,policy);
  const peer=new VoteJournal(directory,policy);
  try{
    const first=sign(0),second=sign(1);
    await expect(journal.observe({...first,signature:'0'.repeat(128)})).rejects.toThrow();
    expect(await journal.equivocations(target)).toEqual([]);
    const duplicates=await Promise.all([journal.observe(first),peer.observe(first)]);
    expect(duplicates.filter(v=>v.replay)).toHaveLength(1);
    await journal.observe(second);
    const accepted=await journal.certify(target);expect(accepted.certificate.signers).toHaveLength(2);
    expect(await verifyScoreQuorum(accepted.attestations,target,policy)).toEqual(accepted.certificate);
    // A second randomized signature of the same target is not equivocation.
    expect((await journal.observe(sign(0))).equivocated).toBe(false);
    const conflict=sign(0,{...target,cohortSha256:'e'.repeat(64)});
    expect((await peer.observe(conflict)).equivocated).toBe(true);
    await expect(journal.certify(target)).rejects.toThrow('Insufficient');
    journal.close();journal=new VoteJournal(directory,{...policy,validators:[...validators].reverse()});
    const evidence=await journal.equivocations(target);expect(evidence).toHaveLength(1);expect(evidence[0].votes).toHaveLength(2);
    expect(new Set(evidence[0].votes.map(v=>v.target.cohortSha256)).size).toBe(2);
    expect((await journal.observe(sign(0,{...target,resultSha256:'f'.repeat(64)}))).equivocated).toBe(true);
    expect((await journal.equivocations(target))[0].votes).toHaveLength(2);
    await journal.observe(sign(2));
    const recovered=await journal.certify(target);
    expect(recovered.certificate.signers).toEqual(validators.slice(1).sort());expect(recovered.certificate.threshold).toBe(2);
    expect(recovered.evidence).toHaveLength(1);
    // Distinct rounds never conflict with this one.
    await journal.observe(sign(1,{...target,round:'f'.repeat(64)}));
    expect((await journal.equivocations(target)).map(e=>e.validator)).toEqual([validators[0]]);
    const pending=journal.certify(target).then(()=>null,error=>error);
    await peer.observe(sign(1,{...target,resultSha256:'e'.repeat(64)}));
    const outcome=await pending;expect(outcome).toBeInstanceOf(Error);
    await expect(journal.certify(target)).rejects.toThrow('Insufficient');
    const db=new Database(join(directory,'votes.sqlite'));
    try{db.exec("UPDATE votes SET target='corrupt' WHERE id=(SELECT min(id) FROM votes)");await expect(journal.equivocations(target)).rejects.toThrow('integrity');await expect(journal.certify(target)).rejects.toThrow('integrity');}finally{db.close();}
  }finally{journal.close();peer.close();await rm(directory,{recursive:true,force:true});}
});
