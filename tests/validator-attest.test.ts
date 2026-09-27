import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,chmod,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {Database} from 'bun:sqlite';
import {ContributionInbox,challengePayload,contributionPayload,practiceContract,practiceRound,sha256,type Scope} from '../src/protocol';
import {reference,type Submission} from '../src/competition';
import {VoteJournal} from '../src/vote-journal';
import {verifyScoreAttestation} from '../src/attestations';

test('independent local validator processes recompute, persist signing locks and refuse conflicting recovery',async()=>{
  await cryptoWaitReady();
  const directory=await mkdtemp('/tmp/opencode/subnet-attest-');
  const seeds=[randomBytes(32),randomBytes(32)],keys=seeds.map(seed=>sr25519PairFromSeed(seed));
  const validators=keys.map(k=>encodeAddress(k.publicKey,42)),policy={validators,threshold:2};
  const coordinator=sr25519PairFromSeed(randomBytes(32)),miner=sr25519PairFromSeed(randomBytes(32)),minerAddress=encodeAddress(miner.publicKey,42);
  const seed='a'.repeat(64),salt='b'.repeat(64),contract=practiceContract(seed,salt,1);
  const scope:Scope={genesis:'c'.repeat(64),netuid:7,round:practiceRound(contract),validator:encodeAddress(coordinator.publicKey,42)};
  const fixture=async(name:string,submission:Submission)=>{
    const inbox=new ContributionInbox(join(directory,name),scope,[minerAddress],100,()=>1000);
    try{
      inbox.registerPractice(contract);const challenge=inbox.issue(minerAddress),bytes=Buffer.from(JSON.stringify(submission)),artifactSha256=sha256(bytes);
      await inbox.accept({schema:'sentinel-contribution/v1',challenge,artifactSha256,signature:Buffer.from(sr25519Sign(contributionPayload(challenge,artifactSha256),miner)).toString('hex')},bytes);
      await inbox.attestAdmission({challenge,signature:Buffer.from(sr25519Sign(challengePayload(challenge),coordinator)).toString('hex')},async payload=>Buffer.from(sr25519Sign(payload,coordinator)).toString('hex'));
      inbox.closePractice(seed,1,salt);const snapshot=inbox.exportPractice();
      return {snapshot,expected:{scope,eligible:[minerAddress],cohortSha256:sha256(snapshot)}};
    }finally{inbox.close();}
  };
  try{
    const a=await fixture('coordinator-a',reference),b=await fixture('coordinator-b',{schema:'sentinel-literal-miner/v1',rules:[{id:'empty-result',literal:'absent-marker'}]});
    const journalDirectory=join(directory,'locks');let journal=new VoteJournal(journalDirectory,policy);
    let attempts=0;
    const sign=async(payload:Uint8Array)=>{attempts++;return Buffer.from(sr25519Sign(payload,keys[0])).toString('hex');};
    try{
      await expect(journal.evaluateAndSign(a.snapshot,a.expected,'untrusted',sign)).rejects.toThrow('Untrusted');expect(attempts).toBe(0);
      await expect(journal.evaluateAndSign(a.snapshot,a.expected,validators[0],async()=>{throw new Error('Signer response lost');})).rejects.toThrow('Signer response lost');
      journal.close();journal=new VoteJournal(journalDirectory,policy);
      await expect(journal.evaluateAndSign(b.snapshot,b.expected,validators[0],sign)).rejects.toThrow('Conflicting signing target');expect(attempts).toBe(0);
      const signed=await journal.evaluateAndSign(a.snapshot,a.expected,validators[0],sign);expect(attempts).toBe(1);
      expect(await verifyScoreAttestation(signed.vote,policy)).toEqual(signed.vote);
      expect(signed.report.results[0].comparison.candidate).toMatchObject({tp:4,fp:0});
      journal.close();journal=new VoteJournal(journalDirectory,policy);
      expect((await journal.evaluateAndSign(a.snapshot,a.expected,validators[0],sign)).vote).toEqual(signed.vote);expect(attempts).toBe(1);
      const peer=new VoteJournal(journalDirectory,policy);
      try{
        const outcomes=await Promise.allSettled([
          journal.evaluateAndSign(a.snapshot,a.expected,validators[1],async bytes=>Buffer.from(sr25519Sign(bytes,keys[1])).toString('hex')),
          peer.evaluateAndSign(b.snapshot,b.expected,validators[1],async bytes=>Buffer.from(sr25519Sign(bytes,keys[1])).toString('hex')),
        ]);
        expect(outcomes.filter(r=>r.status==='fulfilled')).toHaveLength(1);
        expect(outcomes.find(r=>r.status==='rejected')).toMatchObject({reason:{message:'Conflicting signing target'}});
      }finally{peer.close();}
      const db=new Database(join(journalDirectory,'votes.sqlite'));
      try{
        expect(()=>db.exec('DELETE FROM signing_locks')).toThrow('permanent');
        expect(()=>db.exec("UPDATE signing_locks SET target='changed'")).toThrow('immutable');
        expect(()=>db.exec('INSERT OR REPLACE INTO signing_locks SELECT * FROM signing_locks LIMIT 1')).toThrow('replaced');
      }finally{db.close();}
    }finally{journal.close();}
    for(const [name,value] of [['snapshot',a.snapshot],['expectations',Buffer.from(JSON.stringify(a.expected))],['policy',Buffer.from(JSON.stringify(policy))]] as const)await writeFile(join(directory,name),value);
    const cli=async(i:number,journalName=`validator-${i}`)=>{
      const child=Bun.spawn([process.execPath,'src/validator-attest.ts',join(directory,'snapshot'),join(directory,'expectations'),join(directory,'policy'),validators[i],join(directory,`key-${i}`),join(directory,journalName)],{cwd:new URL('..',import.meta.url).pathname,env:{PATH:process.env.PATH},stdout:'pipe',stderr:'pipe'});
      const [out,err,exit]=await Promise.all([new Response(child.stdout).text(),new Response(child.stderr).text(),child.exited]);return {out,err,exit};
    };
    for(let i=0;i<keys.length;i++)await writeFile(join(directory,`key-${i}`),seeds[i],{mode:0o600});
    const processes=await Promise.all([cli(0),cli(1)]),results=processes.map(p=>{expect(p.exit).toBe(0);expect(p.err).toBe('');return JSON.parse(p.out);});
    expect(results[0].target).toEqual(results[1].target);
    expect(results[0].vote.validator).not.toBe(results[1].vote.validator);
    const observer=new VoteJournal(join(directory,'observer'),policy);
    try{
      for(const result of results)await observer.observe(result.vote);
      expect((await observer.certify(results[0].target)).certificate.signers).toEqual([...validators].sort());
    }finally{observer.close();}
    expect(JSON.parse((await cli(0)).out).vote).toEqual(results[0].vote);
    for(const seed of seeds)expect(processes.some(p=>p.out.includes(seed.toString('hex')) || p.err.includes(seed.toString('hex')))).toBe(false);
    await chmod(join(directory,'key-0'),0o644);const refused=await cli(0,'unsafe-seed');expect(refused.exit).toBe(1);expect(refused.out).toBe('');
    // Persisted signatures can be recovered without reopening key material.
    expect(JSON.parse((await cli(0)).out).vote).toEqual(results[0].vote);
    console.log(JSON.stringify({event:'validator.local-independent-recomputation',processes:2,equalTargets:true,persistentSigningLocks:true,weights:null,rewards:null,hiddenEvaluation:false}));
  }finally{seeds.forEach(seed=>seed.fill(0));keys.forEach(key=>key.secretKey.fill(0));await rm(directory,{recursive:true,force:true});}
},30000);
