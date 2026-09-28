import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,chmod,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {Database} from 'bun:sqlite';
import {ContributionInbox,challengePayload,contributionPayload,practiceContract,practiceRound,sha256,type Scope} from '../src/protocol';
import {measure,reference,type Finding,type Submission} from '../src/competition';
import {corpus} from '../src/corpus';
import {VoteJournal} from '../src/vote-journal';
import {verifyScoreAttestation} from '../src/attestations';

test('separate local validator processes revalidate the complete cohort, persist signing locks and refuse conflicting recovery',async()=>{
  await cryptoWaitReady();
  const directory=await mkdtemp('/tmp/opencode/subnet-attest-');
  const seeds=[randomBytes(32),randomBytes(32)],keys=seeds.map(seed=>sr25519PairFromSeed(seed));
  const validators=keys.map(k=>encodeAddress(k.publicKey,42)),policy={validators,threshold:2};
  const coordinator=sr25519PairFromSeed(randomBytes(32)),miners=[sr25519PairFromSeed(randomBytes(32)),sr25519PairFromSeed(randomBytes(32))],minerAddresses=miners.map(k=>encodeAddress(k.publicKey,42));
  const seed='a'.repeat(64),salt='b'.repeat(64),contract=practiceContract(seed,salt,1);
  const scope:Scope={genesis:'c'.repeat(64),netuid:7,round:practiceRound(contract),validator:encodeAddress(coordinator.publicKey,42)};
  const fixture=async(name:string,submission:Submission)=>{
    const inbox=new ContributionInbox(join(directory,name),scope,minerAddresses,100,()=>1000);
    try{
      inbox.registerPractice(contract);const bytes=Buffer.from(JSON.stringify(submission)),artifactSha256=sha256(bytes);
      for(const [i,miner] of miners.entries()){
        const challenge=inbox.issue(minerAddresses[i]);
        await inbox.accept({schema:'sentinel-contribution/v1',challenge,artifactSha256,signature:Buffer.from(sr25519Sign(contributionPayload(challenge,artifactSha256),miner)).toString('hex')},bytes);
        await inbox.attestAdmission({challenge,signature:Buffer.from(sr25519Sign(challengePayload(challenge),coordinator)).toString('hex')},async payload=>Buffer.from(sr25519Sign(payload,coordinator)).toString('hex'));
      }
      inbox.closePractice(seed,1,salt);const snapshot=inbox.exportPractice();
      return {snapshot,expected:{scope,eligible:minerAddresses,cohortSha256:sha256(snapshot)}};
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
    const run=async(args:string[],input?:string)=>{
      const child=Bun.spawn([process.execPath,...args],{cwd:new URL('..',import.meta.url).pathname,env:{PATH:process.env.PATH},stdin:'pipe',stdout:'pipe',stderr:'pipe'});
      if(input!==undefined)child.stdin.write(input);child.stdin.end();
      const [out,err,exit]=await Promise.all([new Response(child.stdout).text(),new Response(child.stderr).text(),child.exited]);return {out,err,exit};
    };
    const cli=(i:number,journalName=`validator-${i}`)=>run(['src/validator-attest.ts',join(directory,'snapshot'),join(directory,'expectations'),join(directory,'policy'),validators[i],join(directory,`key-${i}`),join(directory,journalName)]);
    const replay=()=>run(['src/replay.ts',join(directory,'snapshot'),join(directory,'expectations')]);
    const setSnapshot=async(snapshot:Buffer,expected=a.expected)=>{
      await writeFile(join(directory,'snapshot'),snapshot);await writeFile(join(directory,'expectations'),JSON.stringify(expected));
    };
    const modified=(change:(value:any)=>void)=>{const value=JSON.parse(a.snapshot.toString());change(value);return Buffer.from(JSON.stringify(value));};
    const malformed=[
      Buffer.from(a.snapshot.toString().replace('"schema":','"schema":"duplicate","schema":')),
      Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),a.snapshot]),Buffer.concat([Buffer.from([0xff]),a.snapshot]),Buffer.concat([a.snapshot,Buffer.from('\n')]),
      modified(v=>v.contributions[1].artifactSha256='0'.repeat(64)),modified(v=>v.contributions[1].signature='0'.repeat(128)),
      modified(v=>{const c=v.contributions[1];c.submission.rules[0].literal='tampered';c.artifactSha256=sha256(Buffer.from(JSON.stringify(c.submission)));}),
      modified(v=>v.contributions[1].admission.challengeSignature='0'.repeat(128)),modified(v=>v.contributions[1].admission.receiptSignature='0'.repeat(128)),
      modified(v=>v.contributions[1]=v.contributions[0]),modified(v=>v.fixtureSha256='0'.repeat(64)),modified(v=>v.extra=true),
    ];
    // A valid first entry cannot authorize a malformed later entry, even with an approved byte hash.
    // No key files exist yet; invalid evidence must fail before any signing reservation.
    for(const bytes of malformed){
      await setSnapshot(bytes,{...a.expected,cohortSha256:sha256(bytes)});
      for(const rejected of await Promise.all([cli(0,'rejected'),replay()])){
        expect(rejected.exit).not.toBe(0);expect(rejected.out).toBe('');expect(rejected.err.length).toBeGreaterThan(0);expect(rejected.err).not.toContain('key-0');
      }
    }
    // Omitting an admitted entry cannot keep the independently pinned complete-cohort digest.
    await setSnapshot(modified(v=>v.contributions.pop()));
    for(const rejected of await Promise.all([cli(0,'rejected'),replay()])){
      expect(rejected.exit).not.toBe(0);expect(rejected.out).toBe('');expect(rejected.err).toContain('digest mismatch');
    }
    await setSnapshot(a.snapshot);
    for(const name of ['expectations','policy']){
      const text=JSON.stringify(name==='expectations'?a.expected:policy),duplicate=name==='policy'?'{"threshold":0,':'{"cohortSha256":"duplicate",';
      for(const bytes of [Buffer.from(text.replace('{','{"unknown":true,')),Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(text)]),Buffer.from(text.replace('{',duplicate))]){
        await writeFile(join(directory,name),bytes);
        const rejected=await cli(0,'rejected');expect(rejected.exit).toBe(1);expect(rejected.out).toBe('');expect(rejected.err).not.toContain('key-0');
        if(name==='expectations'){const refused=await replay();expect(refused.exit).not.toBe(0);expect(refused.out).toBe('');}
      }
      await writeFile(join(directory,name),text);
    }
    const rejectedDb=new Database(join(directory,'rejected','votes.sqlite'),{readonly:true});
    try{expect(rejectedDb.query('SELECT * FROM signing_locks').all()).toEqual([]);expect(rejectedDb.query('SELECT * FROM votes').all()).toEqual([]);}finally{rejectedDb.close();}
    // A new process with valid evidence reserves the target, then fails to open its missing seed.
    const missingKey=await cli(0,'rejected');expect(missingKey.exit).toBe(1);expect(missingKey.out).toBe('');expect(missingKey.err).toContain('key-0');
    await setSnapshot(b.snapshot,b.expected);
    const conflicting=await cli(0,'rejected');expect(conflicting.exit).toBe(1);expect(conflicting.out).toBe('');expect(conflicting.err).toContain('Conflicting signing target');
    await setSnapshot(a.snapshot);
    for(let i=0;i<keys.length;i++)await writeFile(join(directory,`key-${i}`),seeds[i],{mode:0o600});
    const recovered=await cli(0,'rejected');expect(recovered.exit).toBe(0);expect(recovered.err).toBe('');
    const processes=await Promise.all([cli(0),cli(1)]),results=processes.map(p=>{expect(p.exit).toBe(0);expect(p.err).toBe('');return JSON.parse(p.out);});
    expect(results[0].target).toEqual(results[1].target);
    expect(JSON.parse(recovered.out).target).toEqual(results[0].target);
    const replayed=await replay();expect(replayed.exit).toBe(0);expect(replayed.err).toBe('');expect(JSON.parse(replayed.out).target).toEqual(results[0].target);
    await writeFile(join(directory,'artifact'),JSON.stringify(reference));
    const exported=await run(['src/corpus.ts',seed,'1']);expect(exported.exit).toBe(0);expect(exported.err).toBe('');
    const mined=await run(['src/miner.ts',join(directory,'artifact')],exported.out);expect(mined.exit).toBe(0);expect(mined.err).toBe('');
    const outputs=mined.out.trim().split('\n').map(line=>JSON.parse(line) as {id:string;findings:Finding[]});
    expect(outputs).toHaveLength(8);expect(new Set(outputs.map(o=>o.id)).size).toBe(8);
    expect(measure(corpus(seed,1),new Map(outputs.map(o=>[o.id,o.findings])))).toEqual(results[0].report.results[0].comparison.candidate);
    expect(results[0].vote.validator).not.toBe(results[1].vote.validator);
    const observer=new VoteJournal(join(directory,'observer'),policy);
    try{
      for(const result of results)await observer.observe(result.vote);
      expect((await observer.certify(results[0].target)).certificate.signers).toEqual([...validators].sort());
    }finally{observer.close();}
    const faultPolicy={schema:'sentinel-quorum-policy/v2' as const,validators,threshold:2,maxFaultyValidators:0};
    await writeFile(join(directory,'policy'),JSON.stringify(faultPolicy));
    const bounded=await Promise.all([cli(0,'v2-validator-0'),cli(1,'v2-validator-1')]);
    const boundedResults=bounded.map(result=>{expect(result.exit).toBe(0);expect(result.err).toBe('');return JSON.parse(result.out);});
    expect(boundedResults[0].target).toEqual(results[0].target);
    expect(boundedResults[0].vote.policySha256).not.toBe(results[0].vote.policySha256);
    const boundedObserver=new VoteJournal(join(directory,'v2-observer'),faultPolicy);
    try{
      await expect(boundedObserver.observe(results[0].vote)).rejects.toThrow('Untrusted');
      for(const result of boundedResults)await boundedObserver.observe(result.vote);
      expect((await boundedObserver.certify(results[0].target)).certificate).toMatchObject({schema:'sentinel-score-quorum/v2',maxFaultyValidators:0,threshold:2});
    }finally{boundedObserver.close();}
    await writeFile(join(directory,'policy'),JSON.stringify({...faultPolicy,maxFaultyValidators:1}));
    const invalidPolicy=await cli(0,'v2-invalid');expect(invalidPolicy.exit).toBe(1);expect(invalidPolicy.out).toBe('');expect(invalidPolicy.err).toContain('honest intersection');
    await writeFile(join(directory,'policy'),JSON.stringify(policy));
    expect(JSON.parse((await cli(0)).out).vote).toEqual(results[0].vote);
    for(const seed of seeds)expect(processes.some(p=>p.out.includes(seed.toString('hex')) || p.err.includes(seed.toString('hex')))).toBe(false);
    await chmod(join(directory,'key-0'),0o644);const refused=await cli(0,'unsafe-seed');expect(refused.exit).toBe(1);expect(refused.out).toBe('');
    // Persisted signatures can be recovered without reopening key material.
    expect(JSON.parse((await cli(0)).out).vote).toEqual(results[0].vote);
    console.log(JSON.stringify({event:'validator.local-recomputation',validators:2,equalTargets:true,persistentSigningLocks:true,completeCohortRevalidation:true,weights:null,rewards:null,hiddenEvaluation:false,independentOperators:false}));
  }finally{seeds.forEach(seed=>seed.fill(0));keys.forEach(key=>key.secretKey.fill(0));await rm(directory,{recursive:true,force:true});}
},30000);
