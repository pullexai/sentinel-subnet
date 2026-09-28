import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {cryptoWaitReady,decodeAddress,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {ContributionInbox,practiceContract,practiceRound,challengePayload,contributionPayload,sha256,evaluateSnapshot} from '../src/protocol';
import {reference,executionIdentity} from '../src/competition';
import {scoreTarget} from '../src/attestations';
import {TranscriptJournal,transcriptPayload,type Signed,type Opening,type TranscriptPolicy} from '../src/transcripts';

test('complete practice transcript roster commits, opens and certifies through separate processes and restart',async()=>{
  await cryptoWaitReady();
  const directory=await mkdtemp('/tmp/opencode/subnet-transcripts-'),seeds=[randomBytes(32),randomBytes(32)],keys=seeds.map(s=>sr25519PairFromSeed(s));
  const validators=keys.map(k=>encodeAddress(k.publicKey,42)),coordinator=sr25519PairFromSeed(randomBytes(32));
  const miner=sr25519PairFromSeed(randomBytes(32)),minerAddress=encodeAddress(miner.publicKey,42);
  const seed='a'.repeat(64),salt='b'.repeat(64),contract=practiceContract(seed,salt,1);
  const scope={genesis:'c'.repeat(64),netuid:1,round:practiceRound(contract),validator:encodeAddress(coordinator.publicKey,42)};
  const inbox=new ContributionInbox(join(directory,'inbox'),scope,[minerAddress],1000,()=>100);
  const run=async(args:string[])=>{
    const child=Bun.spawn([process.execPath,...args],{cwd:new URL('..',import.meta.url).pathname,env:{PATH:process.env.PATH},stdout:'pipe',stderr:'pipe'});
    const [out,err,exit]=await Promise.all([new Response(child.stdout).text(),new Response(child.stderr).text(),child.exited]);return {out,err,exit};
  };
  const file=async(name:string,value:unknown)=>{const path=join(directory,name);await writeFile(path,JSON.stringify(value),{mode:0o600});return path;};
  const path=(name:string)=>join(directory,name);
  const cli=(action:string,i:number,input:string,journal=`validator-${i}`,policy='policy',key=`key-${i}`)=>run(['src/validator-transcript.ts',action,path('snapshot'),path(policy),validators[i],path(journal),path(input),...(['freeze','agree'].includes(action)?[path(key)]:[])]);
  const ok=async(p:ReturnType<typeof run>)=>{const r=await p;expect(r.exit).toBe(0);expect(r.err).toBe('');return JSON.parse(r.out);};
  const reject=async(p:ReturnType<typeof run>,message?:string)=>{const r=await p;expect(r.exit).not.toBe(0);expect(r.out).toBe('');if(message)expect(r.err).toContain(message);return r;};
  const resign=(vote:Signed,i:number)=>{const {signature,...payload}=vote;return {...payload,signature:Buffer.from(sr25519Sign(transcriptPayload(payload),keys[i])).toString('hex')};};
  try{
    inbox.registerPractice(contract);const challenge=inbox.issue(minerAddress),bytes=Buffer.from(JSON.stringify(reference)),artifactSha256=sha256(bytes);
    await inbox.accept({schema:'sentinel-contribution/v1',challenge,artifactSha256,signature:Buffer.from(sr25519Sign(contributionPayload(challenge,artifactSha256),miner)).toString('hex')},bytes);
    await inbox.attestAdmission({challenge,signature:Buffer.from(sr25519Sign(challengePayload(challenge),coordinator)).toString('hex')},async p=>Buffer.from(sr25519Sign(p,coordinator)).toString('hex'));
    inbox.closePractice(seed,1,salt);const snapshot=inbox.exportPractice(),expected={cohortSha256:sha256(snapshot),scope,eligible:[minerAddress]};
    await writeFile(path('snapshot'),snapshot);await file('expected',expected);await file('roster',validators);
    const commitDeadline=Date.now()+180000,openingDeadline=commitDeadline+180000;
    const policy=await ok(run(['src/validator-transcript.ts','plan',path('snapshot'),path('expected'),path('roster'),String(commitDeadline),String(openingDeadline)])) as TranscriptPolicy;
    await file('policy',policy);
    expect(policy.tuples).toHaveLength(16);expect(policy.tuples.filter(t=>t.role==='baseline')).toHaveLength(8);
    expect(new Set(policy.tuples.map(t=>t.executionIdentity))).toEqual(new Set([executionIdentity(reference)]));
    const rawKeys=policy.validators.map(v=>Buffer.from(decodeAddress(v,false,42)).toString('hex'));expect(rawKeys).toEqual([...rawKeys].sort());
    for(const bad of [{...policy,tuples:policy.tuples.slice(1)},{...policy,tuples:[...policy.tuples,policy.tuples[0]]},{...policy,profile:'arbitrary-bank'}]){
      await file('bad-policy',bad);await reject(cli('commit',0,'key-0','bad','bad-policy'));
    }
    await writeFile(path('bad-policy'),'\ufeff'+JSON.stringify(policy));await reject(cli('commit',0,'key-0','bad','bad-policy'));
    // No key file: execution and salt persist before signing. Restart must not reexecute.
    await reject(cli('commit',0,'key-0'),'key-0');
    const db=new Database(path('validator-0/transcripts.sqlite'),{readonly:true});
    const execution=(db.query("SELECT body FROM transcript_state WHERE key='execution'").get() as {body:string}).body;
    expect(db.query("SELECT body FROM transcript_state WHERE key='intent:transcript'").get()).not.toBeNull();db.close();
    for(let i=0;i<2;i++)await writeFile(path(`key-${i}`),seeds[i],{mode:0o600});
    const commits=await Promise.all([ok(cli('commit',0,'key-0')),ok(cli('commit',1,'key-1'))]) as Signed[];
    for(const commit of commits){expect(Object.keys(commit.body as object)).toEqual(['commitment']);expect(JSON.stringify(commit)).not.toContain('paths');}
    const resumed=new Database(path('validator-0/transcripts.sqlite'),{readonly:true});
    expect((resumed.query("SELECT body FROM transcript_state WHERE key='execution'").get() as {body:string}).body).toBe(execution);resumed.close();
    expect(await ok(cli('commit',0,'missing-key'))).toEqual(commits[0]);
    await file('changed-policy',{...policy,openingDeadline:policy.openingDeadline+1});
    await reject(cli('commit',0,'key-0','validator-0','changed-policy'),'Conflicting transcript state');
    await file('commits',commits);await file('empty',[]);
    await reject(cli('open',0,'empty'),'Freeze complete');
    await file('missing',[commits[0]]);await reject(cli('freeze',0,'missing'),'Complete execution roster');
    await file('duplicate',[commits[0],commits[0]]);await reject(cli('freeze',0,'duplicate'),'Duplicate');
    const badSignature=structuredClone(commits);badSignature[1].signature='0'.repeat(128);await file('bad-signature',badSignature);
    await reject(cli('freeze',0,'bad-signature'),'signature');
    const listVotes=await Promise.all([ok(cli('freeze',0,'commits')),ok(cli('freeze',1,'commits'))]) as Signed[];
    expect(listVotes[0].body).toEqual(listVotes[1].body);
    await file('list-votes',listVotes);await file('one-list-vote',[listVotes[0]]);
    await reject(cli('open',0,'one-list-vote'),'Complete execution roster');
    const openings=await Promise.all([ok(cli('open',0,'list-votes')),ok(cli('open',1,'list-votes'))]) as Opening[];
    expect(openings[0].transcript.body).toEqual(openings[1].transcript.body);
    expect(openings[0].transcript.body.target).toEqual(scoreTarget(await evaluateSnapshot(snapshot,expected)));
    expect(openings[0].transcript.body.tuples).toHaveLength(16);
    const firstOpening=openings[0];await file('openings',[...openings].reverse());
    await file('one-opening',[firstOpening]);await reject(cli('agree',0,'one-opening'),'Complete execution roster');
    await file('duplicate-opening',[firstOpening,firstOpening]);await reject(cli('agree',0,'duplicate-opening'),'Duplicate');
    const badSalt=structuredClone(openings);badSalt[1].salt='0'.repeat(64);await file('bad-salt',badSalt);
    await reject(cli('agree',0,'bad-salt'),'salt mismatch');
    for(const alter of [(o:Opening)=>o.transcript.body.tuples.pop(),(o:Opening)=>o.transcript.body.tuples[0]=o.transcript.body.tuples[1],(o:Opening)=>o.transcript.body.tuples[0].trialIndex=1 as 0]){
      const bad=structuredClone(openings);alter(bad[1]);bad[1].transcript=resign(bad[1].transcript,1) as Opening['transcript'];await file('bad-tuple',bad);
      await reject(cli('agree',0,'bad-tuple'),'transcript');
    }
    const altered=structuredClone(openings);altered[1].transcript.body.target.resultSha256='0'.repeat(64);await file('altered',altered);
    await reject(cli('agree',0,'altered'),'signature');
    const setVotes=await Promise.all([ok(cli('agree',0,'openings')),ok(cli('agree',1,'openings'))]) as Signed[];
    expect(setVotes[0].body).toEqual(setVotes[1].body);await file('set-votes',setVotes);
    const wrongRoot=structuredClone(setVotes);(wrongRoot[1].body as any).root='0'.repeat(64);await file('wrong-root',wrongRoot);
    await reject(cli('certify',0,'wrong-root'),'signature');
    await file('one-set-vote',[setVotes[0]]);await reject(cli('certify',0,'one-set-vote'),'Complete execution roster');
    await file('duplicate-set-vote',[setVotes[0],setVotes[0]]);await reject(cli('certify',0,'duplicate-set-vote'),'Duplicate');
    const certificates=await Promise.all([ok(cli('certify',0,'set-votes')),ok(cli('certify',1,'set-votes'))]);
    expect(certificates[0]).toEqual(certificates[1]);expect(certificates[0].schema).toBe('sentinel-practice-transcript-set/v2');
    expect(certificates[0].weights).toBeNull();expect(certificates[0].rewards).toBeNull();
    expect(certificates[0].descriptors.map((d:any)=>d.validator)).toEqual(rawKeys);
    expect(await ok(cli('certify',0,'set-votes'))).toEqual(certificates[0]);
    expect(await ok(cli('open',0,'list-votes'))).toEqual(firstOpening);
    // Reopen copies of the genuinely executed journal in fresh CLI processes for each
    // batch/order. An invalid sibling must neither hide signed evidence nor frame a key.
    const ready=new Database(path('validator-0/transcripts.sqlite'),{readonly:true}),checkpoint=ready.serialize();
    const before=ready.query('SELECT key,body,digest FROM transcript_state ORDER BY key').all();ready.close();
    const restore=async(name:string)=>{await mkdir(path(name),{mode:0o700});await writeFile(path(`${name}/transcripts.sqlite`),checkpoint,{mode:0o600});};
    const phaseCases=[
      {action:'freeze',prior:commits[1],invalid:{...commits[0],signature:'0'.repeat(128)},valid:commits[1],body:{commitment:'e'.repeat(64)}},
      {action:'open',prior:listVotes[1],invalid:{...listVotes[0],signature:'0'.repeat(128)},valid:listVotes[1],body:{root:'e'.repeat(64)}},
      {action:'certify',prior:setVotes[1],invalid:{...setVotes[0],signature:'0'.repeat(128)},valid:setVotes[1],body:{...(setVotes[1].body as object),root:'e'.repeat(64)}},
      {action:'agree',prior:openings[1].transcript,invalid:null,valid:openings[1],body:{...openings[1].transcript.body,target:{...openings[1].transcript.body.target,resultSha256:'e'.repeat(64)}}},
    ];
    for(const {action,prior,invalid,valid,body} of phaseCases){
      const signedConflict=resign({...prior,body},1),conflicting=action==='agree'?{...openings[1],transcript:signedConflict}:signedConflict;
      const cleanName=`invalid-only-${action}`;await restore(cleanName);await file(`${cleanName}.json`,[invalid,valid]);
      await reject(cli(action,0,`${cleanName}.json`,cleanName));
      const clean=new Database(path(`${cleanName}/transcripts.sqlite`),{readonly:true});
      try{expect(clean.query('SELECT key,body,digest FROM transcript_state ORDER BY key').all()).toEqual(before);}finally{clean.close();}
      expect(await ok(cli('certify',0,'set-votes',cleanName))).toEqual(certificates[0]);
      for(const invalidFirst of [false,true]){
        const name=`mixed-${action}-${invalidFirst}`;await restore(name);
        await file(`${name}.json`,invalidFirst?[invalid,conflicting]:[conflicting,invalid]);
        await reject(cli(action,0,`${name}.json`,name));
        const retained=new Database(path(`${name}/transcripts.sqlite`),{readonly:true});
        try{
          const row=retained.query("SELECT body FROM transcript_state WHERE key='equivocation'").get() as {body:string}|null;
          expect(row).not.toBeNull();expect(JSON.parse(row!.body)).toEqual({first:prior,second:signedConflict});
          expect(retained.query("SELECT key,body,digest FROM transcript_state WHERE key<>'equivocation' ORDER BY key").all()).toEqual(before);
        }finally{retained.close();}
        // Every operation reopens the persistent journal in another process.
        for(const [next,input] of [['commit','key-0'],['freeze','commits'],['open','list-votes'],['agree','openings'],['certify','set-votes']]){
          await reject(cli(next,0,input,name),'equivocated');
        }
      }
    }
    // Later valid equivocation survives process exit; neither old set nor new list certifies.
    const conflict=structuredClone(commits);(conflict[1].body as any).commitment='f'.repeat(64);conflict[1]=resign(conflict[1],1);await file('conflict',conflict);
    await reject(cli('freeze',0,'conflict'),'equivocated');await reject(cli('certify',0,'set-votes'),'equivocated');
    expect(await ok(cli('certify',1,'set-votes'))).toEqual(certificates[1]); // Only observed conflicts are known.
    const inspect=new Database(path('validator-0/transcripts.sqlite'));
    try{
      expect(inspect.query("SELECT body FROM transcript_state WHERE key='equivocation'").get()).not.toBeNull();
      expect(()=>inspect.exec('DELETE FROM transcript_state')).toThrow('permanent');
      expect(()=>inspect.exec("UPDATE transcript_state SET body='{}'")).toThrow('immutable');
      expect(()=>inspect.exec('INSERT OR REPLACE INTO transcript_state SELECT * FROM transcript_state LIMIT 1')).toThrow('replaced');
    }finally{inspect.close();}
    // Deterministic clock tests still use real fresh processes and durable journals.
    const clockRun=(name:string,now:number,action:string,input:string)=>run(['--eval',`import {TranscriptJournal} from './src/transcripts'; import {signPractice} from './src/validator-attest'; const [d,n,a,p,v,k,b,x]=process.argv.slice(1); const j=await TranscriptJournal.open(d,await Bun.file(p).json(),v,new Uint8Array(await Bun.file(b).arrayBuffer()),()=>Number(n)); try { const sign=z=>signPractice(z,v,k); console.log(JSON.stringify(a==='commit'?await j.execute(new Uint8Array(await Bun.file(b).arrayBuffer()),sign):a==='freeze'?await j.freeze(await Bun.file(x).json(),sign):a==='open'?await j.opening(await Bun.file(x).json()):await j.agree(await Bun.file(x).json(),sign))); } finally {j.close();}`,path(name),String(now),action,path('policy'),validators[0],path('key-0'),path('snapshot'),path(input)]);
    await reject(clockRun('late-commit',commitDeadline,'commit','empty'),'Late');
    await reject(clockRun('late-commit',commitDeadline-1,'commit','empty'),'aborted');
    const third=await ok(clockRun('late-open',Date.now(),'commit','empty'));
    await file('late-commits',[third,commits[1]]);
    const thirdList=await ok(clockRun('late-open',Date.now(),'freeze','late-commits')) as Signed;
    const otherList=resign({...thirdList,validator:validators[1]},1);await file('late-list-votes',[thirdList,otherList]);
    const thirdOpening=await ok(clockRun('late-open',Date.now(),'open','late-list-votes')) as Opening;
    await file('late-openings',[thirdOpening,openings[1]]);
    await reject(clockRun('late-open',openingDeadline,'agree','late-openings'),'Late');
    await reject(clockRun('late-open',openingDeadline-1,'agree','late-openings'),'aborted');
    const lateListCommit=await ok(clockRun('late-list',Date.now(),'commit','empty'));
    await file('late-list-commits',[lateListCommit,commits[1]]);
    await reject(clockRun('late-list',commitDeadline,'freeze','late-list-commits'),'Late');
    await reject(clockRun('late-list',commitDeadline-1,'freeze','late-list-commits'),'aborted');
    // A signed conflicting transcript poisons an otherwise healthy local round durably.
    await ok(clockRun('transcript-conflict',Date.now(),'commit','empty'));
    const conflictDb=new Database(path('transcript-conflict/transcripts.sqlite'),{readonly:true});
    const localCommit=JSON.parse((conflictDb.query("SELECT body FROM transcript_state WHERE key='signed:commit'").get() as {body:string}).body);conflictDb.close();
    await file('conflict-commits',[localCommit,commits[1]]);
    const ownList=await ok(clockRun('transcript-conflict',Date.now(),'freeze','conflict-commits')) as Signed;
    await file('conflict-list-votes',[ownList,resign({...ownList,validator:validators[1]},1)]);
    const ownOpening=await ok(clockRun('transcript-conflict',Date.now(),'open','conflict-list-votes')) as Opening;
    await file('conflict-openings',[ownOpening,openings[1]]);await ok(clockRun('transcript-conflict',Date.now(),'agree','conflict-openings'));
    const changed=structuredClone(openings[1]);changed.transcript.body.target.resultSha256='d'.repeat(64);changed.transcript=resign(changed.transcript,1) as Opening['transcript'];
    await file('conflicting-transcripts',[ownOpening,changed]);
    await reject(clockRun('transcript-conflict',Date.now(),'agree','conflicting-transcripts'),'equivocated');
    await reject(clockRun('transcript-conflict',Date.now(),'agree','conflict-openings'),'equivocated');
    // Kill an actual process inside its signer, after FULL-synced execution/salt/intent.
    const killed=await run(['--eval',`import {TranscriptJournal} from './src/transcripts'; const [d,p,v,b]=process.argv.slice(1); const bytes=new Uint8Array(await Bun.file(b).arrayBuffer()); const j=await TranscriptJournal.open(d,await Bun.file(p).json(),v,bytes); await j.execute(bytes,async()=>{process.kill(process.pid,'SIGKILL'); throw new Error('unreachable');});`,path('killed'),path('policy'),validators[0],path('snapshot')]);
    expect(killed.exit).not.toBe(0);expect(killed.out).toBe('');expect(killed.err).toBe('');
    const killedDb=new Database(path('killed/transcripts.sqlite'),{readonly:true});
    const killedExecution=(killedDb.query("SELECT body FROM transcript_state WHERE key='execution'").get() as {body:string}).body;
    expect(killedDb.query("SELECT body FROM transcript_state WHERE key='signed:transcript'").get()).toBeNull();killedDb.close();
    const killedCommit=await ok(cli('commit',0,'key-0','killed'));expect(killedCommit.phase).toBe('commit');
    const recoveredDb=new Database(path('killed/transcripts.sqlite'),{readonly:true});
    expect((recoveredDb.query("SELECT body FROM transcript_state WHERE key='execution'").get() as {body:string}).body).toBe(killedExecution);recoveredDb.close();
    // A run interrupted before completion never silently reruns after restart.
    const crashJournal=await TranscriptJournal.open(path('interrupted'),policy,validators[0],snapshot);crashJournal.close();
    const interrupted=new Database(path('interrupted/transcripts.sqlite'));
    const started=JSON.stringify({at:Date.now()});interrupted.query('INSERT INTO transcript_state VALUES(?,?,?)').run('started',started,sha256(Buffer.from(started)));interrupted.close();
    await reject(cli('commit',0,'key-0','interrupted'),'Incomplete execution');
    // Journal corruption fails instead of selecting fresh execution/signatures.
    const corrupt=new Database(path('validator-1/transcripts.sqlite'));corrupt.exec('DROP TRIGGER transcript_no_update');corrupt.exec("UPDATE transcript_state SET body='{}' WHERE key='opening'");corrupt.close();
    await reject(cli('certify',1,'set-votes'),'integrity');
    expect((await readFile(path('key-0'))).equals(seeds[0])).toBe(true);
  }finally{inbox.close();seeds.forEach(s=>s.fill(0));keys.forEach(k=>k.secretKey.fill(0));await rm(directory,{recursive:true,force:true});}
},60000);
