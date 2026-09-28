import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {ContributionInbox,practiceContract,practiceRound,challengePayload,contributionPayload,sha256} from '../src/protocol';
import {reference,type Submission} from '../src/competition';
import {holdoutBankDigest,holdoutCommitmentPayload,type HoldoutBank,type HoldoutCase} from '../src/holdout';

// Independently authored holdout families, disjoint from the public corpus templates.
function holdoutCase(family:string,variant:number,buggy:boolean):HoldoutCase{
  const name=`h_${sha256(Buffer.from(`${family}:${variant}`)).slice(0,8)}`;
  let fixed:string,bug:string,expression:string,expected:unknown;
  if(family==='negative-modulo'){
    fixed=`export function run(i, n) {\n  const ${name} = ((i % n) + n) % n;\n  return ${name};\n}\n`;
    bug=fixed.replace('((i % n) + n) % n','i % n');expression=`[run(-1, ${5+variant}), run(3, ${5+variant})]`;expected=[4+variant,3];
  }else{
    fixed=`export function run(lo, hi) {\n  let ${name} = 0;\n  for (let i = lo; i <= hi; i++) ${name} += i;\n  return ${name};\n}\n`;
    bug=fixed.replace('i <= hi;','i < hi;');expression=`run(1, ${3+variant})`;expected=(3+variant)*(4+variant)/2;
  }
  const files={'main.js':buggy?bug:fixed};
  return {input:{schema:'sentinel-practice-input/v1',id:sha256(Buffer.from(JSON.stringify([family,variant,buggy,files]))),files,changedFiles:['main.js']},
    family,lineage:`${family}-l${variant}`,buggy,defectPath:'main.js',fixedFiles:{'main.js':fixed},oracle:{entry:'main.js',expression,expected}};
}

test('sealed independent holdout: owner commits before intake, miner verifies, separate validators reproduce ranking and flag public-template memorization',async()=>{
  await cryptoWaitReady();
  const directory=await mkdtemp('/tmp/opencode/subnet-holdout-'),path=(n:string)=>join(directory,n);
  const file=async(n:string,v:unknown)=>{await writeFile(path(n),typeof v==='string'?v:JSON.stringify(v),{mode:0o600});return path(n);};
  const run=async(args:string[])=>{
    const child=Bun.spawn([process.execPath,...args],{cwd:new URL('..',import.meta.url).pathname,env:{PATH:process.env.PATH},stdout:'pipe',stderr:'pipe'});
    const [out,err,exit]=await Promise.all([new Response(child.stdout).text(),new Response(child.stderr).text(),child.exited]);return {out,err,exit};
  };
  const ok=async(p:ReturnType<typeof run>)=>{const r=await p;expect(r.err).toBe('');expect(r.exit).toBe(0);return JSON.parse(r.out);};
  const reject=async(p:ReturnType<typeof run>,message:string)=>{const r=await p;expect(r.exit).not.toBe(0);expect(r.out).toBe('');expect(r.err).toContain(message);};
  const ownerSeed=randomBytes(32),owner=encodeAddress(sr25519PairFromSeed(ownerSeed).publicKey,42),stranger=sr25519PairFromSeed(randomBytes(32));
  const coordinator=sr25519PairFromSeed(randomBytes(32)),minerKeys=[0,1].map(()=>sr25519PairFromSeed(randomBytes(32))),miners=minerKeys.map(k=>encodeAddress(k.publicKey,42));
  const seed='a'.repeat(64),salt='b'.repeat(64),contract=practiceContract(seed,salt,1),round=practiceRound(contract);
  const scope={genesis:'c'.repeat(64),netuid:3,round,validator:encodeAddress(coordinator.publicKey,42)};
  const cases=['negative-modulo','inclusive-range'].flatMap(f=>[0,1].flatMap(v=>[true,false].map(b=>holdoutCase(f,v,b))));
  const bank:HoldoutBank={schema:'sentinel-holdout-bank/v1',salt:randomBytes(32).toString('hex'),cases};
  const memorizer=reference,general:Submission={schema:'sentinel-literal-miner/v1',rules:[{id:'mod-sign',literal:'= i % n;'},{id:'range-edge',literal:'i < hi;'}]};
  const cohort=async(name:string)=>{
    const inbox=new ContributionInbox(path(name),scope,miners,60000,()=>Date.now());
    try{
      inbox.registerPractice(contract);
      for(const [i,submission] of [memorizer,general].entries()){
        const challenge=inbox.issue(miners[i]),bytes=Buffer.from(JSON.stringify(submission)),artifactSha256=sha256(bytes);
        await inbox.accept({schema:'sentinel-contribution/v1',challenge,artifactSha256,signature:Buffer.from(sr25519Sign(contributionPayload(challenge,artifactSha256),minerKeys[i])).toString('hex')},bytes);
        await inbox.attestAdmission({challenge,signature:Buffer.from(sr25519Sign(challengePayload(challenge),coordinator)).toString('hex')},async p=>Buffer.from(sr25519Sign(p,coordinator)).toString('hex'));
      }
      inbox.closePractice(seed,1,salt);const snapshot=inbox.exportPractice();
      await file(`${name}.snapshot`,snapshot.toString());
      return file(`${name}.expected`,{snapshot:{cohortSha256:sha256(snapshot),scope,eligible:miners},owner});
    }finally{inbox.close();}
  };
  try{
    await file('bank',bank);await writeFile(path('owner-key'),ownerSeed,{mode:0o600});
    // 1. Holdout owner seals the bank in its own process; stdout never carries case bytes.
    const commitment=await ok(run(['src/holdout.ts','commit',path('bank'),round,owner,path('owner-key')]));
    expect(commitment.bankSha256).toBe(holdoutBankDigest(bank));expect(JSON.stringify(commitment)).not.toContain('main.js');
    await file('commitment',commitment);
    // 2. Miner-side verification before contributing.
    expect(await ok(run(['src/holdout.ts','verify',path('commitment'),round,owner]))).toEqual(commitment);
    await reject(run(['src/holdout.ts','verify',path('commitment'),'d'.repeat(64),owner]),'scope mismatch');
    await Bun.sleep(5);
    const expected=await cohort('cohort');
    // 3. Two separate validator processes open the bank after closure and agree byte-for-byte.
    const args=['src/holdout.ts','evaluate',path('cohort.snapshot'),expected,path('commitment'),path('bank')];
    const [a,b]=await Promise.all([ok(run(args)),ok(run(args))]);
    expect(a).toEqual(b);expect(a.cases).toBe(8);expect(a.families).toEqual(['inclusive-range','negative-modulo']);
    const byMiner=(m:string)=>a.results.find((r:any)=>r.participants.includes(m));
    const mem=byMiner(miners[0]),gen=byMiner(miners[1]);
    expect(mem.public.tp).toBe(4);expect(mem.holdout.candidate.tp).toBe(0);expect(mem.memorizationSuspect).toBe(true);
    expect(gen.holdout.candidate).toMatchObject({tp:4,fp:0,fn:0});expect(gen.memorizationSuspect).toBe(false);
    expect(a.tiers).toEqual([[gen.digest],[mem.digest]]);expect(a.weights).toBeNull();expect(a.rewards).toBeNull();
    // 4. Tampering and substitution fail closed.
    const evaluate=(commit:string,bankPath:string,exp=expected)=>run(['src/holdout.ts','evaluate',path('cohort.snapshot'),exp,commit,bankPath]);
    const tampered=structuredClone(bank);tampered.cases[0].oracle.expected=[0,0];await file('tampered',tampered);
    await reject(evaluate(path('commitment'),path('tampered')),'does not match commitment');
    await file('forged',{...commitment,signature:'0'.repeat(128)});await reject(evaluate(path('forged'),path('bank')),'signature');
    const {signature:_,...unsigned}=commitment;
    await file('stranger',{...unsigned,signature:Buffer.from(sr25519Sign(holdoutCommitmentPayload(unsigned),stranger)).toString('hex')});
    await reject(evaluate(path('stranger'),path('bank')),'signature');
    const sealedBank=async(name:string,value:HoldoutBank,committedAt=commitment.committedAt)=>{
      await file(`${name}-bank`,value);
      const payload={...unsigned,bankSha256:holdoutBankDigest(value),cases:value.cases.length,committedAt};
      await file(`${name}-commit`,{...payload,signature:Buffer.from(sr25519Sign(holdoutCommitmentPayload(payload),sr25519PairFromSeed(ownerSeed))).toString('hex')});
      return [path(`${name}-commit`),path(`${name}-bank`)] as const;
    };
    await reject(evaluate(...await sealedBank('late',bank,Date.now())),'after intake');
    const overlap=structuredClone(bank);for(const c of overlap.cases.filter(c=>c.family==='negative-modulo'))c.family='tenant-cache';
    await reject(evaluate(...await sealedBank('overlap',overlap)),'overlaps public');
    const {corpus}=await import('../src/corpus');const leak=structuredClone(bank),pub=corpus(seed,1)[0];
    leak.cases[0].input.files={'main.js':pub.input.files[pub.defectPath]};leak.cases[0].fixedFiles={'main.js':pub.fixedFiles[pub.defectPath]};
    await reject(evaluate(...await sealedBank('leak',leak)),'leaks public');
    await reject(evaluate(...await sealedBank('polarity',{...bank,cases:bank.cases.filter(c=>c.buggy)})),'defective and clean');
    await reject(evaluate(...await sealedBank('spans',{...bank,cases:bank.cases.map((c,i)=>({...c,lineage:i<4?c.lineage:'shared-l0'})).map((c,i)=>i===0?{...c,lineage:'shared-l0'}:c)})),'spans families');
    const lying=structuredClone(bank);lying.cases[0].buggy=!lying.cases[0].buggy;lying.cases[1].buggy=!lying.cases[1].buggy;
    await reject(evaluate(...await sealedBank('oracle',lying)),'Oracle did not demonstrate');
    await file('bom','\ufeff'+JSON.stringify(bank));await reject(evaluate(path('commitment'),path('bom')),'JSON');
  }finally{await rm(directory,{recursive:true,force:true});}
},120000);
