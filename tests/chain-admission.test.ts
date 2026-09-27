import { test,expect } from 'bun:test';
import { mkdtempSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chainCanonical,chainDigest,verifyChainAdmission,type ChainAdmission } from '../src/chain-admission';
import { ContributionInbox,practiceContract,practiceRound,challengePayload,contributionPayload,sha256,evaluateSnapshot } from '../src/protocol';
import { cryptoWaitReady,sr25519PairFromSeed,sr25519Sign,encodeAddress } from '@polkadot/util-crypto';
import { reference } from '../src/competition';

test('operator-approved chain identity binds freshness, registrations and durable round incarnation',async()=>{
  await cryptoWaitReady();
  const pair=sr25519PairFromSeed(new Uint8Array(32).fill(7)),key=encodeAddress(pair.publicKey,42),hash='a'.repeat(64);
  const sign=(bytes:Uint8Array)=>Buffer.from(sr25519Sign(bytes,pair)).toString('hex');
  const contract=practiceContract('1'.repeat(64),'2'.repeat(64),1);
  const scope={genesis:hash,netuid:2,round:practiceRound(contract),validator:key};
  const policy={scope,eligible:[key],creationHeight:10,creationHash:hash,owner:key,ownerHotkey:key,runtime:424,metadataSha256:hash};
  const observation={schema:'sentinel-chain-observation/v1',genesis:hash,netuid:2,finalizedHeight:20,finalizedHash:hash,
    creationHeight:10,creationHash:hash,owner:key,ownerHotkey:key,runtime:424,metadataSha256:hash,validator:key,
    members:[{hotkey:key,uid:0,owner:key,registrationHeight:10,registrationHash:hash,validatorPermit:true}],limitation:'Fixture, not chain qualification'};
  const input:ChainAdmission={policy,approval:{snapshotSha256:chainDigest(observation),policySha256:chainDigest(policy),observedAt:1000,maxAgeMs:100,finalizedHeight:20,finalizedHash:hash},
    bytes:Buffer.from(chainCanonical({sha256:chainDigest(observation),observation})+'\n')};
  expect(verifyChainAdmission(input,1000).policy).toEqual(policy);
  for(const now of [999,1100,NaN])expect(()=>verifyChainAdmission(input,now)).toThrow();
  for(const change of [{snapshotSha256:'b'.repeat(64)},{policySha256:'b'.repeat(64)},{finalizedHeight:21},{finalizedHash:'b'.repeat(64)},{maxAgeMs:0}])
    expect(()=>verifyChainAdmission({...input,approval:{...input.approval,...change}},1000)).toThrow();
  expect(()=>verifyChainAdmission({...input,policy:{...policy,creationHeight:11}},1000)).toThrow();
  for(const change of [{genesis:'b'.repeat(64)},{creationHash:'b'.repeat(64)},{owner:'bad'},
    {members:[{...observation.members[0],uid:true}]},{members:[{...observation.members[0],validatorPermit:false}]},
    {members:[{...observation.members[0],registrationHeight:21}]},{members:[observation.members[0],observation.members[0]]},{members:[]}]){
    const o={...observation,...change},sha256=chainDigest(o);
    expect(()=>verifyChainAdmission({...input,bytes:Buffer.from(chainCanonical({sha256,observation:o})),approval:{...input.approval,snapshotSha256:sha256}},1000)).toThrow();
  }
  const text=Buffer.from(input.bytes).toString().trim();
  expect(()=>verifyChainAdmission({...input,bytes:Buffer.from(text.replace('"sha256":','"sha256":"bad","sha256":'))},1000)).toThrow();
  const dir=mkdtempSync(join(tmpdir(),'sentinel-chain-'));let now=1000;
  try{
    const legacy=new ContributionInbox(dir,scope,[key],50,()=>now);
    const inbox=ContributionInbox.chainQualified(dir,input,50,()=>now);
    expect(()=>legacy.registerPractice(contract)).toThrow('binding');legacy.close();
    inbox.registerPractice(contract);const challenge=inbox.issue(key);expect(challenge.miner).toBe(key);
    const artifact=Buffer.from(JSON.stringify(reference)),artifactSha256=sha256(artifact);
    await inbox.accept({schema:'sentinel-contribution/v1',challenge,artifactSha256,signature:sign(contributionPayload(challenge,artifactSha256))},artifact);
    await inbox.attestAdmission({challenge,signature:sign(challengePayload(challenge))},async bytes=>sign(bytes));
    inbox.closePractice('1'.repeat(64),1,'2'.repeat(64));
    const snapshot=inbox.exportPractice(),expected={cohortSha256:sha256(snapshot),scope,eligible:[key],chain:{policy,approval:input.approval}};
    expect((await evaluateSnapshot(snapshot,expected)).authentication.eligibility).toBe('operator-approved-rpc-observed-registration');
    const original=JSON.parse(snapshot.toString());expect(original.schema).toBe('sentinel-frozen-practice/v3');
    for(const mutate of [(v:any)=>delete v.chain,(v:any)=>v.chain.observation='{}',(v:any)=>v.chain.approval.finalizedHeight++,
      (v:any)=>v.chain.policy.creationHeight++,(v:any)=>{delete v.chain;v.schema='sentinel-frozen-practice/v2';}]){
      const v=structuredClone(original);mutate(v);const bytes=Buffer.from(JSON.stringify(v));
      await expect(evaluateSnapshot(bytes,{...expected,cohortSha256:sha256(bytes)})).rejects.toThrow();
    }
    await expect(evaluateSnapshot(snapshot,{cohortSha256:sha256(snapshot),scope,eligible:[key]})).rejects.toThrow();
    await expect(evaluateSnapshot(snapshot,{...expected,chain:{policy,approval:{...input.approval,finalizedHash:'b'.repeat(64)}}})).rejects.toThrow();
    const child=Bun.spawn(['bun','--eval',`import {evaluateSnapshot} from './src/protocol'; const x=await Bun.stdin.json(); const r=await evaluateSnapshot(Buffer.from(x.snapshot),x.expected); console.log(r.authentication.eligibility);`],{cwd:process.cwd(),stdin:'pipe',stdout:'pipe',stderr:'pipe'});
    child.stdin.write(JSON.stringify({snapshot:snapshot.toString(),expected}));child.stdin.end();
    expect(await child.exited).toBe(0);expect(await new Response(child.stdout).text()).toContain('operator-approved-rpc-observed-registration');
    inbox.close();
    expect(()=>new ContributionInbox(dir,scope,[key],50,()=>now)).toThrow('binding');
    const restarted=ContributionInbox.chainQualified(dir,input,50,()=>now);
    now=1100;expect(()=>restarted.issue(key)).toThrow('expired');restarted.close();
    now=1000;
    const changed={...input,approval:{...input.approval,maxAgeMs:200}};
    expect(()=>ContributionInbox.chainQualified(dir,changed,50,()=>now)).toThrow('binding');
    const dir2=join(dir,'legacy');const old=new ContributionInbox(dir2,scope,[key],50,()=>now);old.registerPractice(contract);old.close();
    expect(()=>ContributionInbox.chainQualified(dir2,input,50,()=>now)).toThrow('legacy');
  }finally{rmSync(dir,{recursive:true,force:true});}
});
