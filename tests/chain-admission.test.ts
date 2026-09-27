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
    expect(()=>legacy.revokeChainApproval()).toThrow('required');
    const inbox=ContributionInbox.chainQualified(dir,input,50,()=>now);
    expect(()=>legacy.registerPractice(contract)).toThrow('binding');legacy.close();
    inbox.registerPractice(contract);const challenge=inbox.issue(key);expect(challenge.miner).toBe(key);
    const artifact=Buffer.from(JSON.stringify(reference)),artifactSha256=sha256(artifact);
    const acceptedContribution={schema:'sentinel-contribution/v1',challenge,artifactSha256,signature:sign(contributionPayload(challenge,artifactSha256))};
    await inbox.accept(acceptedContribution,artifact);
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
    expect(await restarted.accept(acceptedContribution,artifact)).toEqual({hotkey:key,artifactSha256});
    now=1100;expect(()=>restarted.issue(key)).toThrow('expired');
    await expect(restarted.accept(acceptedContribution,artifact)).rejects.toThrow('expired');
    expect(restarted.exportPractice()).toEqual(snapshot);
    expect(restarted.revokeChainApproval()).toEqual({revokedAt:1100});
    await expect(restarted.accept(acceptedContribution,artifact)).rejects.toThrow('revoked');
    expect(()=>restarted.closePractice('1'.repeat(64),1,'2'.repeat(64))).toThrow('revoked');
    expect(restarted.exportPractice()).toEqual(snapshot);restarted.close();
    const historical=ContributionInbox.chainQualified(dir,input,50,()=>now);
    expect(historical.exportPractice()).toEqual(snapshot);
    const replay=await historical.evaluatePractice();
    expect(replay.authentication).toMatchObject({evidenceUse:'historical-replay',currentEligibility:'not-assessed',revocationStatus:'not-assessed'});
    expect(replay.cohortSha256).toBe(expected.cohortSha256);
    expect(historical.revokeChainApproval()).toEqual({revokedAt:1100});
    expect(()=>historical.issue(key)).toThrow('revoked');historical.close();
    now=1000;
    const changed={...input,approval:{...input.approval,maxAgeMs:200}};
    expect(()=>ContributionInbox.chainQualified(dir,changed,50,()=>now)).toThrow('binding');
    const dir2=join(dir,'legacy');const old=new ContributionInbox(dir2,scope,[key],50,()=>now);old.registerPractice(contract);old.close();
    expect(()=>ContributionInbox.chainQualified(dir2,input,50,()=>now)).toThrow('legacy');
    const roundInput=(salt:string)=>{
      const contract=practiceContract('1'.repeat(64),salt,1),policy={...input.policy,scope:{...scope,round:practiceRound(contract)}};
      return {contract,input:{...input,policy,approval:{...input.approval,policySha256:chainDigest(policy)}}};
    };
    const pending=roundInput('3'.repeat(64)),other=roundInput('4'.repeat(64));
    const a=ContributionInbox.chainQualified(dir,pending.input,50,()=>now),b=ContributionInbox.chainQualified(dir,pending.input,50,()=>now);
    const unaffected=ContributionInbox.chainQualified(dir,other.input,50,()=>now);
    a.registerPractice(pending.contract);unaffected.registerPractice(other.contract);
    const pendingChallenge=a.issue(key),pendingContribution={schema:'sentinel-contribution/v1',challenge:pendingChallenge,artifactSha256,signature:sign(contributionPayload(pendingChallenge,artifactSha256))};
    expect(b.revokeChainApproval()).toEqual({revokedAt:1000});
    expect(()=>a.issue(key)).toThrow('revoked');
    expect(()=>a.registerPractice(pending.contract)).toThrow('revoked');
    await expect(a.accept(pendingContribution,artifact)).rejects.toThrow('revoked');
    expect(()=>a.closePractice('1'.repeat(64),1,'3'.repeat(64))).toThrow('revoked');
    a.close();b.close();
    const revokedChild=Bun.spawn(['bun','--eval',`import {ContributionInbox} from './src/protocol'; const x=await Bun.stdin.json(); const inbox=ContributionInbox.chainQualified(x.dir,{...x.input,bytes:Buffer.from(x.input.bytes)},50,()=>1000); try { inbox.issue(x.key); process.exitCode=1; } catch(e) { if(e.message!=='Chain approval revoked')throw e; console.log(e.message); } finally { inbox.close(); }`],{cwd:process.cwd(),stdin:'pipe',stdout:'pipe',stderr:'pipe'});
    revokedChild.stdin.write(JSON.stringify({dir,input:{...pending.input,bytes:Array.from(pending.input.bytes)},key}));revokedChild.stdin.end();
    expect(await revokedChild.exited).toBe(0);expect(await new Response(revokedChild.stdout).text()).toContain('Chain approval revoked');
    const pendingRestart=ContributionInbox.chainQualified(dir,pending.input,50,()=>now);
    await expect(pendingRestart.accept(pendingContribution,artifact)).rejects.toThrow('revoked');
    expect(()=>pendingRestart.issue(key)).toThrow('revoked');
    expect(()=>pendingRestart.closePractice('1'.repeat(64),1,'3'.repeat(64))).toThrow('revoked');pendingRestart.close();
    const otherChallenge=unaffected.issue(key);
    await unaffected.accept({schema:'sentinel-contribution/v1',challenge:otherChallenge,artifactSha256,signature:sign(contributionPayload(otherChallenge,artifactSha256))},artifact);
    await unaffected.attestAdmission({challenge:otherChallenge,signature:sign(challengePayload(otherChallenge))},async bytes=>sign(bytes));
    expect(unaffected.closePractice('1'.repeat(64),1,'4'.repeat(64)).participants).toBe(1);unaffected.close();
    const signing=roundInput('5'.repeat(64)),signingInbox=ContributionInbox.chainQualified(dir,signing.input,50,()=>now);
    signingInbox.registerPractice(signing.contract);const signingChallenge=signingInbox.issue(key);
    await signingInbox.accept({schema:'sentinel-contribution/v1',challenge:signingChallenge,artifactSha256,signature:sign(contributionPayload(signingChallenge,artifactSha256))},artifact);
    await expect(signingInbox.attestAdmission({challenge:signingChallenge,signature:sign(challengePayload(signingChallenge))},async bytes=>{
      const operator=ContributionInbox.chainQualified(dir,signing.input,50,()=>now);
      operator.revokeChainApproval();operator.close();return sign(bytes);
    })).rejects.toThrow('revoked');
    expect(()=>signingInbox.closePractice('1'.repeat(64),1,'5'.repeat(64))).toThrow('revoked');signingInbox.close();
    const boundary=roundInput('7'.repeat(64));let ticks:number[]=[];
    const boundaryInbox=ContributionInbox.chainQualified(dir,boundary.input,200,()=>ticks.shift()??1099);
    boundaryInbox.registerPractice(boundary.contract);
    for(const timestamp of [1100,999]){
      ticks=[1099,1099,timestamp];
      expect(()=>boundaryInbox.issue(key)).toThrow('expired or future-dated');
      expect(ticks).toEqual([]);
    }
    const boundaryChallenge=boundaryInbox.issue(key);
    expect(boundaryChallenge.issuedAt).toBe(1099);
    const boundaryContribution={schema:'sentinel-contribution/v1',challenge:boundaryChallenge,artifactSha256,signature:sign(contributionPayload(boundaryChallenge,artifactSha256))};
    for(const timestamp of [1100,999]){
      ticks=[1099,1099,timestamp];
      await expect(boundaryInbox.accept(boundaryContribution,artifact)).rejects.toThrow('expired or future-dated');
      expect(ticks).toEqual([]);
      expect(boundaryInbox.candidates()).toEqual([]);
    }
    await boundaryInbox.accept(boundaryContribution,artifact);
    await boundaryInbox.attestAdmission({challenge:boundaryChallenge,signature:sign(challengePayload(boundaryChallenge))},async bytes=>sign(bytes));
    for(const timestamp of [1100,999]){
      ticks=[1099,timestamp];
      expect(()=>boundaryInbox.closePractice('1'.repeat(64),1,'7'.repeat(64))).toThrow('expired or future-dated');
      expect(ticks).toEqual([]);
      expect(()=>boundaryInbox.exportPractice()).toThrow('Close practice cohort');
    }
    expect(boundaryInbox.closePractice('1'.repeat(64),1,'7'.repeat(64)).closedAt).toBe(1099);
    expect((await boundaryInbox.evaluatePractice()).closedAt).toBe(1099);boundaryInbox.close();
    now=1100;const expired=roundInput('6'.repeat(64));
    expect(()=>ContributionInbox.chainQualified(dir,expired.input,50,()=>now)).toThrow('expired');
  }finally{rmSync(dir,{recursive:true,force:true});}
});
