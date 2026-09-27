import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {quorumPolicyDigest,scoreAttestationPayload,verifyScoreQuorum,type ScoreTarget} from '../src/attestations';

test('explicit score quorum binds unique validators, contract, cohort, result and threshold',async()=>{
  await cryptoWaitReady();
  const keys=Array.from({length:4},()=>sr25519PairFromSeed(randomBytes(32))),addresses=keys.map(k=>encodeAddress(k.publicKey,42));
  const policy={validators:addresses.slice(0,3),threshold:2},policySha256=quorumPolicyDigest(policy);
  const target:ScoreTarget={genesis:'a'.repeat(64),netuid:9,round:'b'.repeat(64),cohortSha256:'c'.repeat(64),resultSha256:'d'.repeat(64)};
  const sign=(i:number,t=target,p=policySha256)=>({schema:'sentinel-score-attestation/v1',target:t,policySha256:p,validator:addresses[i],
    signature:Buffer.from(sr25519Sign(scoreAttestationPayload(t,p,addresses[i]),keys[i])).toString('hex')});
  const a=sign(0),b=sign(1);
  const result=await verifyScoreQuorum([a,b],target,policy);
  expect(result.signers).toEqual(addresses.slice(0,2).sort());expect(result.weights).toBeNull();
  expect(await verifyScoreQuorum([b,a],target,{...policy,validators:[...policy.validators].reverse()})).toEqual(result);
  await expect(verifyScoreQuorum([a],target,policy)).rejects.toThrow('Insufficient');
  await expect(verifyScoreQuorum([],target,policy)).rejects.toThrow('Insufficient');
  for(const invalid of [[a,a],[a,sign(3)],[a,{...b,signature:'0'.repeat(128)}],[a,{...b,extra:1}]])await expect(verifyScoreQuorum(invalid,target,policy)).rejects.toThrow();
  for(const field of ['genesis','round','cohortSha256','resultSha256'] as const){
    const changed={...target,[field]:'e'.repeat(64)};
    await expect(verifyScoreQuorum([a,sign(1,changed)],target,policy)).rejects.toThrow('conflicting');
    await expect(verifyScoreQuorum([a,b],changed,policy)).rejects.toThrow('conflicting');
  }
  await expect(verifyScoreQuorum([a,sign(1,{...target,netuid:10})],target,policy)).rejects.toThrow();
  await expect(verifyScoreQuorum([a,b],target,{...policy,threshold:1})).rejects.toThrow();
  await expect(verifyScoreQuorum([a,b],target,{...policy,validators:addresses.slice(0,2)})).rejects.toThrow();
  for(const invalid of [{...policy,threshold:0},{...policy,threshold:4},{...policy,threshold:1.5},{validators:[addresses[0],addresses[0]],threshold:1},
    {...policy,extra:true},{validators:['not-a-hotkey'],threshold:1}])expect(()=>quorumPolicyDigest(invalid)).toThrow();
  await expect(verifyScoreQuorum([a,b],{...target,netuid:NaN},policy)).rejects.toThrow();
  const mutable=structuredClone([a,b]),mutablePolicy=structuredClone(policy),mutableTarget=structuredClone(target);
  const pending=verifyScoreQuorum(mutable,mutableTarget,mutablePolicy);
  mutable[0].signature='0'.repeat(128);mutablePolicy.threshold=3;mutableTarget.round='f'.repeat(64);
  expect(await pending).toEqual(result);
});

test('fault-bounded policy requires availability and honest intersection without rewriting practice v1',async()=>{
  await cryptoWaitReady();
  const keys=Array.from({length:7},()=>sr25519PairFromSeed(randomBytes(32))),validators=keys.map(k=>encodeAddress(k.publicKey,42));
  const target:ScoreTarget={genesis:'a'.repeat(64),netuid:9,round:'b'.repeat(64),cohortSha256:'c'.repeat(64),resultSha256:'d'.repeat(64)};
  // Exhaust all small N/f/q combinations against independent set intersection:
  // the smallest possible overlap is 2q-N, which must exceed the faulty set.
  for(let n=1;n<=7;n++)for(let f=0;f<n;f++)for(let q=1;q<=n;q++){
    const policy={schema:'sentinel-quorum-policy/v2' as const,validators:validators.slice(0,n),threshold:q,maxFaultyValidators:f};
    const safe=q<=n-f && Math.max(0,2*q-n)>f;
    if(safe)expect(quorumPolicyDigest(policy)).toMatch(/^[a-f0-9]{64}$/);
    else expect(()=>quorumPolicyDigest(policy)).toThrow('honest intersection');
  }
  const policy={schema:'sentinel-quorum-policy/v2' as const,validators:validators.slice(0,4),threshold:3,maxFaultyValidators:1};
  const digest=quorumPolicyDigest(policy);
  expect(digest).not.toBe(quorumPolicyDigest({validators:policy.validators,threshold:3}));
  expect(quorumPolicyDigest({...policy,validators:[...policy.validators].reverse()})).toBe(digest);
  const votes=keys.slice(0,3).map((key,i)=>({schema:'sentinel-score-attestation/v1',target,policySha256:digest,validator:validators[i],
    signature:Buffer.from(sr25519Sign(scoreAttestationPayload(target,digest,validators[i]),key)).toString('hex')}));
  const receipt=await verifyScoreQuorum(votes,target,policy);
  expect(receipt).toMatchObject({schema:'sentinel-score-quorum/v2',maxFaultyValidators:1,threshold:3,weights:null,rewards:null});
  await expect(verifyScoreQuorum(votes.slice(0,2),target,policy)).rejects.toThrow('Insufficient');
  await expect(verifyScoreQuorum(votes,target,{validators:policy.validators,threshold:3})).rejects.toThrow('Untrusted');
  await expect(verifyScoreQuorum(votes,target,{...policy,maxFaultyValidators:0})).rejects.toThrow('Untrusted');
  for(const invalid of [{...policy,maxFaultyValidators:-1},{...policy,maxFaultyValidators:1.5},{...policy,maxFaultyValidators:4},
    {...policy,schema:'unknown'},{...policy,extra:true},{validators,threshold:5,maxFaultyValidators:1}])expect(()=>quorumPolicyDigest(invalid)).toThrow();
  const mutable=structuredClone(policy),pending=verifyScoreQuorum(votes,target,mutable);mutable.maxFaultyValidators=0;
  expect(await pending).toEqual(receipt);
});
