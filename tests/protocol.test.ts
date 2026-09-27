import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {ContributionInbox,challengePayload,contributionPayload,sha256,verifyChallenge,practiceContract,practiceRound,type Scope} from '../src/protocol';
import {reference} from '../src/competition';

test('sr25519 challenge binding, durable idempotent acceptance and authenticated practice evaluation',async()=>{
  await cryptoWaitReady();
  const validator=sr25519PairFromSeed(randomBytes(32)),miner=sr25519PairFromSeed(randomBytes(32)),other=sr25519PairFromSeed(randomBytes(32));
  const address=encodeAddress(miner.publicKey,42),otherAddress=encodeAddress(other.publicKey,42);
  const contract=practiceContract('d'.repeat(64),'e'.repeat(64),1);
  const scope:Scope={genesis:'a'.repeat(64),netuid:7,round:practiceRound(contract),validator:encodeAddress(validator.publicKey,42)};
  const directory=await mkdtemp('/tmp/opencode/subnet-protocol-');let now=1000;
  let inbox=new ContributionInbox(directory,scope,[address,otherAddress],100,()=>now);
  const bytes=Buffer.from(JSON.stringify(reference)),digest=sha256(bytes);
  try{
    inbox.registerPractice(contract);
    const c=inbox.issue(address);expect(inbox.issue(address)).toEqual(c);
    const signed={challenge:c,signature:Buffer.from(sr25519Sign(challengePayload(c),validator)).toString('hex')};
    expect(await verifyChallenge(signed,scope,address,now,100)).toEqual(c);
    for(const changed of [{...scope,netuid:8},{...scope,genesis:'c'.repeat(64)},{...scope,round:'c'.repeat(64)},{...scope,validator:otherAddress}])await expect(verifyChallenge(signed,changed,address,now,100)).rejects.toThrow();
    await expect(verifyChallenge(signed,scope,otherAddress,now,100)).rejects.toThrow();
    for(const time of [999,1100])await expect(verifyChallenge(signed,scope,address,time,100)).rejects.toThrow();
    await expect(verifyChallenge({...signed,signature:'0'.repeat(128)},scope,address,now,100)).rejects.toThrow();
    await expect(verifyChallenge(signed,scope,address,now,99)).rejects.toThrow();
    const envelope={schema:'sentinel-contribution/v1',challenge:c,artifactSha256:digest,signature:Buffer.from(sr25519Sign(contributionPayload(c,digest),miner)).toString('hex')};
    await expect(inbox.accept({...envelope,signature:signed.signature},bytes)).rejects.toThrow();
    await expect(inbox.accept({...envelope,extra:true},bytes)).rejects.toThrow();
    await expect(inbox.accept(envelope,Buffer.from('{}'))).rejects.toThrow();
    for(const changed of [{...c,nonce:'c'.repeat(64)},{...c,round:'c'.repeat(64)},{...c,expiresAt:1200}]){
      await expect(inbox.accept({...envelope,challenge:changed,signature:Buffer.from(sr25519Sign(contributionPayload(changed,digest),miner)).toString('hex')},bytes)).rejects.toThrow();
    }
    const malformed=Buffer.from('{"schema":"sentinel-literal-miner/v1","schema":"sentinel-literal-miner/v1","rules":[{"id":"aa","literal":"x"}]}');
    await expect(inbox.accept({...envelope,artifactSha256:sha256(malformed),signature:Buffer.from(sr25519Sign(contributionPayload(c,sha256(malformed)),miner)).toString('hex')},malformed)).rejects.toThrow('Noncanonical');
    const peer=new ContributionInbox(directory,scope,[address],100,()=>now);
    const expectedReceipt={hotkey:address,artifactSha256:digest};
    try{expect(await Promise.all([inbox.accept(envelope,bytes),peer.accept(envelope,bytes)])).toEqual([expectedReceipt,expectedReceipt]);}finally{peer.close();}
    inbox.close();inbox=new ContributionInbox(directory,scope,[address,otherAddress],100,()=>now);
    expect(await inbox.accept(envelope,bytes)).toEqual(expectedReceipt);
    const different=Buffer.from(JSON.stringify({schema:'sentinel-literal-miner/v1',rules:[{id:'changed',literal:'other'}]}));
    const conflicting={...envelope,artifactSha256:sha256(different),signature:Buffer.from(sr25519Sign(contributionPayload(c,sha256(different)),miner)).toString('hex')};
    await expect(inbox.accept(conflicting,different)).rejects.toThrow('nonce conflict');
    expect(inbox.candidates()).toEqual([{participant:address,submission:reference}]);
    const expired=inbox.issue(otherAddress);now=expired.expiresAt;
    await expect(inbox.accept({...envelope,challenge:expired,signature:Buffer.from(sr25519Sign(contributionPayload(expired,digest),other)).toString('hex')},bytes)).rejects.toThrow('Expired');
    expect(await inbox.accept(envelope,bytes)).toEqual(expectedReceipt);
    const revoked=new ContributionInbox(directory,scope,[otherAddress],100,()=>now);
    try{expect(revoked.candidates()).toEqual([]);await expect(revoked.accept(envelope,bytes)).rejects.toThrow('Ineligible');}finally{revoked.close();}
    await inbox.attestAdmission(signed,async payload=>Buffer.from(sr25519Sign(payload,validator)).toString('hex'));
    inbox.closePractice('d'.repeat(64),1,'e'.repeat(64));
    const frozen=inbox.exportPractice();
    expect(await inbox.accept(envelope,bytes)).toEqual(expectedReceipt);
    expect(await inbox.accept({...envelope,signature:Buffer.from(sr25519Sign(contributionPayload(c,digest),miner)).toString('hex')},bytes)).toEqual(expectedReceipt);
    expect(inbox.exportPractice()).toEqual(frozen);
    await expect(inbox.accept(conflicting,different)).rejects.toThrow('nonce conflict');
    expect(inbox.candidates()).toHaveLength(1);
    const report=await inbox.evaluatePractice();
    expect(report.authentication.scope).toEqual(scope);
    expect(report.results[0].participants).toEqual([address]);expect(report.results[0].comparison.candidate).toMatchObject({tp:4,fp:0});
    expect(()=>new ContributionInbox(join(directory,'bad'),{...scope,validator:encodeAddress(validator.publicKey,0)},[address],100)).toThrow();
  }finally{inbox.close();await rm(directory,{recursive:true,force:true});}
});
