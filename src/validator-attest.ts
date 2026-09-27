import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {boundedFile} from './replay';
import {snapshotByteLimit,type SnapshotExpectation} from './protocol';
import {VoteJournal} from './vote-journal';
import {quorumPolicyDigest,type QuorumPolicy} from './attestations';

if(import.meta.main){
  let journal:VoteJournal|undefined;
  try{
    const [snapshot,expectations,policyPath,validator,keyPath,directory,...extra]=process.argv.slice(2);
    if(!snapshot || !expectations || !policyPath || !validator || !keyPath || !directory || extra.length)throw new Error('Usage: validator-attest.ts SNAPSHOT EXPECTATIONS POLICY VALIDATOR PRIVATE_SEED JOURNAL_DIRECTORY');
    const json=async(path:string)=>{
      const text=new TextDecoder('utf-8',{fatal:true}).decode(await boundedFile(path,1024*1024)),value=JSON.parse(text);
      if(JSON.stringify(value)!==text)throw new Error('Compact canonical JSON required');return value;
    };
    const expected=await json(expectations) as SnapshotExpectation,policy=await json(policyPath) as QuorumPolicy;
    quorumPolicyDigest(policy);
    journal=new VoteJournal(directory,policy);
    const result=await journal.evaluateAndSign(await boundedFile(snapshot,snapshotByteLimit),expected,validator,
      async payload=>{
        // Practice-only local custody: load no secret until evaluation finishes and
        // the durable lock is committed. Network custody needs an isolated signer.
        const seed=await boundedFile(keyPath,32,true);let key:ReturnType<typeof sr25519PairFromSeed>|undefined;
        try{
          if(seed.length!==32)throw new Error('Private seed must contain exactly 32 raw bytes');
          await cryptoWaitReady();key=sr25519PairFromSeed(seed);seed.fill(0);
          if(encodeAddress(key.publicKey,42)!==validator)throw new Error('Signing key does not match validator');
          return Buffer.from(sr25519Sign(payload,key)).toString('hex');
        }finally{seed.fill(0);key?.secretKey.fill(0);}
      });
    console.log(JSON.stringify(result));
  }catch(error){console.error(error instanceof Error?error.message:'Validator attestation failed');process.exitCode=1;}
  finally{journal?.close();}
}
