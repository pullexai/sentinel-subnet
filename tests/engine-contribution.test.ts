import {expect,test} from 'bun:test';
import {cryptoWaitReady,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {createHash} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {ContributionNonceLedger,contributionDomain,contributionId,contributionSigningBytes,envelopeBytes,verifyContribution,type ContributionExpectation,type ContributionPayload} from '../src/engine-contribution';
import {jcs,jcsBytes} from '../src/jcs';

const h=(c:string)=>c.repeat(64),sha=(b:string|Uint8Array)=>createHash('sha256').update(b).digest('hex');
const seed=Buffer.alloc(32,7);
const fixture=JSON.parse(readFileSync(import.meta.dir+'/fixtures/engine-contribution-payload.json','utf8'));
function payload(hotkey:string):ContributionPayload{const p=structuredClone(fixture);p.submitter.hotkey_public_key=hotkey;return p;}
const expectation=(p:ContributionPayload):ContributionExpectation=>({network:structuredClone(p.network),window_id:p.window_id,policy_sha256:p.policy_sha256,
  baseline_bundle_sha256:p.baseline_bundle_sha256,now:1790000100n,max_lifetime_seconds:3600n,max_skew_seconds:60n});

// Child processes sign and verify so no in-process state can mask a byte mismatch.
async function run(script:string,input:string){
  const child=Bun.spawn([process.execPath,'-e',script],{cwd:import.meta.dir+'/..',stdin:'pipe',stdout:'pipe',stderr:'pipe'});
  child.stdin.write(input);child.stdin.end();
  const [code,out,err]=await Promise.all([child.exited,new Response(child.stdout).text(),new Response(child.stderr).text()]);
  if(code)throw new Error(err);return out;
}

test('signing bytes, identity and sr25519 roundtrip across separate processes',async()=>{
  await cryptoWaitReady();
  const pair=sr25519PairFromSeed(seed),hotkey=Buffer.from(pair.publicKey).toString('hex'),p=payload(hotkey);
  const message=contributionSigningBytes(p);
  expect(message.subarray(0,contributionDomain.length).toString()).toBe('sentinel-engine-contribution/v1\n');
  expect(message.subarray(contributionDomain.length)).toEqual(jcsBytes(p));
  // Pinned vector: fixed payload -> fixed identity. Update only with a new protocol version.
  expect(contributionId(p)).toBe(sha(message));
  expect(sha(message)).toBe('6fec465475ff33b3b5d4c64582a2c0a33b88ea8d1214af4170c32d98800ccb67');
  const wire=(await run(`import {sr25519PairFromSeed,sr25519Sign,cryptoWaitReady} from '@polkadot/util-crypto';
    import {contributionSigningBytes,envelopeBytes} from './src/engine-contribution';
    await cryptoWaitReady();const p=JSON.parse(await Bun.stdin.text()),k=sr25519PairFromSeed(Buffer.alloc(32,7));
    process.stdout.write(envelopeBytes(p,Buffer.from(sr25519Sign(contributionSigningBytes(p),k)).toString('hex')).toString('hex'));`,JSON.stringify(p))).trim();
  const verified=JSON.parse(await run(`import {verifyContribution} from './src/engine-contribution';
    const {wire,e}=JSON.parse(await Bun.stdin.text());
    const r=await verifyContribution(Buffer.from(wire,'hex'),{...e,now:BigInt(e.now),max_lifetime_seconds:BigInt(e.max_lifetime_seconds),max_skew_seconds:BigInt(e.max_skew_seconds)});
    process.stdout.write(JSON.stringify(r.contribution_id));`,
    JSON.stringify({wire,e:{...expectation(p),now:'1790000100',max_lifetime_seconds:'3600',max_skew_seconds:'60'}})));
  expect(verified).toBe(contributionId(p));
  const again=envelopeBytes(p,Buffer.from(sr25519Sign(message,pair)).toString('hex'));
  expect(again.toString('hex')).not.toBe(wire);
  expect((await verifyContribution(again,expectation(p))).contribution_id).toBe(verified);
});

test('rejects tampering, wrong domains, ambiguity and replay',async()=>{
  await cryptoWaitReady();
  const pair=sr25519PairFromSeed(seed),other=sr25519PairFromSeed(Buffer.alloc(32,8)),hotkey=Buffer.from(pair.publicKey).toString('hex');
  const p=payload(hotkey),e=expectation(p),sign=(x:ContributionPayload,k=pair)=>Buffer.from(sr25519Sign(contributionSigningBytes(x),k)).toString('hex');
  const good=envelopeBytes(p,sign(p));
  await verifyContribution(good,e);
  const text=good.toString();
  const rejects=async(bytes:Uint8Array|string,x=e)=>expect(verifyContribution(typeof bytes==='string'?Buffer.from(bytes):bytes,x)).rejects.toThrow();
  // Wire ambiguity.
  await rejects(text.replace('{"payload":','{"payload":{},"payload":'));
  await rejects(text.replace('"lane":"detection"','"lane":"detection","lane":"detection"'));
  await rejects(JSON.stringify({signature:JSON.parse(text).signature,payload:JSON.parse(text).payload}));
  await rejects(text.replace('"window_id":"w-2026-10"','"window_id":"w-2026-1\\u0030"'));
  await rejects(text+'\n');await rejects(text.replace(':',': '));
  await rejects(text.replace('"netuid":"42"','"netuid":42'));
  await rejects(Buffer.concat([Buffer.from(text.slice(0,-1)),Buffer.from([0xff]),Buffer.from('}')]));
  // Mutations of signed or envelope fields (canonical re-encoding, so only semantics differ).
  const mutate=async(edit:(x:any)=>void,resign=false)=>{
    const x=structuredClone(p) as any;edit(x);
    // Encoding a lone surrogate already fails in JCS; that is also a rejection.
    let bytes:Uint8Array;
    try{bytes=envelopeBytes(x,resign?Buffer.from(sr25519Sign(Buffer.concat([Buffer.from(contributionDomain),jcsBytes(x)]),pair)).toString('hex'):sign(p));}catch{return;}
    return rejects(bytes,e);
  };
  await mutate(x=>{x.nonce='1';});await mutate(x=>{x.lane='fix';});
  for(const edit of [(x:any)=>{x.protocol='sentinel-engine-contribution/v2';},(x:any)=>{x.extra=1;},(x:any)=>{x.lane='security';},
    (x:any)=>{x.nonce='01';},(x:any)=>{x.nonce='-1';},(x:any)=>{x.nonce='18446744073709551616';},(x:any)=>{x.issued_at='2026-09-26T00:00:00Z';},
    (x:any)=>{x.network.netuid='65536';},(x:any)=>{x.window_id='W\ud800';},(x:any)=>{x.capabilities.languages=['typescript','python'];},
    (x:any)=>{x.capabilities.languages=['python','python'];},(x:any)=>{x.artifact.entrypoint='missing.json';},(x:any)=>{x.artifact.files_sha256=h('0');},
    (x:any)=>{x.artifact.files[1].path='../rules.json';},(x:any)=>{x.change.operation='replace';},(x:any)=>{x.format.id='wasm/v1';},
    (x:any)=>{x.policy_sha256=h('A');},(x:any)=>{x.expires_at=x.issued_at;},(x:any)=>{x.provenance.training_data_statement_sha256=h('9');}])await mutate(edit,true);
  const wrap=(o:object)=>rejects(jcsBytes(o));
  const sig=JSON.parse(text).signature;
  await wrap({payload:p,signature:{...sig,scheme:'ed25519'}});
  await wrap({payload:p,signature:{...sig,public_key:Buffer.from(other.publicKey).toString('hex')}});
  await wrap({payload:p,signature:{...sig,value:sig.value.toUpperCase()}});
  await wrap({payload:p,signature:{...sig,value:sign(p,other)}});
  // Legacy practice signature over another domain is not reusable.
  await wrap({payload:p,signature:{...sig,value:Buffer.from(sr25519Sign(jcsBytes(p),pair)).toString('hex')}});
  // Wrong chain/window/time expectations.
  await rejects(good,{...e,network:{...e.network,genesis_hash:h('0')}});
  await rejects(good,{...e,network:{...e.network,netuid:'43'}});
  await rejects(good,{...e,window_id:'w-other'});
  for(const now of [1789999900n,1790000600n])await rejects(good,{...e,now});
  await rejects(good,{...e,max_lifetime_seconds:599n});
  // Durable nonce fence.
  const dir=await mkdtemp('/tmp/opencode/engine-nonce-');
  try{
    const ledger=new ContributionNonceLedger(dir+'/nonces.sqlite'),v=await verifyContribution(good,e);
    expect(ledger.record(v)).toBe('received');expect(ledger.record(v)).toBe('replay');
    const q={...structuredClone(p),lane:'retrieval'} as ContributionPayload;
    expect(()=>ledger.record(await_(q))).toThrow('nonce_conflict');
    ledger.close();
    const reopened=new ContributionNonceLedger(dir+'/nonces.sqlite');expect(reopened.record(v)).toBe('replay');reopened.close();
  }finally{await rm(dir,{recursive:true,force:true});}
  function await_(x:ContributionPayload){return {payload:x,contribution_id:contributionId(x)};}
});
