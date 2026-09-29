
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,rm,readFile} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {contributionSigningBytes,envelopeBytes,type ContributionPayload} from '../src/engine-contribution';
import {type IntakeConfig} from '../src/engine-intake';
import {holdoutBankDigest,holdoutCommitmentPayload,type HoldoutBank,type HoldoutCase} from '../src/holdout';
import {jcsBytes} from '../src/jcs';

export const sha=(b:string|Uint8Array)=>createHash('sha256').update(b).digest('hex');
export const root=new URL('..',import.meta.url).pathname;
export function holdoutCase(family:string,variant:number,buggy:boolean):HoldoutCase{
  const name=`e_${sha(`${family}:${variant}`).slice(0,8)}`;let fixed:string,bug:string,expression:string,expected:unknown;
  if(family==='negative-modulo'){
    fixed=`export function run(i, n) {\n  const ${name} = ((i % n) + n) % n;\n  return ${name};\n}\n`;
    bug=fixed.replace('((i % n) + n) % n','i % n');expression=`[run(-1, ${5+variant}), run(3, ${5+variant})]`;expected=[4+variant,3];
  }else{
    fixed=`export function run(lo, hi) {\n  let ${name} = 0;\n  for (let i = lo; i <= hi; i++) ${name} += i;\n  return ${name};\n}\n`;
    bug=fixed.replace('i <= hi;','i < hi;');expression=`run(1, ${3+variant})`;expected=(3+variant)*(4+variant)/2;
  }
  const files={'main.js':buggy?bug:fixed};
  return {input:{schema:'sentinel-practice-input/v1',id:sha(JSON.stringify([family,variant,buggy,files])),files,changedFiles:['main.js']},
    family,lineage:`${family}-l${variant}`,buggy,defectPath:'main.js',fixedFiles:{'main.js':fixed},oracle:{entry:'main.js',expression,expected}};
}

export async function setup(){
  await cryptoWaitReady();
  const dir=await mkdtemp('/tmp/opencode/engine-intake-'),at=(n:string)=>join(dir,n);
  const miner=sr25519PairFromSeed(randomBytes(32)),hotkey=Buffer.from(miner.publicKey).toString('hex');
  const ownerSeed=randomBytes(32),owner=encodeAddress(sr25519PairFromSeed(ownerSeed).publicKey,42),round='a'.repeat(64);
  const bank:HoldoutBank={schema:'sentinel-holdout-bank/v1',salt:randomBytes(32).toString('hex'),
    cases:['negative-modulo','inclusive-range'].flatMap(f=>[0,1].flatMap(v=>[true,false].map(b=>holdoutCase(f,v,b))))};
  await writeFile(at('bank'),JSON.stringify(bank),{mode:0o600});
  const unsigned={schema:'sentinel-holdout-commitment/v1' as const,round,owner,bankSha256:holdoutBankDigest(bank),cases:bank.cases.length,committedAt:1};
  const commitment={...unsigned,signature:Buffer.from(sr25519Sign(holdoutCommitmentPayload(unsigned),sr25519PairFromSeed(ownerSeed))).toString('hex')};
  const {privateKey}=generateKeyPairSync('ed25519');
  await writeFile(at('receipt.pem'),privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  // Local origin: serves /<revision>/<path>; a few paths misbehave on purpose.
  const origin=new Map<string,Uint8Array>();
  const originServer=Bun.serve({hostname:'127.0.0.1',port:0,async fetch(req){
    const path=new URL(req.url).pathname;
    if(path.endsWith('/redirect.json'))return Response.redirect('http://169.254.169.254/latest',302);
    if(path.endsWith('/slow.json'))await Bun.sleep(3000);
    const body=origin.get(path.split('/').slice(2).join('/'));return body?new Response(Buffer.from(body)):new Response('missing',{status:404});
  }});
  const fixture=JSON.parse(readFileSync(join(root,'tests/fixtures/engine-contribution-payload.json'),'utf8'));
  const now=Math.floor(Date.now()/1000);
  const payload=(files:Record<string,string>,nonce:string,extra:(p:any)=>void=()=>{}):ContributionPayload=>{
    const p=structuredClone(fixture);p.submitter.hotkey_public_key=hotkey;p.nonce=nonce;p.issued_at=String(now-10);p.expires_at=String(now+600);
    p.artifact.files=Object.entries(files).sort(([a],[b])=>a<b?-1:1).map(([path,text])=>({path,sha256:sha(text),bytes:String(Buffer.byteLength(text)),media_type:'application/json',role:path==='LICENSE'?'license':'entrypoint'}));
    p.artifact.entrypoint='rules.json';p.provenance.license_files=['LICENSE'];p.provenance.source_revisions=[];
    p.origins=p.artifact.files.map((f:any)=>({origin_id:'local',immutable_revision:'0'.repeat(40),file_path:f.path,artifact_path:f.path}));
    p.format.id='retrieval-profile/v1';p.lane='retrieval';
    extra(p);p.artifact.files_sha256=sha(jcsBytes(p.artifact.files));return p;
  };
  const envelope=(p:ContributionPayload)=>envelopeBytes(p,Buffer.from(sr25519Sign(contributionSigningBytes(p),miner)).toString('hex'));
  const config:IntakeConfig={db:at('intake.sqlite'),sealed_dir:at('sealed'),hostname:'127.0.0.1',port:0,receipt_key_path:at('receipt.pem'),
    expectation:{network:fixture.network,window_id:fixture.window_id,policy_sha256:fixture.policy_sha256,baseline_bundle_sha256:fixture.baseline_bundle_sha256,max_lifetime_seconds:'3600',max_skew_seconds:'60'},
    limits:{body_timeout_ms:500,fetch_timeout_ms:1000,sandbox_timeout_ms:10000,sandbox_output_bytes:1<<20,max_attempts_per_content:2,max_attempts_per_hotkey:20,lease_ms:60000},
    origins:{local:{base_url:`http://127.0.0.1:${originServer.port}/`}},registration:{mode:'local_allowlist',hotkeys:[hotkey]},
    holdout:{commitment,owner,round,bank_path:at('bank')},insecure_loopback_origins:true};
  const writeConfig=async(c=config)=>{await writeFile(at('config.json'),JSON.stringify(c));return at('config.json');};
  const put=(files:Record<string,string>)=>{for(const [k,v] of Object.entries(files))origin.set(k,Buffer.from(v));};
  const cleanup=async()=>{originServer.stop(true);await rm(dir,{recursive:true,force:true});};
  return {dir,at,bank,config,payload,envelope,writeConfig,put,cleanup,hotkey,now};
}
