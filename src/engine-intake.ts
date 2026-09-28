import {Database} from 'bun:sqlite';
import {createHash,createPrivateKey,createPublicKey,randomBytes,sign as edSign,type KeyObject} from 'node:crypto';
import {lookup} from 'node:dns/promises';
import {mkdir,rm,writeFile,chmod,readFile,readdir} from 'node:fs/promises';
import {realpathSync,existsSync} from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import {BlockList,isIP} from 'node:net';
import {dirname,join} from 'node:path';
import {ContributionNonceLedger,checkBinding,contributionMediaType,contributionByteLimit,verifyEnvelopeSignature,type ContributionExpectation,type ContributionPayload} from './engine-contribution';
import {caseFromPractice} from './engine-case';
import {Unqualified,registry,requiredEvidence,runProfile,scoreRetrieval,validateOutput,validateProfile,type RetrievalGold} from './engine-retrieval';
import {proveFixture,type Fixture} from './corpus';
import {admitHoldoutBank,parseHoldoutJSON,verifyHoldoutCommitment,holdoutByteLimit,type HoldoutCommitment} from './holdout';
import {jcs,jcsBytes} from './jcs';
import {boundedFile} from './replay';

// EC-03 local intake: HTTP intake, durable SQLite receipts/queue, bounded origin fetcher, sealed store,
// sandboxed evaluation against a sealed holdout the artifact process never sees.
// Items that need finalized chain state, btauth/1 or independent operators are reported as `unverified`.
export const unverifiedChecks=['finalized_registration_lineage','btauth_transport','signed_engine_policy','independent_operators','execution_profile_qualification'] as const;
export type ReceiptState='received'|'admitted'|'rejected'|'policy_unresolved';
export type IntakeConfig={
  db:string;sealed_dir:string;hostname:'127.0.0.1';port:number;receipt_key_path:string;
  expectation:{network:ContributionExpectation['network'];window_id:string;policy_sha256:string;baseline_bundle_sha256:string;max_lifetime_seconds:string;max_skew_seconds:string};
  limits:{body_timeout_ms:number;fetch_timeout_ms:number;sandbox_timeout_ms:number;sandbox_output_bytes:number;max_attempts_per_content:number;max_attempts_per_hotkey:number;lease_ms:number}|null;
  origins:Record<string,{base_url:string}>|null;
  // ponytail: operator allowlist stands in for finalized registration; null keeps every contribution `received`.
  registration:{mode:'local_allowlist';hotkeys:string[]}|null;
  holdout:{commitment:HoldoutCommitment;owner:string;round:string;bank_path:string}|null;
  insecure_loopback_origins?:boolean; // Tests only: permits http:// and 127.0.0.0/8 origins.
};
const sha256=(b:Uint8Array|string)=>createHash('sha256').update(b).digest('hex');
const fail=(reason:string):never=>{throw Object.assign(new Error(reason),{reason});};
export const unresolvedPolicy=(c:IntakeConfig)=>(['limits','origins','holdout'] as const).filter(k=>!c[k]);
// EC-10 approximation of execution-content identity: everything that changes what runs, nothing about who/when.
// ponytail: exact bytes only; semantic clone families belong to EC-10 proper.
export const contentId=(p:ContributionPayload)=>sha256('sentinel-engine-content/v1\n'+jcs({format:p.format,files:p.artifact.files,entrypoint:p.artifact.entrypoint,components:p.components,change:p.change,capabilities:p.capabilities,execution_profile_sha256:p.execution_profile_sha256,output_schema_sha256:p.output_schema_sha256}));

export class EngineStore{
  db:Database;ledger:ContributionNonceLedger;key:KeyObject;keyId:string;
  constructor(readonly config:IntakeConfig,keyPem:string){
    this.db=new Database(config.db,{create:true,strict:true});
    this.ledger=new ContributionNonceLedger(this.db);
    this.db.exec(`CREATE TABLE IF NOT EXISTS engine_receipts(contribution_id TEXT PRIMARY KEY,domain TEXT NOT NULL,hotkey TEXT NOT NULL,nonce TEXT NOT NULL,content_id TEXT NOT NULL,state TEXT NOT NULL,reason TEXT,envelope BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS engine_attempts(scope TEXT NOT NULL,key TEXT NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(scope,key));
      CREATE TABLE IF NOT EXISTS engine_queue(contribution_id TEXT PRIMARY KEY,state TEXT NOT NULL,lease_token TEXT,lease_expires INTEGER NOT NULL DEFAULT 0,infra_retries INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS engine_evaluations(contribution_id TEXT PRIMARY KEY,report_sha256 TEXT NOT NULL,report TEXT NOT NULL);`);
    this.key=createPrivateKey(keyPem);
    if(this.key.asymmetricKeyType!=='ed25519')throw new Error('Receipt key must be Ed25519');
    this.keyId=sha256(createPublicKey(this.key).export({type:'spki',format:'der'}));
  }
  // Deterministic: derived only from durable state; Ed25519 signatures are deterministic too.
  receipt(id:string){
    const r=this.db.query('SELECT * FROM engine_receipts WHERE contribution_id=?').get(id) as any;
    if(!r)return null;
    const payload={schema:'sentinel-engine-receipt/v1',contribution_id:id,hotkey:r.hotkey,nonce:r.nonce,state:r.state as ReceiptState,reason:r.reason ?? null,unverified:[...unverifiedChecks]};
    const value=edSign(null,Buffer.concat([Buffer.from('sentinel-engine-receipt/v1\n'),jcsBytes(payload)]),this.key).toString('hex');
    return jcsBytes({payload,signature:{scheme:'ed25519',key_id:this.keyId,value}});
  }
  setState(id:string,state:ReceiptState,reason:string|null){this.db.query('UPDATE engine_receipts SET state=?,reason=? WHERE contribution_id=?').run(state,reason,id);}

  // EC-02 order: bounded canonical parse/schema, signature, existing-receipt replay, binding, registration and quota,
  // then one immediate transaction records nonce, receipt, attempts and queue entry together.
  async submit(bytes:Uint8Array,now:bigint):Promise<{status:number;body:Uint8Array}>{
    const error=(status:number,reason:string)=>({status,body:jcsBytes({error:reason})});
    let v;try{v=await verifyEnvelopeSignature(bytes);}catch(e){return error(400,e instanceof Error?e.message:'invalid envelope');}
    const existing=this.receipt(v.contribution_id);
    if(existing)return {status:200,body:existing};
    const c=this.config,e=c.expectation;
    try{checkBinding(v.payload,{network:e.network,window_id:e.window_id,policy_sha256:e.policy_sha256,baseline_bundle_sha256:e.baseline_bundle_sha256,now,max_lifetime_seconds:BigInt(e.max_lifetime_seconds),max_skew_seconds:BigInt(e.max_skew_seconds)});}
    catch(x){return error(422,x instanceof Error?x.message:'binding');}
    const p=v.payload,content=contentId(p),unresolved=unresolvedPolicy(c);
    let state:ReceiptState='received',reason:string|null=null,queue=false;
    if(unresolved.length){state='policy_unresolved';reason='unset: '+unresolved.join(',');}
    else if(!c.registration)reason='registration_unverified';
    else if(!c.registration.hotkeys.includes(p.submitter.hotkey_public_key)){state='rejected';reason='not_registered';}
    else queue=true;
    try{
      const recorded=this.ledger.record(v,()=>{
        if(queue){
          const count=(scope:string,key:string)=>(this.db.query('SELECT count FROM engine_attempts WHERE scope=? AND key=?').get(scope,key) as {count:number}|null)?.count ?? 0;
          if(count('content',content)>=c.limits!.max_attempts_per_content || count('hotkey',p.submitter.hotkey_public_key)>=c.limits!.max_attempts_per_hotkey)fail('attempt_quota_exhausted');
          for(const [scope,key] of [['content',content],['hotkey',p.submitter.hotkey_public_key]])
            this.db.query('INSERT INTO engine_attempts VALUES(?,?,1) ON CONFLICT(scope,key) DO UPDATE SET count=count+1').run(scope,key);
          this.db.query("INSERT INTO engine_queue(contribution_id,state) VALUES(?,'queued')").run(v.contribution_id);
        }
        this.db.query('INSERT INTO engine_receipts VALUES(?,?,?,?,?,?,?,?)').run(v.contribution_id,jcs(p.network),p.submitter.hotkey_public_key,p.nonce,content,state,reason,Buffer.from(bytes));
      });
      return {status:recorded==='received'?202:200,body:this.receipt(v.contribution_id)!};
    }catch(x){
      const r=(x as {message?:string}).message;
      return r==='nonce_conflict'?error(409,r):r==='attempt_quota_exhausted'?error(429,r):error(500,'intake failure');
    }
  }

  // Lease survives crashes: an expired lease is re-leased; infrastructure retries never touch attempts.
  lease(now:number){
    return this.db.transaction(()=>{
      const row=this.db.query("SELECT contribution_id FROM engine_queue WHERE state='queued' OR (state='leased' AND lease_expires<=?) ORDER BY contribution_id LIMIT 1").get(now) as {contribution_id:string}|null;
      if(!row)return null;
      const token=randomBytes(16).toString('hex');
      this.db.query("UPDATE engine_queue SET state='leased',lease_token=?,lease_expires=?,infra_retries=infra_retries+(state='leased') WHERE contribution_id=?").run(token,now+this.config.limits!.lease_ms,row.contribution_id);
      return {id:row.contribution_id,token};
    }).immediate();
  }
  // Completion is fenced by the lease token: a worker whose lease was taken over cannot write twice.
  complete(lease:{id:string;token:string},state:ReceiptState,reason:string|null,report:object|null){
    return this.db.transaction(()=>{
      if(!this.db.query("UPDATE engine_queue SET state='done',lease_token=NULL WHERE contribution_id=? AND state='leased' AND lease_token=?").run(lease.id,lease.token).changes)return false;
      this.setState(lease.id,state,reason);
      if(report){const text=jcs(report);this.db.query('INSERT INTO engine_evaluations VALUES(?,?,?)').run(lease.id,sha256('sentinel-engine-evaluation/v1\n'+text),text);}
      return true;
    }).immediate();
  }
  payload(id:string){return JSON.parse(Buffer.from((this.db.query('SELECT envelope FROM engine_receipts WHERE contribution_id=?').get(id) as {envelope:Uint8Array}).envelope).toString()).payload as ContributionPayload;}
  close(){this.db.close();}
}

// ---- Fetcher: manifest-listed raw files from approved immutable origins only.
const denied=new BlockList();
for(const [a,n] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.168.0.0',16],['198.18.0.0',15],['224.0.0.0',4],['240.0.0.0',4]] as const)denied.addSubnet(a,n,'ipv4');
for(const [a,n] of [['::',128],['::1',128],['::ffff:0:0',96],['64:ff9b::',96],['2002::',16],['fc00::',7],['fe80::',10],['ff00::',8]] as const)denied.addSubnet(a,n,'ipv6');
const loopback=(ip:string)=>isIP(ip)===4 && ip.startsWith('127.');
// Resolve once, validate every address, connect to the validated one: no DNS rebinding window.
async function pinned(host:string,allowLoopback:boolean){
  const addresses=await lookup(host,{all:true,verbatim:true});
  if(!addresses.length || addresses.some(a=>denied.check(a.address,a.family===6?'ipv6':'ipv4') && !(allowLoopback && loopback(a.address))))fail('origin_address_denied');
  return addresses[0];
}
function download(url:URL,address:{address:string;family:number},declared:number,timeoutMs:number){
  return new Promise<{bytes:Buffer;sha256:string}>((resolve,reject)=>{
    const hash=createHash('sha256'),chunks:Buffer[]=[];let total=0;
    const req=(url.protocol==='https:'?https:http).get({hostname:url.hostname,port:url.port || undefined,path:url.pathname,servername:isIP(url.hostname)?undefined:url.hostname,
      headers:{'accept-encoding':'identity'},agent:false,
      lookup:(_h:string,o:any,cb:any)=>o?.all?cb(null,[address]):cb(null,address.address,address.family)},res=>{
      // Redirects and every non-200 are rejected: no following to unapproved destinations.
      if(res.statusCode!==200){res.resume();return done(new Error('origin_status_'+res.statusCode));}
      const length=res.headers['content-length'];
      if(length!==undefined && Number(length)!==declared)return done(new Error('artifact_length_mismatch'));
      res.on('data',(chunk:Buffer)=>{total+=chunk.length;if(total>declared)return done(new Error('artifact_length_mismatch'));hash.update(chunk);chunks.push(chunk);});
      res.on('end',()=>total===declared?done(null):done(new Error('artifact_length_mismatch')));
      res.on('error',done);
    });
    const timer=setTimeout(()=>done(new Error('artifact_fetch_timeout')),timeoutMs);
    req.on('error',done);
    let settled=false;
    function done(error:Error|null){
      if(settled)return;settled=true;clearTimeout(timer);req.destroy();
      error?reject(Object.assign(error,{reason:error.message})):resolve({bytes:Buffer.concat(chunks),sha256:hash.digest('hex')});
    }
  });
}
export async function fetchAndSeal(p:ContributionPayload,config:IntakeConfig,directory:string){
  const origins=config.origins!,insecure=config.insecure_loopback_origins===true;
  const byPath=new Map(p.origins.map(o=>[o.artifact_path,o]));
  await rm(directory,{recursive:true,force:true});await mkdir(directory,{recursive:true,mode:0o700});
  for(const file of p.artifact.files){
    const origin=byPath.get(file.path) ?? fail('artifact_file_without_origin');
    const approved=origins[origin.origin_id] ?? fail('origin_not_approved');
    if(!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(origin.immutable_revision))fail('mutable_revision');
    const base=new URL(approved.base_url);
    if(base.username || base.password || base.search || base.hash || !(base.protocol==='https:' || insecure && base.protocol==='http:'))fail('origin_not_approved');
    const url=new URL(base.href.replace(/\/?$/,'/')+origin.immutable_revision+'/'+origin.file_path);
    if(url.origin!==base.origin)fail('origin_not_approved');
    const got=await download(url,await pinned(url.hostname,insecure),Number(file.bytes),config.limits!.fetch_timeout_ms);
    if(got.sha256!==file.sha256)fail('artifact_hash_mismatch');
    const target=join(directory,file.path);
    await mkdir(dirname(target),{recursive:true,mode:0o755});
    await writeFile(target,got.bytes,{flag:'wx',mode:0o444}); // wx: never follows or overwrites an existing entry.
  }
  await chmod(directory,0o555);
}
// Re-hash sealed bytes before every run; exactly the listed files must be present.
export async function verifySealed(p:ContributionPayload,directory:string){
  const present=(await readdir(directory,{recursive:true,withFileTypes:true})).filter(d=>!d.isDirectory()).map(d=>join(d.parentPath,d.name).slice(directory.length+1)).sort();
  if(jcs(present)!==jcs(p.artifact.files.map(f=>f.path)))fail('sealed_set_mismatch');
  for(const f of p.artifact.files)if(sha256(await readFile(join(directory,f.path)))!==f.sha256)fail('sealed_hash_mismatch');
}

// ---- Sandbox: separate process, no network, no host filesystem except the sealed artifact and adapter code.
// ponytail: bubblewrap + nobody uid is a local stand-in; memory/CPU cgroups and the qualified EX profile belong to execution-profile.md.
export async function runSandbox(o:{appDir:string;script:string;args:string[];artifactDir:string;stdin:Uint8Array;timeoutMs:number;maxOutput:number}){
  if(!Bun.which('bwrap'))fail('sandbox_unavailable');
  const libs=['/lib','/lib64','/usr/lib','/usr/lib64'].filter(existsSync).flatMap(d=>['--ro-bind',d,d]);
  const child=Bun.spawn(['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--cap-drop','ALL','--uid','65534','--gid','65534',
    '--ro-bind',realpathSync(process.execPath),'/bun',...libs,'--proc','/proc','--dev','/dev','--tmpfs','/tmp',
    '--ro-bind',o.appDir,'/app','--ro-bind',o.artifactDir,'/artifact','--chdir','/tmp','/bun','/app/'+o.script,...o.args],
    {stdin:'pipe',stdout:'pipe',stderr:'ignore',timeout:o.timeoutMs,killSignal:'SIGKILL',env:{}});
  child.stdin.write(o.stdin);child.stdin.end();
  const chunks:Uint8Array[]=[];let total=0;
  for await(const chunk of child.stdout){total+=chunk.length;if(total>o.maxOutput){child.kill('SIGKILL');break;}chunks.push(chunk);}
  const code=await child.exited;
  if(child.signalCode==='SIGKILL' && total<=o.maxOutput)fail('sandbox_timeout');
  if(total>o.maxOutput)fail('sandbox_output_limit');
  if(code!==0)fail('sandbox_failed');
  return Buffer.concat(chunks).toString('utf8');
}

// ---- Worker: trusted process holding the sealed holdout; the artifact sees only `sentinel-engine-case/v1` bundles on stdin.
// Formats whose EC-04/06/07 adapters need an unqualified external engine or model are rejected, never simulated.
export const unqualifiedFormats:Record<string,string>={
  'structural-rule/v1':'needs a qualified ast-grep engine/grammar build (EC-04)',
  'taint-rule/v1':'needs a qualified Opengrep analysis profile (EC-04)',
  'tensor-model/v1':'needs a qualified model runtime and architecture ABI (EC-06)',
  'lora-adapter/v1':'needs a qualified base model and PEFT runtime (EC-06)',
  'fix-template/v1':'needs a qualified structural matcher and challenge-fix-test/v1 profile (EC-07)',
};
export const caseQuery='Locate the code regions most relevant to reviewing the changed files for defects.';
export async function loadHoldout(config:IntakeConfig){
  const h=config.holdout!,commitment=await verifyHoldoutCommitment(h.commitment,h.round,h.owner);
  // Lineage separation: admitHoldoutBank rejects lineages that span families, public-template families and missing polarity.
  const bank=admitHoldoutBank(parseHoldoutJSON(await boundedFile(h.bank_path,holdoutByteLimit,true)),commitment,[]);
  const fixtures=structuredClone(bank.cases) as unknown as Fixture[];
  for(const f of fixtures)await proveFixture(f);
  // Engine cases are derived with the bank salt, so file IDs and family commitments are unlinkable to public data.
  const cases=bank.cases.map(c=>{
    const {bundle,fileId}=caseFromPractice(c.input,bank.salt,c.lineage,'retrieval',caseQuery);
    const evidence=c.buggy?{file_id:fileId(c.defectPath),...requiredEvidence(c.input.files[c.defectPath],c.fixedFiles[c.defectPath])}:null;
    return {bundle,gold:{case_input_id:bundle.case.case_input_id,evidence} as RetrievalGold};
  });
  return {fixtures,cases,bankSha256:commitment.bankSha256};
}
export const baselineProfile={schema:'retrieval-profile/v1',chunker_component_sha256:registry.chunker.id,index_schema_sha256:registry.index.id,embedding_component_sha256:null,
  stages:[{operator:'lexical_bm25',params:{query_source:'query_text',k1:{numerator:'6',denominator:'5'},b:{numerator:'3',denominator:'4'},top_k:'8'}},{operator:'pack_context',params:{max_ranges:'4'}}],
  output_limit_ref:registry.output_limit.id};
export async function processOne(store:EngineStore,holdout:Awaited<ReturnType<typeof loadHoldout>>,now=Date.now()){
  const lease=store.lease(now);if(!lease)return null;
  const c=store.config,p=store.payload(lease.id),dir=join(c.sealed_dir,lease.id);
  const base={schema:'sentinel-engine-evaluation/v1',contribution_id:lease.id,format:p.format.id,files_sha256:p.artifact.files_sha256,holdout_bank_sha256:holdout.bankSha256,
    input_schema:'sentinel-engine-case/v1',isolation:'bwrap-local-unqualified',weights:null,rewards:null,unverified:[...unverifiedChecks]};
  if(Object.hasOwn(unqualifiedFormats,p.format.id)){
    // Nothing is fetched or executed: the attempt is recorded with an explicit, rank-independent reason.
    const reason='unqualified-engine';
    store.complete(lease,'rejected',reason,{...base,result:reason,detail:unqualifiedFormats[p.format.id],holdout:null});
    return {id:lease.id,state:'rejected',reason};
  }
  try{await fetchAndSeal(p,c,dir);await verifySealed(p,dir);}
  catch(x){const reason=(x as {reason?:string}).reason;if(!reason)throw x;store.complete(lease,'rejected',reason,null);return {id:lease.id,state:'rejected',reason};}
  // Pure-data admission in the trusted worker (bounded parser, no execution) so rejection reasons are exact.
  try{validateProfile(await readFile(join(dir,p.artifact.entrypoint)));}
  catch(x){const reason=x instanceof Unqualified?x.reason:'artifact_invalid';store.complete(lease,'rejected',reason,{...base,result:reason,detail:x instanceof Error?x.message:null,holdout:null});return {id:lease.id,state:'rejected',reason};}
  const stdin=Buffer.from(JSON.stringify(holdout.cases.map(x=>x.bundle)));
  let report:object;
  try{
    const out=JSON.parse(await runSandbox({appDir:import.meta.dir,script:'engine-sandbox.ts',args:[p.format.id,p.artifact.entrypoint],artifactDir:dir,stdin,timeoutMs:c.limits!.sandbox_timeout_ms,maxOutput:c.limits!.sandbox_output_bytes}));
    if(!Array.isArray(out) || out.length!==holdout.cases.length)fail('sandbox_output_invalid');
    // Trusted re-validation of every range against the verified file table; the adapter's word counts for nothing.
    const candidate=new Map(holdout.cases.map((x,i)=>[x.gold.case_input_id,validateOutput(out[i],x.gold.case_input_id,x.bundle.file_table)]));
    const reference=validateProfile(Buffer.from(JSON.stringify(baselineProfile)));
    const baseline=new Map(holdout.cases.map(x=>[x.gold.case_input_id,runProfile(reference,x.bundle)]));
    const gold=holdout.cases.map(x=>x.gold),b=scoreRetrieval(gold,baseline),k=scoreRetrieval(gold,candidate);
    const regressed=gold.filter(g=>b.hits.get(g.case_input_id) && !k.hits.get(g.case_input_id)).length;
    const strip=({hits,...rest}:typeof b)=>rest;
    report={...base,result:'scored',holdout:{baseline:strip(b),candidate:strip(k),regressed}};
  }catch(x){
    // Hostile or broken artifacts consume their reserved attempt; no retry, no score.
    report={...base,result:(x as {reason?:string}).reason ?? 'sandbox_output_invalid',holdout:null};
  }
  store.complete(lease,'admitted',null,report);
  return {id:lease.id,state:'admitted',report};
}

// ---- HTTP surface (EC-03 routes). Loopback only: no network activation is authorized.
export function serve(store:EngineStore,clock=()=>BigInt(Math.floor(Date.now()/1000))){
  const c=store.config;
  if(c.hostname!=='127.0.0.1')throw new Error('Only 127.0.0.1 is authorized');
  const json=(status:number,body:Uint8Array|object)=>new Response(body instanceof Uint8Array?Buffer.from(body):jcsBytes(body),{status,headers:{'content-type':'application/json'}});
  return Bun.serve({hostname:'127.0.0.1',port:c.port,maxRequestBodySize:contributionByteLimit,async fetch(req){
    const path=new URL(req.url).pathname;
    if(req.method==='POST' && path==='/engine/v1/contributions'){
      if(req.headers.get('content-type')!==contributionMediaType)return json(415,{error:'unsupported_media_type'});
      const reader=req.body?.getReader();if(!reader)return json(400,{error:'empty_body'});
      const chunks:Uint8Array[]=[];let total=0,timer:ReturnType<typeof setTimeout>|undefined;
      const deadline=new Promise<'timeout'>(r=>{timer=setTimeout(()=>r('timeout'),c.limits?.body_timeout_ms ?? 5000);});
      const read=(async()=>{for(;;){const {done,value}=await reader.read();if(done)return 'ok' as const;total+=value.length;if(total>contributionByteLimit)return 'large' as const;chunks.push(value);}})();
      const outcome=await Promise.race([read,deadline]);clearTimeout(timer);
      if(outcome!=='ok'){reader.cancel().catch(()=>{});return json(outcome==='timeout'?408:413,{error:outcome==='timeout'?'body_timeout':'body_too_large'});}
      const r=await store.submit(Buffer.concat(chunks),clock());return json(r.status,r.body);
    }
    let m;
    if(req.method==='GET' && (m=/^\/engine\/v1\/receipts\/([0-9a-f]{64})$/.exec(path))){const r=store.receipt(m[1]);return r?json(200,r):json(404,{error:'unknown_contribution'});}
    // Signed policy documents and EC-08/11 disclosure are not implemented: fixed answers independent of rank.
    if(req.method==='GET' && /^\/engine\/v1\/windows\/[a-z0-9][a-z0-9._-]{0,127}\/replay$/.test(path))return json(200,{state:'unavailable'});
    if(req.method==='GET' && /^\/engine\/v1\/policies\/[0-9a-f]{64}$/.test(path))return json(404,{error:'policy_unresolved'});
    return json(404,{error:'not_found'});
  }});
}

if(import.meta.main){
  const [action,configPath,...extra]=process.argv.slice(2);
  try{
    if(!configPath || extra.length || !['serve','work'].includes(action))throw new Error('Usage: engine-intake.ts serve|work CONFIG');
    const config=JSON.parse(await readFile(configPath,'utf8')) as IntakeConfig;
    const store=new EngineStore(config,await readFile(config.receipt_key_path,'utf8'));
    if(action==='serve'){const server=serve(store);console.log(JSON.stringify({listening:server.port}));}
    else{
      if(unresolvedPolicy(config).length)throw new Error('policy_unresolved');
      const holdout=await loadHoldout(config);let r;
      while((r=await processOne(store,holdout)))console.log(JSON.stringify({id:r.id,state:r.state,reason:'reason' in r?r.reason:null}));
      store.close();
    }
  }catch(error){console.error(error instanceof Error?error.message:'engine intake failed');process.exitCode=1;}
}
