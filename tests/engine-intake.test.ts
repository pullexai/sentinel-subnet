import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,rm,readFile} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {contributionMediaType,contributionSigningBytes,envelopeBytes,contributionId,type ContributionPayload} from '../src/engine-contribution';
import {EngineStore,runSandbox,unverifiedChecks,type IntakeConfig} from '../src/engine-intake';
import {holdoutBankDigest,holdoutCommitmentPayload,type HoldoutBank,type HoldoutCase} from '../src/holdout';
import {jcsBytes} from '../src/jcs';

const sha=(b:string|Uint8Array)=>createHash('sha256').update(b).digest('hex');
const root=new URL('..',import.meta.url).pathname;
function holdoutCase(family:string,variant:number,buggy:boolean):HoldoutCase{
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

async function setup(){
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
const spawnBun=(args:string[])=>Bun.spawn([process.execPath,...args],{cwd:root,env:{PATH:process.env.PATH},stdout:'pipe',stderr:'pipe'});
async function startServer(config:string){
  const child=spawnBun(['src/engine-intake.ts','serve',config]),reader=child.stdout.getReader();
  const {value}=await reader.read();reader.releaseLock();
  return {child,base:`http://127.0.0.1:${JSON.parse(new TextDecoder().decode(value)).listening}`};
}
async function work(config:string){
  const child=spawnBun(['src/engine-intake.ts','work',config]);
  const [out,err,code]=await Promise.all([new Response(child.stdout).text(),new Response(child.stderr).text(),child.exited]);
  expect(err).toBe('');expect(code).toBe(0);
  return out.trim().split('\n').filter(Boolean).map(l=>JSON.parse(l));
}
const post=(base:string,body:Uint8Array|string,type=contributionMediaType)=>fetch(base+'/engine/v1/contributions',{method:'POST',headers:{'content-type':type},body:typeof body==='string'?body:Buffer.from(body)});

test('intake, fetch, sandboxed evaluation and signed receipts across separate processes and restarts',async()=>{
  const s=await setup();
  const good={'LICENSE':'MIT\n','rules.json':JSON.stringify({schema:'sentinel-literal-miner/v1',rules:[{id:'mod-sign',literal:'= i % n;'},{id:'range-edge',literal:'i < hi;'}]})};
  s.put(good);s.put({'bad-hash.json':'x'});
  const config=await s.writeConfig();
  let server=await startServer(config);
  try{
    const p1=s.payload(good,'1'),e1=s.envelope(p1),id1=contributionId(p1);
    const r1=await post(server.base,e1);expect(r1.status).toBe(202);
    const receipt=Buffer.from(await r1.arrayBuffer());
    expect(JSON.parse(receipt.toString()).payload).toMatchObject({contribution_id:id1,state:'received',reason:null,unverified:[...unverifiedChecks]});
    // Rejections before any state change.
    expect((await post(server.base,e1,'application/json')).status).toBe(415);
    expect((await post(server.base,'{"payload":{}}')).status).toBe(400);
    expect((await post(server.base,Buffer.from(e1.toString().replace('"lane":"detection"','"lane":"fix"')))).status).toBe(400); // signature no longer verifies
    expect((await post(server.base,'x'.repeat(256*1024+1))).status).toBe(413);
    const slow=await Bun.connect({hostname:'127.0.0.1',port:Number(new URL(server.base).port),socket:{data(sock,d){(slow as any).got=(((slow as any).got) ?? '')+d.toString();},open(){}}});
    slow.write(`POST /engine/v1/contributions HTTP/1.1\r\nHost: x\r\nContent-Type: ${contributionMediaType}\r\nContent-Length: 1000\r\n\r\n{`);
    await Bun.sleep(900);expect(String((slow as any).got)).toContain('408');slow.end();
    // Exact replay returns the same bytes; same nonce with different content is a conflict.
    const replay=await post(server.base,e1);expect(replay.status).toBe(200);expect(Buffer.from(await replay.arrayBuffer())).toEqual(receipt);
    const conflict=s.payload({...good,'LICENSE':'MIT \n'},'1');
    expect((await post(server.base,s.envelope(conflict))).status).toBe(409);
    // Same execution content under fresh nonces: second allowed, third exhausts the content quota.
    expect((await post(server.base,s.envelope(s.payload(good,'2')))).status).toBe(202);
    expect((await post(server.base,s.envelope(s.payload(good,'3')))).status).toBe(429);
    // Declared hash differs from served bytes.
    const bad=s.payload({'LICENSE':'MIT\n','rules.json':'y'},'4',p=>{p.origins[1].file_path='bad-hash.json';});
    expect((await post(server.base,s.envelope(bad))).status).toBe(202);
    const redirect=s.payload({'LICENSE':'MIT\n','rules.json':'z'},'5',p=>{p.origins[1].file_path='redirect.json';});
    expect((await post(server.base,s.envelope(redirect))).status).toBe(202);
    const timeout=s.payload({'LICENSE':'MIT\n','rules.json':'t'},'6',p=>{p.origins[1].file_path='slow.json';});
    expect((await post(server.base,s.envelope(timeout))).status).toBe(202);

    // Restart the intake process: durable receipt bytes survive.
    server.child.kill();await server.child.exited;server=await startServer(config);
    const again=await fetch(`${server.base}/engine/v1/receipts/${id1}`);expect(Buffer.from(await again.arrayBuffer())).toEqual(receipt);

    // Separate worker process holds the holdout; results per contribution.
    const results=await work(config);
    const reason=(p:ContributionPayload)=>results.find(r=>r.id===contributionId(p));
    expect(reason(p1)).toMatchObject({state:'admitted'});
    expect(reason(bad)).toMatchObject({state:'rejected',reason:'artifact_hash_mismatch'});
    expect(reason(redirect)).toMatchObject({state:'rejected',reason:'origin_status_302'});
    expect(reason(timeout)).toMatchObject({state:'rejected',reason:'artifact_fetch_timeout'});
    const final=JSON.parse(await (await fetch(`${server.base}/engine/v1/receipts/${id1}`)).text());
    expect(final.payload.state).toBe('admitted');expect(JSON.stringify(final)).not.toContain('tp');
    // Evaluation report stays with the operator; deterministic given the sealed inputs.
    const {Database}=await import('bun:sqlite');const db=new Database(s.config.db,{readonly:true});
    const report=JSON.parse((db.query('SELECT report FROM engine_evaluations WHERE contribution_id=?').get(id1) as {report:string}).report);db.close();
    expect(report.result).toBe('scored');expect(report.holdout.candidate).toMatchObject({tp:4,fp:0,fn:0});expect(report.weights).toBeNull();
    expect(await work(config)).toEqual([]); // Nothing re-evaluated.
    expect((await fetch(`${server.base}/engine/v1/windows/w-2026-10/replay`)).status).toBe(200);
  }finally{server.child.kill();await server.child.exited;await s.cleanup();}
},60000);

test('policy gaps stay explicit and crash recovery never duplicates attempts',async()=>{
  const s=await setup();
  const key=await readFile(s.at('receipt.pem'),'utf8'),files={'LICENSE':'MIT\n','rules.json':'{}'};
  try{
    const now=BigInt(s.now);
    let store=new EngineStore({...s.config,limits:null},key);
    const r=JSON.parse((await store.submit(s.envelope(s.payload(files,'1')),now)).body.toString());
    expect(r.payload).toMatchObject({state:'policy_unresolved',reason:'unset: limits'});store.close();
    store=new EngineStore({...s.config,db:s.at('b.sqlite'),registration:null},key);
    expect(JSON.parse((await store.submit(s.envelope(s.payload(files,'1')),now)).body.toString()).payload).toMatchObject({state:'received',reason:'registration_unverified'});
    expect(store.lease(Date.now())).toBeNull();store.close();
    // Expired first submission fails; the exact replay of a recorded one still returns its receipt.
    store=new EngineStore({...s.config,db:s.at('c.sqlite')},key);
    const env=s.envelope(s.payload(files,'7'));
    expect((await store.submit(s.envelope(s.payload(files,'8')),now+10000n)).status).toBe(422);
    const first=await store.submit(env,now);expect(first.status).toBe(202);
    const lease=store.lease(1000)!;store.close(); // Crash while leased.
    store=new EngineStore({...s.config,db:s.at('c.sqlite')},key);
    expect(await store.submit(env,now+10000n)).toEqual({status:200,body:first.body});
    expect(store.lease(1001)).toBeNull(); // Lease still held.
    const retry=store.lease(1000+60000)!;expect(retry.id).toBe(lease.id);
    expect(store.complete(lease,'admitted',null,null)).toBe(false); // Stale worker fenced out.
    expect(store.complete(retry,'rejected','x',null)).toBe(true);expect(store.complete(retry,'rejected','x',null)).toBe(false);
    expect(store.db.query("SELECT count FROM engine_attempts WHERE scope='hotkey'").get()).toEqual({count:1});
    expect(store.db.query('SELECT infra_retries FROM engine_queue').get()).toEqual({infra_retries:1});
    store.close();
  }finally{await s.cleanup();}
},30000);

test('artifact process cannot see the holdout, the queue or the network',async()=>{
  const s=await setup();
  try{
    const app=s.at('app');await Bun.write(join(app,'hostile.ts'),`
      const fs=require('fs'),tries={};
      for(const p of ${JSON.stringify([s.at('bank'),s.config.db,s.at('receipt.pem'),'/etc/passwd',root+'src/engine-intake.ts'])})try{fs.readFileSync(p);tries[p]='READ';}catch(e){tries[p]=e.code;}
      try{fs.writeFileSync('/artifact/rules.json','x');tries.write='WROTE';}catch(e){tries.write=e.code;}
      try{await fetch('http://127.0.0.1:${new URL(s.config.origins!.local.base_url).port}/');tries.net='CONNECTED';}catch(e){tries.net='blocked';}
      tries.uid=process.getuid();tries.env=Object.keys(process.env).filter(k=>process.env[k]!==undefined && k!=='PWD');tries.stdin=await Bun.stdin.text();
      if(process.argv[2]==='hang')await new Promise(()=>{});
      if(process.argv[2]==='flood')for(;;)process.stdout.write('x'.repeat(65536));
      process.stdout.write(JSON.stringify(tries));`);
    await Bun.write(s.at('artifact/rules.json'),'{}');
    const run=(mode:string)=>runSandbox({appDir:app,script:'hostile.ts',args:[mode],artifactDir:s.at('artifact'),stdin:Buffer.from('only-inputs'),timeoutMs:3000,maxOutput:1<<20});
    const tries=JSON.parse(await run('probe'));
    for(const p of [s.at('bank'),s.config.db,s.at('receipt.pem'),'/etc/passwd',root+'src/engine-intake.ts'])expect(tries[p]).toBe('ENOENT');
    expect(tries).toMatchObject({write:'EROFS',net:'blocked',uid:65534,env:[],stdin:'only-inputs'});
    await expect(run('hang')).rejects.toThrow('sandbox_timeout');
    await expect(run('flood')).rejects.toThrow('sandbox_output_limit');
  }finally{await s.cleanup();}
},30000);
