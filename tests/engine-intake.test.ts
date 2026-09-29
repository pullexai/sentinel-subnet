import {expect,test} from 'bun:test';
import {cryptoWaitReady,encodeAddress,sr25519PairFromSeed,sr25519Sign} from '@polkadot/util-crypto';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,rm,readFile} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {contributionMediaType,contributionSigningBytes,envelopeBytes,contributionId,type ContributionPayload} from '../src/engine-contribution';
import {EngineStore,baselineProfile,runSandbox,unverifiedChecks,type IntakeConfig} from '../src/engine-intake';
import {holdoutBankDigest,holdoutCommitmentPayload,type HoldoutBank,type HoldoutCase} from '../src/holdout';
import {jcsBytes} from '../src/jcs';

import {setup,sha,root} from './engine-fixture';
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
  const profile=structuredClone(baselineProfile);profile.stages[0].params.query_source='changed_files';
  const good={'LICENSE':'MIT\n','rules.json':JSON.stringify(profile)};
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
    expect((await post(server.base,Buffer.from(e1.toString().replace('"lane":"retrieval"','"lane":"fix"')))).status).toBe(400); // signature no longer verifies
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
    // Formats that need an unqualified external engine are rejected without fetching; embedding stages likewise.
    const structural=s.payload({'LICENSE':'MIT\n','rules.json':'{}'},'9',p=>{p.format.id='structural-rule/v1';p.lane='detection';});
    expect((await post(server.base,s.envelope(structural))).status).toBe(202);
    const embedding={'LICENSE':'MIT\n','rules.json':JSON.stringify({...profile,embedding_component_sha256:'9'.repeat(64)})};s.put({'embed.json':embedding['rules.json']});
    const embed=s.payload(embedding,'10',p=>{p.origins[1].file_path='embed.json';});expect((await post(server.base,s.envelope(embed))).status).toBe(202);
    const hostile={'LICENSE':'MIT\n','rules.json':JSON.stringify({...profile,stages:[{operator:'exec',params:{cmd:'cat /etc/passwd'}}]})};s.put({'hostile.json':hostile['rules.json']});
    const host=s.payload(hostile,'11',p=>{p.origins[1].file_path='hostile.json';});expect((await post(server.base,s.envelope(host))).status).toBe(202);

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
    expect(reason(structural)).toMatchObject({state:'rejected',reason:'unqualified-engine'});
    expect(reason(embed)).toMatchObject({state:'rejected',reason:'unqualified-engine'});
    expect(reason(host)).toMatchObject({state:'rejected',reason:'artifact_invalid'});
    const final=JSON.parse(await (await fetch(`${server.base}/engine/v1/receipts/${id1}`)).text());
    expect(final.payload.state).toBe('admitted');expect(JSON.stringify(final)).not.toContain('tp');
    // Evaluation report stays with the operator; deterministic given the sealed inputs.
    const {Database}=await import('bun:sqlite');const db=new Database(s.config.db,{readonly:true});
    const report=JSON.parse((db.query('SELECT report FROM engine_evaluations WHERE contribution_id=?').get(id1) as {report:string}).report);db.close();
    expect(report).toMatchObject({result:'scored',input_schema:'sentinel-engine-case/v1',format:'retrieval-profile/v1',weights:null});
    // Changed-file query retrieves the oracle-proven defect span in every defective case; the query-text baseline in half.
    expect(report.holdout.candidate).toMatchObject({required:4,covered:4,missed:0,evidence_recall:{numerator:'4',denominator:'4'}});
    expect(report.holdout.baseline).toMatchObject({required:4,covered:2,missed:2,ranges:4,evidence_recall:{numerator:'2',denominator:'4'}});expect(report.holdout.regressed).toBe(0);
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
