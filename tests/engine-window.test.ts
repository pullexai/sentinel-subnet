import {expect,test} from 'bun:test';
import {sr25519PairFromSeed} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {copyFile,readFile,writeFile} from 'node:fs/promises';
import {EngineStore,baselineProfile} from '../src/engine-intake';
import {verifyJournalExport} from '../src/engine-journal';
import {jcs} from '../src/jcs';
import {root,setup} from './engine-fixture';

const bun=(args:string[])=>Bun.spawn([process.execPath,...args],{cwd:root,env:{PATH:process.env.PATH},stdout:'pipe',stderr:'pipe'});
const run=async(args:string[])=>{
  const c=bun(args),[out,err,code]=await Promise.all([new Response(c.stdout).text(),new Response(c.stderr).text(),c.exited]);
  expect(err).toBe('');expect(code).toBe(0);return out.trim();
};

test('journaled window: kill during lease, resume, offline verify, tamper, reproducible root',async()=>{
  const s=await setup();
  try{
    const key=await readFile(s.at('receipt.pem'),'utf8'),profile=structuredClone(baselineProfile);profile.stages[0].params.query_source='changed_files';
    const good={'LICENSE':'MIT\n','rules.json':JSON.stringify(profile)},bad={'LICENSE':'MIT\n','rules.json':'{}'};
    s.put(good);s.put({'bad.json':bad['rules.json']});
    const store=new EngineStore(s.config,key),now=BigInt(s.now);
    for(const [files,nonce,extra] of [[good,'1'],[good,'2'],[bad,'3',(p:any)=>{p.origins[1].file_path='bad.json';}]] as const)
      expect((await store.submit(s.envelope(s.payload(files,nonce,extra as any)),now)).status).toBe(202);
    store.close();
    await copyFile(s.at('intake.sqlite'),s.at('copy.sqlite'));
    const seed=randomBytes(32).toString('hex'),issuer=Buffer.from(sr25519PairFromSeed(Buffer.from(seed,'hex')).publicKey).toString('hex');
    const config=await s.writeConfig(),window=s.config.expectation.window_id;

    // Separate process killed while holding a lease; the lease is still live in the journal.
    const hung=bun(['tests/engine-window-worker.ts',config,s.at('j.sqlite'),seed,'hang']);
    const reader=hung.stdout.getReader();expect(new TextDecoder().decode((await reader.read()).value)).toContain('hang');
    hung.kill('SIGKILL');await hung.exited;
    await Bun.sleep(2100); // lease ttl 2s: expiry, then bounded re-lease
    const r=JSON.parse(await run(['tests/engine-window-worker.ts',config,s.at('j.sqlite'),seed,'resume']));
    expect(r.report.status).toBe('evaluated');
    expect(Object.keys(r.report.losses).length).toBe(2); // exact duplicates alias to one execution + baseline
    expect(r.report.classes.classes).toHaveLength(1);expect(r.report.classes.classes[0].members).toHaveLength(2);
    expect(Object.values(r.report.losses).flat().every((x:any)=>x.loss.status==='policy_unresolved')).toBe(true);

    // Offline export: library and CLI agree with the live root; the lease/retry trail is in the log.
    const {EvaluationJournal}=await import('../src/engine-journal');
    const j=await EvaluationJournal.open(s.at('j.sqlite'),sr25519PairFromSeed(Buffer.from(seed,'hex')),window),bytes=j.export();j.close();
    const v=await verifyJournalExport(bytes,issuer,window);
    expect(v.root).toBe(r.report.window_root);expect(v.status).toBe('evaluated');
    const kinds=JSON.parse(Buffer.from(bytes).toString()).map((e:any)=>e.event.kind);
    expect(kinds.filter((k:string)=>k==='lease').length).toBe(kinds.filter((k:string)=>k==='outcome').length+1);
    expect(kinds).toContain('rejection');
    await writeFile(s.at('export.json'),bytes);
    expect(JSON.parse(await run(['src/engine-journal.ts','verify',s.at('export.json'),issuer,window])).root).toBe(v.root);

    // Tampering with any recorded output breaks verification.
    const forged=Buffer.from(Buffer.from(bytes).toString().replace('"status":"ok"','"status":"abstain"'));
    expect(forged.equals(Buffer.from(bytes))).toBe(false);
    await expect(verifyJournalExport(forged,issuer,window)).rejects.toThrow('Invalid journal');

    // Two independent executions from the same frozen inputs and clock produce the same window root.
    const roots=[];
    for(const n of ['a','b']){
      await copyFile(s.at('copy.sqlite'),s.at(n+'.sqlite'));
      const c=await s.writeConfig({...s.config,db:s.at(n+'.sqlite'),sealed_dir:s.at('sealed-'+n)});
      roots.push(JSON.parse(await run(['tests/engine-window-worker.ts',c,s.at('j-'+n+'.sqlite'),seed,'plain','1000'])).report.window_root);
    }
    expect(roots[0]).toBe(roots[1]);expect(jcs(roots)).toMatch(/[0-9a-f]{64}/);
  }finally{await s.cleanup();}
},120000);
