import {readFile} from 'node:fs/promises';
import {cryptoWaitReady,sr25519PairFromSeed} from '@polkadot/util-crypto';
import {EngineStore,loadHoldout,type IntakeConfig} from '../src/engine-intake';
import {openWindow,windowReport,workWindow} from '../src/engine-window';

// Test worker: `hang` stops forever after leasing the first candidate tuple (the parent SIGKILLs it).
await cryptoWaitReady();
const [configPath,journalPath,seed,mode,fixed]=process.argv.slice(2);
const config=JSON.parse(await readFile(configPath,'utf8')) as IntakeConfig;
const store=new EngineStore(config,await readFile(config.receipt_key_path,'utf8')),holdout=await loadHoldout(config);
const clock=fixed?()=>BigInt(fixed):undefined,baseline=config.expectation.baseline_bundle_sha256;
const journal=await openWindow(store,holdout,journalPath,sr25519PairFromSeed(Buffer.from(seed,'hex')),
  {window_id:config.expectation.window_id,trials:2,beacon:{identity:'local-test-beacon',round:'7',value:'b'.repeat(64)},max_infra_retries:1,clock});
const counts=await workWindow(journal,store,holdout,{ttl:fixed?10n:2n,afterLease:async t=>{
  if(mode==='hang' && t.execution_content_id!==baseline){console.log('hang');await new Promise(()=>{});}
}});
console.log(JSON.stringify({counts,report:windowReport(journal,holdout,baseline,null)}));
journal.close();store.close();
