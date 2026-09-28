import {expect,test} from 'bun:test';
import {cryptoWaitReady,sr25519PairFromSeed} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';
import {mkdtemp,readFile,copyFile} from 'node:fs/promises';
import {join} from 'node:path';
import {EvaluationJournal,PolicyUnresolved,detectForks,predicateHash,scheduleRound,signAttestation,transcriptCommitment,trialSeed,verifyAttestation,verifyCheckpoint,verifyJournalExport,type AttestationPayload,type Beacon} from '../src/engine-journal';
import {cellLoss,clonePartition,disagreement,pairedGain,parseQ,precision,q,rosterMean,text,transcriptSetRoot,type TranscriptRow} from '../src/engine-scoring';
import {jcs,jcsBytes} from '../src/jcs';

const root=new URL('..',import.meta.url).pathname;
const h=(c:string)=>c.repeat(64);
const beacon:Beacon={identity:'local-test-beacon',round:'7',value:h('b')};

test('seeds and rounds are independent of submitter; missing beacon pauses', ()=>{
  expect(()=>trialSeed(null,'w1','0',h('c'),'0')).toThrow(PolicyUnresolved);
  const a=scheduleRound({window_id:'w1',round_index:'0',previous_round_root:null,bundle_sha256:h('0'),execution_content_ids:[h('2'),h('1'),h('2')],cases:[h('c'),h('d')],trials:2,beacon});
  const b=scheduleRound({window_id:'w1',round_index:'0',previous_round_root:null,bundle_sha256:h('0'),execution_content_ids:[h('1'),h('2')],cases:[h('c'),h('d')],trials:2,beacon});
  // Exact-content duplicates alias; baseline paired; same seed per (case, trial) for every execution.
  expect(a).toEqual(b);expect(a.tuples.length).toBe(3*2*2);
  expect(new Set(a.tuples.filter(t=>t.case_input_id===h('c') && t.trial_index==='1').map(t=>t.seed)).size).toBe(1);
  expect(()=>scheduleRound({window_id:'w1',round_index:'0',previous_round_root:null,bundle_sha256:h('0'),execution_content_ids:[],cases:[h('c')],trials:1,beacon:null})).toThrow('beacon_unavailable');
  const c1=transcriptCommitment({window_id:'w1',round_id:a.round_id,validator_public_key:h('a'),salt:h('5'),attestation_sha256:h('6'),transcript_sha256:h('7')});
  expect(c1).not.toBe(transcriptCommitment({window_id:'w1',round_id:a.round_id,validator_public_key:h('a'),salt:h('4'),attestation_sha256:h('6'),transcript_sha256:h('7')}));
});

// Child process: runs one validator's evaluation, optionally crashing (exit without closing) after the first lease.
const child=`
import {EvaluationJournal,scheduleRound} from '${root}src/engine-journal.ts';
import {sr25519PairFromSeed,cryptoWaitReady} from '@polkadot/util-crypto';
await cryptoWaitReady();
const [db,seed,crash,start]=process.argv.slice(1);let now=BigInt(start);
const j=await EvaluationJournal.open(db,sr25519PairFromSeed(Buffer.from(seed,'hex')),'w1',()=>now);
const h=c=>c.repeat(64);
const r=scheduleRound({window_id:'w1',round_index:'0',previous_round_root:null,bundle_sha256:h('0'),execution_content_ids:[h('1')],cases:[h('c'),h('d')],trials:2,beacon:{identity:'local-test-beacon',round:'7',value:h('b')}});
const tuples=r.tuples.map(({seed,...t})=>t);
if(!j.state.hashes.length){j.append('window_open',{policy_sha256:h('9'),round_id:r.round_id,max_infra_retries:'1',schedule:tuples});j.append('intake',{contribution_id:h('1')});j.append('rejection',{contribution_id:h('e'),reason:'not_registered'});}
for(const [i,t] of tuples.entries()){
  const l=j.lease(t,10n);
  if(l!=='leased'){console.log('skip',l);continue;}
  if(crash==='crash')process.exit(3);
  now+=1n;j.complete(t,{output:r.tuples[i].seed.slice(0,8),status:'ok'});
}
await Bun.write(db+'.export',j.export());console.log(j.root());
`;

test('journal: separate processes, crash recovery, offline verification, tamper and fork detection', async ()=>{
  await cryptoWaitReady();
  const dir=await mkdtemp('/tmp/opencode/engine-journal-');
  const seed=randomBytes(32).toString('hex'),pair=sr25519PairFromSeed(Buffer.from(seed,'hex')),issuer=Buffer.from(pair.publicKey).toString('hex');
  const run=async(db:string,crash:string,start:string)=>{const p=Bun.spawn(['bun','-e',child,db,seed,crash,start],{cwd:root,stdout:'pipe',stderr:'pipe'});const out=await new Response(p.stdout).text();return {code:await p.exited,out:out.trim()};};
  // Run A crashes while holding a lease; restart before expiry sees it busy, after expiry re-leases (infra retry, same tuple).
  const a=join(dir,'a.sqlite');
  expect((await run(a,'crash','100')).code).toBe(3);
  const early=await run(a,'no','105');expect(early.out).toContain('skip busy');
  const late=await run(a,'no','300');expect(late.code).toBe(0);
  const recovered=await verifyJournalExport(await readFile(a+'.export'),Buffer.from(pair.publicKey).toString('hex'),'w1');
  // First tuple: crash lease, busy skip, one retry lease after expiry, then its outcome; nothing lost or doubled.
  expect(recovered.status).toBe('evaluated');
  expect(JSON.parse((await readFile(a+'.export')).toString()).filter((e:any)=>e.event.kind==='lease' && e.body.tuple.trial_index==='0' && e.body.tuple.case_input_id===h('c') && e.body.tuple.execution_content_id===h('0')).length).toBe(2);
  const b=join(dir,'b.sqlite');
  const fresh=await run(b,'no','100'),rootB=fresh.out.split('\n').at(-1)!;
  // Reproducibility: an independent run with the same key and clock yields the byte-identical window root (signatures excluded).
  const c=join(dir,'c.sqlite'),again=await run(c,'no','100');
  expect(again.out.split('\n').at(-1)).toBe(rootB);
  // Offline verification in a separate process via the CLI.
  const cli=Bun.spawn(['bun','src/engine-journal.ts','verify',b+'.export',issuer,'w1'],{cwd:root,stdout:'pipe'});
  const verdict=JSON.parse(await new Response(cli.stdout).text());expect(await cli.exited).toBe(0);
  expect(verdict).toMatchObject({events:3+8*2,root:rootB,status:'evaluated'});

  const exported=await readFile(b+'.export'),entries=JSON.parse(exported.toString());
  const reject=async(mutate:(e:any[])=>void)=>{const x=structuredClone(entries);mutate(x);await expect(verifyJournalExport(jcsBytes(x),issuer,'w1')).rejects.toThrow();};
  await reject(e=>{e[4].body.output.status='invalid';});                      // blob edited
  await reject(e=>{e[4].event.subject_sha256=h('f');});                         // header edited (signature breaks)
  await reject(e=>{e.splice(2,1);});                                           // rejection event removed: success-only log
  await reject(e=>{[e[3],e[4]]=[e[4],e[3]];});                                  // reordered
  await reject(e=>{e[4].signature=e[3].signature;});                            // signature swapped
  await expect(verifyJournalExport(exported,h('a'),'w1')).rejects.toThrow();    // wrong issuer
  await expect(verifyJournalExport(exported,issuer,'w2')).rejects.toThrow();    // wrong window

  // Live journal: idempotent duplicate completion, conflicting output quarantined, second commitment rejected.
  let now=200n;const j=await EvaluationJournal.open(join(dir,'b.sqlite'),pair,'w1',()=>now);
  const t=entries[3].body.tuple,out=entries[4].body.output;
  expect(j.complete(t,out)).toBe('duplicate');
  expect(j.complete(t,{...out,status:'invalid'})).toBe('quarantined');
  j.append('commitment',{round_id:entries[0].body.round_id,commitment:h('3')});
  expect(()=>j.append('commitment',{round_id:entries[0].body.round_id,commitment:h('4')})).toThrow('second commitment');
  const cp=j.checkpoint();j.close();
  const reopened=await EvaluationJournal.open(join(dir,'b.sqlite'),pair,'w1'),v=await verifyJournalExport(reopened.export(),issuer,'w1');reopened.close();
  expect(v.status).toBe('disputed');verifyCheckpoint(cp,v.state.hashes);
  // Append-only at the storage layer.
  const {Database}=await import('bun:sqlite');const raw=new Database(join(dir,'b.sqlite'));
  expect(()=>raw.exec('UPDATE events SET signature=signature')).toThrow('append-only');raw.close();
  // Fork: a different log from the same key at the same position is visible through conflicting checkpoints.
  const d=join(dir,'d.sqlite');{const x=await EvaluationJournal.open(c,pair,'w1');x.close();}await copyFile(c,d);
  const cA=await EvaluationJournal.open(d,pair,'w1',()=>1000n),cC=await EvaluationJournal.open(c,pair,'w1',()=>1000n);
  cA.append('appeal',{note:'a'});cC.append('appeal',{note:'c'});
  expect(detectForks([cA.checkpoint(),cC.checkpoint()]).length).toBe(1);
  expect(detectForks([cA.checkpoint(),cA.checkpoint()]).length).toBe(0);

  // Retry bound: lease, expire, re-lease, expire, then the tuple becomes incomplete and the round cannot certify.
  let t2=0n;const r=await EvaluationJournal.open(join(dir,'r.sqlite'),pair,'w1',()=>t2);
  const tup={execution_content_id:h('1'),case_input_id:h('c'),trial_index:'0'};
  r.append('window_open',{policy_sha256:h('9'),round_id:h('8'),max_infra_retries:'1',schedule:[tup]});
  expect(r.lease(tup,5n)).toBe('leased');t2=5n;expect(r.lease(tup,5n)).toBe('leased');t2=10n;
  expect(r.lease(tup,5n)).toBe('incomplete');expect(()=>r.complete(tup,{x:1})).toThrow();
  expect((await verifyJournalExport(r.export(),issuer,'w1')).status).toBe('incomplete');
  expect(()=>r.append('outcome',{tuple:{...tup,trial_index:'9'},output:{}})).toThrow('unscheduled');
});

test('attestations: role-bound, predicate-bound, unresolved roles never pass', async ()=>{
  await cryptoWaitReady();
  const [v,x]=[0,1].map(()=>sr25519PairFromSeed(randomBytes(32))),key=(p:typeof v)=>Buffer.from(p.publicKey).toString('hex');
  const predicate={transcript_sha256:h('7')};
  const p:AttestationPayload={schema:'sentinel-engine-attestation/v1',type:'evaluation',issuer:key(v),role:'validator',network:{netuid:'0'},window_id:'w1',policy_sha256:h('9'),
    subject_sha256:h('1'),predicate_sha256:predicateHash('evaluation',predicate),previous_event_sha256:null,sequence:'0',issued_at:'1'};
  const reg={validator:{keys:[key(v)],types:['evaluation']}};
  expect((await verifyAttestation(signAttestation(v,p),reg,predicate)).payload.issuer).toBe(key(v));
  await expect(verifyAttestation(signAttestation(v,p),null,predicate)).rejects.toThrow('role_registry_unresolved');
  await expect(verifyAttestation(signAttestation(v,p),reg,{transcript_sha256:h('8')})).rejects.toThrow('predicate');
  await expect(verifyAttestation(signAttestation(x,{...p,issuer:key(x)}),reg,predicate)).rejects.toThrow('role authority');
  await expect(verifyAttestation(signAttestation(v,{...p,type:'adjudication',predicate_sha256:predicateHash('adjudication',predicate)}),reg,predicate)).rejects.toThrow('role authority');
  await expect(verifyAttestation(signAttestation(v,{...p,type:'weight_plan'}),reg,predicate)).rejects.toThrow('finalized_chain_required');
  await expect(verifyAttestation(signAttestation(v,{...p,type:'release'}),reg,predicate)).rejects.toThrow('product_release_trust_root_unresolved');
  const w=JSON.parse(signAttestation(v,p).toString());w.payload.sequence='1';
  await expect(verifyAttestation(jcsBytes(w),reg,predicate)).rejects.toThrow('signature');
});

test('EC-09 rational losses and EC-08 aggregation are exact', ()=>{
  const costs={missed_defect:q(3n),false_comment:q(1n,2n),invalid_evidence:q(1n),mandatory_failure:q(5n)};
  expect(()=>cellLoss({positives:1,cleans:1,missed:0,false_comments:0,invalid:0,mandatory_failures:0},null)).toThrow('loss_costs_unset');
  expect(cellLoss({positives:3,cleans:0,missed:0,false_comments:0,invalid:0,mandatory_failures:0},costs).status).toBe('insufficient_evidence');
  const l=cellLoss({positives:3,cleans:4,missed:1,false_comments:3,invalid:1,mandatory_failures:0},costs);
  // 3*1/3 + 1/2*3/4 + 1*1/7 = 1 + 3/8 + 1/7 = 85/56
  expect(text(l.loss!)).toEqual({numerator:'85',denominator:'56'});
  expect(precision(0,0)).toBe('undefined');expect(text(precision(2,4) as any)).toEqual({numerator:'1',denominator:'2'});
  expect(()=>parseQ({numerator:'2',denominator:'4'})).toThrow('reduced');
  // Trials then roster, each equally weighted: v1 mean 1/2, v2 mean 1/6 -> 1/3; float would drift.
  const m=rosterMean(['v1','v2'],2,new Map([['v1',[q(1n,3n),q(2n,3n)]],['v2',[q(0n),q(1n,3n)]]]));
  expect(text(m.mean)).toEqual({numerator:'1',denominator:'3'});
  expect(()=>rosterMean(['v1','v2'],2,new Map([['v1',[q(1n),q(1n)]]]))).toThrow('incomplete_transcript');
  expect(()=>rosterMean(['v1'],2,new Map([['v1',[q(1n)]]]))).toThrow('incomplete_transcript');
  expect(()=>disagreement({loss:[q(1n)]},null)).toThrow(PolicyUnresolved);
  expect(disagreement({loss:[q(1n,3n),q(1n,2n)]},{loss:q(1n,6n)}).agreed).toBe(true);
  expect(disagreement({loss:[q(1n,3n),q(1n,2n)]},{loss:q(1n,7n)}).blocked).toEqual(['loss']);
  expect(disagreement({loss:[q(0n)]},{loss:q(1n),false_comment_rate:q(1n)}).blocked).toEqual(['false_comment_rate']);
  const g=pairedGain(q(85n,56n),q(1n));expect(g.quality).toBeNull();expect(g.status).toBe('policy_unresolved');
});

test('EC-10 clone partition: exact vectors only, aliases do not multiply, hostile clones', ()=>{
  const roster=[h('a'),h('b')],cases=[h('c'),h('d')];
  const rows=(e:string,out:(v:string,c:string,t:string)=>unknown):TranscriptRow[]=>roster.flatMap(v=>cases.flatMap(c=>['0','1'].map(t=>({validator_public_key:v,round_id:h('8'),execution_content_id:e,case_input_id:c,trial_index:t,canonical_output:out(v,c,t),status:'ok',coverage:'complete'}))));
  // Stochastic but identical full vectors (differ between validators) for e1/e2; e3 differs in one trial; e4 has same aggregate as e1 but different outputs.
  const stoch=(v:string,c:string,t:string)=>({ranges:[v.slice(0,1)+c.slice(0,1)+t]});
  const all=[...rows(h('1'),stoch),...rows(h('2'),stoch),
    ...rows(h('3'),(v,c,t)=>v===h('b') && c===h('d') && t==='1'?{ranges:['near']}:stoch(v,c,t)),
    ...rows(h('4'),(v,c,t)=>({ranges:[c.slice(0,1)+v.slice(0,1)+t]}))];
  const members=[{contribution_id:h('e'),execution_content_id:h('2'),receipt_sequence:'5'},{contribution_id:h('f'),execution_content_id:h('1'),receipt_sequence:'9'},
    {contribution_id:h('7'),execution_content_id:h('1'),receipt_sequence:'2'}, // exact alias of e1, earliest receipt
    {contribution_id:h('6'),execution_content_id:h('3'),receipt_sequence:'3'},{contribution_id:h('5'),execution_content_id:h('4'),receipt_sequence:'4'}];
  const base={window_id:'w1',profile_sha256:h('9'),roster,cases,trials:2,members,rows:all,certified:true};
  const p=clonePartition(base);
  expect(p.classes.length).toBe(3);
  const big=p.classes.find(c=>c.members.length===3)!;
  expect(big.members).toEqual([h('7'),h('e'),h('f')]);expect(big.representative).toBe(h('7'));
  // Deterministic regardless of input order.
  expect(jcs(clonePartition({...base,members:[...members].reverse(),rows:[...all].reverse()}))).toBe(jcs(p));
  // Hostile: changing only signatures/identity fields in rows is impossible; timing/confidence are not in the vector. A missing trial yields no behavior class.
  const partial=clonePartition({...base,rows:all.filter(r=>!(r.execution_content_id===h('2') && r.trial_index==='1' && r.validator_public_key===h('a') && r.case_input_id===h('c')))});
  expect(partial.missing_behavior).toEqual([h('2')]);expect(partial.classes.length).toBe(4);
  const unc=clonePartition({...base,certified:false});
  expect(unc.behavior).toBe('unverified_uncertified_transcripts');expect(unc.classes.length).toBe(4);expect(unc.set_root).toBeNull();
  expect(()=>clonePartition({...base,members:[...members,{contribution_id:h('d'),execution_content_id:h('2'),receipt_sequence:'5'}]})).toThrow('receipt_sequence_conflict');
  // Transcript-set root sorts numerically and rejects duplicate tuples.
  const r10={...all[0],trial_index:'10'},r2={...all[0],trial_index:'2'};
  expect(transcriptSetRoot([r10,r2])).toBe(transcriptSetRoot([r2,r10]));
  expect(()=>transcriptSetRoot([all[0],{...all[0]}])).toThrow('duplicate');
});
