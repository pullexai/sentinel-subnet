import {join} from 'node:path';
import {readFile} from 'node:fs/promises';
import {EvaluationJournal,roundStatus,scheduleRound,type Beacon,type Pair,type Tuple} from './engine-journal';
import {EngineStore,baselineProfile,contentId,fetchAndSeal,loadHoldout,runSandbox,unqualifiedFormats,unverifiedChecks,verifySealed} from './engine-intake';
import {Unqualified,runProfile,scoreRetrieval,validateOutput,validateProfile,type RetrievalOutput} from './engine-retrieval';
import {cellLoss,clonePartition,pairedGain,q,text,type Costs,type Member} from './engine-scoring';

// EC-08 one-validator window: freeze queued contributions, journal every tuple lease/outcome, report from the journal alone.
// Beacon, witnesses, quorum and chain stay policy_unresolved/unverified: a null beacon throws PolicyUnresolved before anything is written.
type Holdout=Awaited<ReturnType<typeof loadHoldout>>;
type Frozen={contribution_id:string;execution_content_id:string;format:string;entrypoint:string;receipt_sequence:string};
const baselineBytes=Buffer.from(JSON.stringify(baselineProfile));

export async function openWindow(store:EngineStore,holdout:Holdout,journalPath:string,pair:Pair,o:{window_id:string;trials:number;beacon:Beacon|null;max_infra_retries:number;clock?:()=>bigint}){
  const journal=await EvaluationJournal.open(journalPath,pair,o.window_id,o.clock);
  if(!journal.state.hashes.length){
    const c=store.config,bundle=c.expectation.baseline_bundle_sha256,cases=holdout.cases.map(x=>x.gold.case_input_id);
    scheduleRound({window_id:o.window_id,round_index:'0',previous_round_root:null,bundle_sha256:bundle,execution_content_ids:[],cases,trials:o.trials,beacon:o.beacon}); // beacon check first
    const rows=store.db.query("SELECT q.contribution_id AS id,r.rowid AS seq FROM engine_queue q JOIN engine_receipts r USING(contribution_id) WHERE q.state='queued' ORDER BY r.rowid").all() as {id:string;seq:number}[];
    const frozen:Frozen[]=[],rejected:{contribution_id:string;reason:string}[]=[];
    for(const r of rows){
      const p=store.payload(r.id),dir=join(c.sealed_dir,r.id);
      try{
        if(Object.hasOwn(unqualifiedFormats,p.format.id))throw Object.assign(new Error(),{reason:'unqualified-engine'});
        await fetchAndSeal(p,c,dir);await verifySealed(p,dir);validateProfile(await readFile(join(dir,p.artifact.entrypoint)));
        frozen.push({contribution_id:r.id,execution_content_id:contentId(p),format:p.format.id,entrypoint:p.artifact.entrypoint,receipt_sequence:String(r.seq)});
      }catch(x){
        const reason=x instanceof Unqualified?x.reason:(x as {reason?:string}).reason ?? 'artifact_invalid';
        rejected.push({contribution_id:r.id,reason});
      }
    }
    const round=scheduleRound({window_id:o.window_id,round_index:'0',previous_round_root:null,bundle_sha256:bundle,execution_content_ids:frozen.map(f=>f.execution_content_id),cases,trials:o.trials,beacon:o.beacon});
    journal.append('window_open',{policy_sha256:c.expectation.policy_sha256,round_id:round.round_id,max_infra_retries:String(o.max_infra_retries),schedule:round.tuples.map(({seed,...t})=>t)});
    for(const f of frozen)journal.append('intake',f);
    for(const r of rejected)journal.append('rejection',r);
    journal.append('freeze',{round_id:round.round_id,baseline:bundle,contributions:frozen.map(f=>f.contribution_id),holdout_bank_sha256:holdout.bankSha256,unverified:[...unverifiedChecks]});
  }
  // ponytail: journal and store are two databases; replaying the journal's decisions onto the queue is idempotent after a crash.
  for(const e of journal.entries()){
    const b=e.body as any;
    if(e.event.kind==='intake')store.db.query("UPDATE engine_queue SET state='frozen' WHERE contribution_id=?").run(b.contribution_id),store.setState(b.contribution_id,'admitted',null);
    if(e.event.kind==='rejection')store.db.query("UPDATE engine_queue SET state='done' WHERE contribution_id=?").run(b.contribution_id),store.setState(b.contribution_id,'rejected',b.reason);
  }
  return journal;
}

const frozenOf=(journal:EvaluationJournal)=>journal.entries().filter(e=>e.event.kind==='intake').map(e=>e.body as Frozen);
const schedule=(journal:EvaluationJournal)=>(journal.entries()[0].body as {schedule:Tuple[]}).schedule;

// One tuple: lease, run, complete. A crash leaves the lease to expire; the next worker re-leases within max_infra_retries.
export async function workTuple(journal:EvaluationJournal,store:EngineStore,holdout:Holdout,t:Tuple,o:{ttl:bigint;afterLease?:(t:Tuple)=>Promise<void>}){
  const l=journal.lease(t,o.ttl);
  if(l!=='leased')return l;
  await o.afterLease?.(t);
  const x=holdout.cases.find(c=>c.gold.case_input_id===t.case_input_id)!,c=store.config;
  let output:unknown;
  if(t.execution_content_id===c.expectation.baseline_bundle_sha256)output=runProfile(validateProfile(baselineBytes),x.bundle); // trusted reference, as in processOne
  else{
    const f=frozenOf(journal).find(f=>f.execution_content_id===t.execution_content_id)!;
    try{
      const dir=join(c.sealed_dir,f.contribution_id);await verifySealed(store.payload(f.contribution_id),dir);
      const out=JSON.parse(await runSandbox({appDir:import.meta.dir,script:'engine-sandbox.ts',args:[f.format,f.entrypoint],artifactDir:dir,stdin:Buffer.from(JSON.stringify([x.bundle])),timeoutMs:c.limits!.sandbox_timeout_ms,maxOutput:c.limits!.sandbox_output_bytes}));
      if(!Array.isArray(out) || out.length!==1)throw Object.assign(new Error(),{reason:'sandbox_output_invalid'});
      output=validateOutput(out[0],t.case_input_id,x.bundle.file_table);
    }catch(e){
      // Artifact failures are outcomes (journaled rejection), never infrastructure retries.
      const reason=(e as {reason?:string}).reason;if(!reason)throw e;
      output={case_input_id:t.case_input_id,status:'rejected',reason};
    }
  }
  return journal.complete(t,JSON.parse(JSON.stringify(output)));
}
export async function workWindow(journal:EvaluationJournal,store:EngineStore,holdout:Holdout,o:{ttl:bigint;afterLease?:(t:Tuple)=>Promise<void>}){
  const counts:Record<string,number>={};
  for(const t of schedule(journal)){const r=await workTuple(journal,store,holdout,t,o);counts[r]=(counts[r] ?? 0)+1;}
  return counts;
}

// Report from journal outcomes only. Costs come from signed policy; null keeps EC-09 loss policy_unresolved.
export function windowReport(journal:EvaluationJournal,holdout:Holdout,baseline:string,costs:Costs){
  const entries=journal.entries(),frozen=frozenOf(journal),status=roundStatus(journal.state),trials=new Set(schedule(journal).map(t=>t.trial_index));
  const outcomes=entries.filter(e=>e.event.kind==='outcome').map(e=>e.body as {tuple:Tuple;output:any});
  const gold=holdout.cases.map(c=>c.gold);
  const perExecution=(id:string)=>[...trials].sort().map(trial=>{
    const outs=outcomes.filter(o=>o.tuple.execution_content_id===id && o.tuple.trial_index===trial);
    const valid=new Map(outs.filter(o=>o.output.status!=='rejected').map(o=>[o.tuple.case_input_id,o.output as RetrievalOutput]));
    const score=scoreRetrieval(gold,valid),positives=gold.filter(g=>g.evidence).length,cleans=gold.length-positives;
    // ponytail: retrieval lane has no comment output; false_comments=0 until a detection lane defines them.
    const counts={positives,cleans,missed:score.missed,false_comments:0,invalid:gold.length-valid.size,mandatory_failures:0};
    let loss;try{const r=cellLoss(counts,costs);loss={status:r.status,loss:r.loss && text(r.loss)};}catch(e){if((e as any).reason!=='policy_unresolved')throw e;loss={status:'policy_unresolved',loss:null,reason:(e as Error).message};}
    return {trial_index:trial,counts,evidence_recall:score.evidence_recall,loss};
  });
  const executions=[baseline,...new Set(frozen.map(f=>f.execution_content_id))];
  const losses=Object.fromEntries(executions.map(e=>[e,perExecution(e)]));
  const members:Member[]=frozen.map(f=>({contribution_id:f.contribution_id,execution_content_id:f.execution_content_id,receipt_sequence:f.receipt_sequence}));
  // Quorum certification is unavailable locally: classes use exact execution content only.
  const classes=clonePartition({window_id:journal.state.window_id,profile_sha256:baseline,roster:[journal.state.issuer],cases:gold.map(g=>g.case_input_id),trials:trials.size,members,rows:[],certified:false});
  const recall=(e:string)=>{const r=losses[e][0]?.evidence_recall;return r?q(BigInt(r.numerator),BigInt(r.denominator)):null;};
  const gains=Object.fromEntries(executions.slice(1).map(e=>{const b=recall(baseline),k=recall(e);return [e,b && k?{...pairedGain(k,b),point_gain:text(pairedGain(k,b).point_gain)}:null];}));
  return {window_id:journal.state.window_id,window_root:journal.root(),events:journal.state.hashes.length,status,losses,gains,classes,
    policy_unresolved:['beacon_identity','quorum','uncertainty_policy',...(costs?[]:['loss_costs'])],unverified:[...unverifiedChecks,'witness_checkpoints','chain_finality']};
}
