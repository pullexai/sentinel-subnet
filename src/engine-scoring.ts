import {jcs} from './jcs';
import {PolicyUnresolved,hashOf} from './engine-journal';

// EC-08 aggregation/disagreement, EC-09 exact rational losses and EC-10 clone partition, all local and deterministic.
// Bootstrap bounds, multiplicity and lane shares need signed policy values: reported as policy_unresolved, never guessed.
export type Q={n:bigint;d:bigint};
const gcd=(a:bigint,b:bigint):bigint=>b?gcd(b,a%b):a<0n?-a:a;
export const q=(n:bigint,d:bigint=1n):Q=>{if(d===0n)throw new Error('zero denominator');if(d<0n){n=-n;d=-d;}const g=gcd(n,d) || 1n;return {n:n/g,d:d/g};};
export const add=(a:Q,b:Q)=>q(a.n*b.d+b.n*a.d,a.d*b.d),sub=(a:Q,b:Q)=>q(a.n*b.d-b.n*a.d,a.d*b.d),mul=(a:Q,b:Q)=>q(a.n*b.n,a.d*b.d);
export const cmp=(a:Q,b:Q)=>{const x=a.n*b.d-b.n*a.d;return x<0n?-1:x>0n?1:0;};
export const text=(a:Q)=>({numerator:String(a.n),denominator:String(a.d)});
const mean=(xs:Q[])=>{if(!xs.length)throw new Error('empty mean');return mul(xs.reduce(add,q(0n)),q(1n,BigInt(xs.length)));};
export function parseQ(v:unknown):Q{
  const o=v as {numerator:unknown;denominator:unknown};
  if(!o || typeof o.numerator!=='string' || typeof o.denominator!=='string' || !/^(0|[1-9][0-9]{0,30})$/.test(o.numerator) || !/^[1-9][0-9]{0,30}$/.test(o.denominator))throw new Error('Invalid rational');
  const r=q(BigInt(o.numerator),BigInt(o.denominator));
  if(r.n!==BigInt(o.numerator))throw new Error('Rational not reduced');
  return r;
}

// ---- EC-09 cell loss. Costs are nonnegative reduced rationals from policy; null means unresolved.
export type Costs={missed_defect:Q;false_comment:Q;invalid_evidence:Q;mandatory_failure:Q}|null;
export type CellCounts={positives:number;cleans:number;missed:number;false_comments:number;invalid:number;mandatory_failures:number};
export function cellLoss(c:CellCounts,costs:Costs){
  if(!costs)throw new PolicyUnresolved('loss_costs_unset');
  if(Object.values(costs).some(x=>x.n<0n))throw new Error('negative cost');
  // A required cell missing either polarity is insufficient evidence, never zero loss.
  if(c.positives<=0 || c.cleans<=0)return {status:'insufficient_evidence' as const,loss:null,terms:null};
  const terms={missed:mul(costs.missed_defect,q(BigInt(c.missed),BigInt(c.positives))),false_comments:mul(costs.false_comment,q(BigInt(c.false_comments),BigInt(c.cleans))),
    invalid:mul(costs.invalid_evidence,q(BigInt(c.invalid),BigInt(c.positives+c.cleans))),mandatory:mul(costs.mandatory_failure,q(BigInt(c.mandatory_failures),BigInt(c.positives+c.cleans)))};
  return {status:'ok' as const,loss:Object.values(terms).reduce(add),terms};
}
export const precision=(tp:number,predicted:number)=>predicted?q(BigInt(tp),BigInt(predicted)):'undefined' as const;

// ---- EC-08 aggregation: equal mean over scheduled trials per validator, then equal mean over the fixed roster.
// Stake, confidence, speed and quorum never weight observations. A missing validator or trial blocks the cell.
export function rosterMean(roster:string[],trials:number,values:Map<string,(Q|undefined)[]>){
  const perValidator=roster.map(v=>{
    const xs=values.get(v);
    if(!xs || xs.length!==trials || xs.some(x=>!x))throw Object.assign(new Error('incomplete_transcript'),{reason:'incomplete_transcript'});
    return mean(xs as Q[]);
  });
  return {mean:mean(perValidator),perValidator};
}
// Every metric: max pairwise |difference| of validator means within its rational bound. Missing bound/metric is never agreement.
export function disagreement(metrics:Record<string,Q[]>,bounds:Record<string,Q>|null){
  if(!bounds)throw new PolicyUnresolved('disagreement_bounds_unset');
  const blocked:string[]=[];
  for(const [name,bound] of Object.entries(bounds)){
    const xs=metrics[name];
    if(!xs?.length){blocked.push(name);continue;}
    const sorted=[...xs].sort(cmp);
    if(cmp(sub(sorted.at(-1)!,sorted[0]),bound)>0)blocked.push(name);
  }
  return {agreed:!blocked.length,blocked};
}
// Point estimate only. q(c|B) needs the pinned bootstrap/PRNG/quantile/multiplicity policy, which is unresolved here.
export function pairedGain(baseline:Q,candidate:Q){
  return {point_gain:sub(baseline,candidate),quality:null,status:'policy_unresolved' as const,reason:'uncertainty_policy_unset'};
}

// ---- Transcript set (EC-08 step 3) and EC-10 behavior identity.
export type TranscriptRow={validator_public_key:string;round_id:string;execution_content_id:string;case_input_id:string;trial_index:string;canonical_output:unknown;status:string;coverage:string};
const numericKey=(r:TranscriptRow)=>[Buffer.from(r.validator_public_key,'hex').toString('latin1'),r.round_id,r.execution_content_id,r.case_input_id,r.trial_index.padStart(20,'0')];
const order=(a:TranscriptRow,b:TranscriptRow)=>{const x=numericKey(a),y=numericKey(b);for(let i=0;i<x.length;i++)if(x[i]!==y[i])return x[i]<y[i]?-1:1;return 0;};
export function transcriptSetRoot(rows:TranscriptRow[]){
  const sorted=[...rows].sort(order);
  for(let i=1;i<sorted.length;i++)if(!order(sorted[i-1],sorted[i]))throw new Error('duplicate transcript tuple');
  return hashOf('sentinel-engine-transcript-set/v1',sorted);
}
// Vector excludes candidate identity, signatures, salts, timing and confidence; includes input and profile.
export function behaviorHash(rows:TranscriptRow[],profile_sha256:string){
  const vector=[...rows].sort(order).map(r=>[r.validator_public_key,r.case_input_id,r.trial_index,r.canonical_output,r.status,r.coverage]);
  return hashOf('sentinel-engine-behavior/v1',{profile_sha256,vector});
}

export type Member={contribution_id:string;execution_content_id:string;receipt_sequence:string};
// Exact execution-content identity and exact full behavior vectors union classes; nothing approximate.
// `certified` must come from a quorum-certified transcript set; without it no behavioral class is formed.
export function clonePartition(o:{window_id:string;profile_sha256:string;roster:string[];cases:string[];trials:number;members:Member[];rows:TranscriptRow[];certified:boolean}){
  const parent=new Map<string,string>();
  const find=(x:string):string=>{const p=parent.get(x)!;if(p===x)return x;const r=find(p);parent.set(x,r);return r;};
  const union=(a:string,b:string)=>{const [x,y]=[find(a),find(b)].sort();if(x!==y)parent.set(y,x);};
  const executions=[...new Set(o.members.map(m=>m.execution_content_id))].sort();
  for(const e of executions)parent.set(e,e);
  const set_root=o.certified?transcriptSetRoot(o.rows):null;
  const behavior=new Map<string,string>(),missing:string[]=[];
  if(o.certified){
    const expected=o.roster.length*o.cases.length*o.trials;
    for(const e of executions){
      const rows=o.rows.filter(r=>r.execution_content_id===e);
      const complete=rows.length===expected && o.roster.every(v=>o.cases.every(c=>Array.from({length:o.trials},(_,t)=>String(t)).every(t=>rows.some(r=>r.validator_public_key===v && r.case_input_id===c && r.trial_index===t))));
      if(!complete){missing.push(e);continue;}
      const h=behaviorHash(rows,o.profile_sha256),prior=behavior.get(h);
      if(prior)union(prior,e);else behavior.set(h,e);
    }
  }
  const seq=(m:Member)=>BigInt(m.receipt_sequence);
  const classes=new Map<string,Member[]>();
  for(const m of o.members){const r=find(m.execution_content_id);classes.set(r,[...(classes.get(r) ?? []),m]);}
  const out=[...classes.values()].map(ms=>{
    ms.sort((a,b)=>seq(a)<seq(b)?-1:seq(a)>seq(b)?1:a.contribution_id<b.contribution_id?-1:1);
    if(ms.some((m,i)=>i && seq(m)===seq(ms[i-1])))throw Object.assign(new Error('receipt_sequence_conflict'),{reason:'class_disputed'});
    const member_executions=[...new Set(ms.map(m=>m.execution_content_id))].sort();
    return {class_id:hashOf('sentinel-engine-class/v1',{window_id:o.window_id,profile_sha256:o.profile_sha256,set_root,member_executions}),
      representative:ms[0].contribution_id,members:ms.map(m=>m.contribution_id),member_executions};
  }).sort((a,b)=>a.class_id<b.class_id?-1:1);
  return {partition_root:hashOf('sentinel-engine-partition/v1',out.map(c=>[c.class_id,c.members])),classes:out,set_root,
    behavior:o.certified?'exact_vectors':'unverified_uncertified_transcripts',missing_behavior:missing,
    // Receipt order is only authoritative from a witness-confirmed admission log, which is not available locally.
    receipt_order:'unverified_witness_confirmation'};
}
export const canonicalOutput=(v:unknown)=>JSON.parse(jcs(v));
