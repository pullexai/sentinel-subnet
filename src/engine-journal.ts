import {Database} from 'bun:sqlite';
import {createHash} from 'node:crypto';
import {cryptoWaitReady,sr25519Sign,sr25519Verify} from '@polkadot/util-crypto';
import {jcs,jcsBytes,parseCanonical} from './jcs';

// EC-08 local part: one validator's append-only evaluation journal, durable leases, committed trial seeds,
// transcript commitments and `sentinel-engine-attestation/v1`. Nothing here talks to a chain, beacon or peer.
export class PolicyUnresolved extends Error{reason='policy_unresolved';}
export const sha256=(b:Uint8Array|string)=>createHash('sha256').update(b).digest('hex');
export const hashOf=(domain:string,value:unknown)=>sha256(Buffer.concat([Buffer.from(domain+'\n'),jcsBytes(value)]));
const bad=(what:string):never=>{throw new Error('Invalid journal '+what);};
const hex=(v:unknown,n=64)=>typeof v==='string' && new RegExp(`^[0-9a-f]{${n}}$`).test(v);
const decimal=(v:unknown)=>typeof v==='string' && /^(0|[1-9][0-9]{0,19})$/.test(v);
const ident=(v:unknown)=>typeof v==='string' && /^[a-z0-9][a-z0-9._-]{0,127}$/.test(v);
function exact(v:unknown,keys:string[],what:string):Record<string,any>{
  if(!v || typeof v!=='object' || Array.isArray(v) || Object.keys(v).length!==keys.length || !keys.every(k=>Object.hasOwn(v,k)))bad(what);
  return v as Record<string,any>;
}
export type Pair={publicKey:Uint8Array;secretKey:Uint8Array};
const signWith=(pair:Pair,message:Uint8Array)=>Buffer.from(sr25519Sign(message,pair)).toString('hex');
function verifySr25519(message:Uint8Array,signature:unknown,publicKey:string){
  if(!hex(signature,128))return false;
  try{return sr25519Verify(message,Buffer.from(signature as string,'hex'),Buffer.from(publicKey,'hex'));}catch{return false;}
}

// ---- Seeds and rounds. Seeds depend on beacon/window/round/case/trial only: never on hotkey, nonce or candidate digest.
export type Beacon={identity:string;round:string;value:string};
export type Tuple={execution_content_id:string;case_input_id:string;trial_index:string};
export function trialSeed(beacon:Beacon|null,window_id:string,round_index:string,case_input_id:string,trial_index:string){
  // A missing beacon pauses the window; there is no discretionary fallback seed.
  if(!beacon)throw new PolicyUnresolved('beacon_unavailable');
  return hashOf('sentinel-engine-trial-seed/v1',{beacon,window_id,round_index,case_input_id,trial_index});
}
export function scheduleRound(o:{window_id:string;round_index:string;previous_round_root:string|null;bundle_sha256:string;execution_content_ids:string[];cases:string[];trials:number;beacon:Beacon|null}){
  if(!ident(o.window_id) || !decimal(o.round_index) || !(o.previous_round_root===null || hex(o.previous_round_root)) || !hex(o.bundle_sha256) ||
    !o.cases.every(c=>hex(c)) || new Set(o.cases).size!==o.cases.length || !Number.isSafeInteger(o.trials) || o.trials<1)bad('round inputs');
  // Exact-content duplicates alias one execution; the paired baseline is always scheduled.
  const executions=[...new Set([o.bundle_sha256,...o.execution_content_ids])].sort();
  if(!executions.every(e=>hex(e)))bad('execution ids');
  const tuples=executions.flatMap(e=>o.cases.flatMap(c=>Array.from({length:o.trials},(_,t)=>({execution_content_id:e,case_input_id:c,trial_index:String(t),
    seed:trialSeed(o.beacon,o.window_id,o.round_index,c,String(t))}))));
  const round_id=hashOf('sentinel-engine-round/v1',{window_id:o.window_id,round_index:o.round_index,previous_round_root:o.previous_round_root,bundle_sha256:o.bundle_sha256,beacon:o.beacon,tuples});
  return {round_id,tuples};
}
export function transcriptCommitment(o:{window_id:string;round_id:string;validator_public_key:string;salt:string;attestation_sha256:string;transcript_sha256:string}){
  if(!hex(o.salt) || !hex(o.round_id) || !hex(o.validator_public_key) || !hex(o.attestation_sha256) || !hex(o.transcript_sha256))bad('commitment fields');
  const {window_id,round_id,validator_public_key,salt,attestation_sha256,transcript_sha256}=o;
  return hashOf('sentinel-engine-transcript-commit/v1',{window_id,round_id,validator_public_key,salt,attestation_sha256,transcript_sha256});
}

// ---- Journal events. The event hash excludes the (randomized) sr25519 signature, so roots are reproducible.
export const eventSchema='sentinel-engine-journal-event/v1';
export const kinds=['window_open','intake','rejection','freeze','lease','outcome','quarantine','incomplete','commitment','attestation','abort','appeal'] as const;
export type Kind=typeof kinds[number];
export type JournalEvent={schema:typeof eventSchema;issuer:string;window_id:string;sequence:string;previous_event_sha256:string|null;kind:Kind;subject_sha256:string;issued_at:string};
export type Entry={event:JournalEvent;signature:string;body:unknown};
export const eventHash=(e:JournalEvent)=>hashOf(eventSchema,e);
export const bodyHash=(body:unknown)=>hashOf('sentinel-engine-journal-blob/v1',body);
export const windowRoot=(hashes:string[])=>hashOf('sentinel-engine-window-root/v1',hashes);
const tupleKey=(t:Tuple)=>jcs([t.execution_content_id,t.case_input_id,t.trial_index]);
function tuple(v:unknown):Tuple{
  const t=exact(v,['execution_content_id','case_input_id','trial_index'],'tuple');
  if(!hex(t.execution_content_id) || !hex(t.case_input_id) || !decimal(t.trial_index))bad('tuple');
  return t as Tuple;
}

type TupleState={expires:bigint;retries:number;output:string|null;quarantined:boolean;incomplete:boolean};
export type JournalState={issuer:string;window_id:string;maxRetries:number;scheduled:Map<string,TupleState>;commitments:Map<string,string>;aborted:boolean;hashes:string[]};
export const newState=(issuer:string,window_id:string):JournalState=>({issuer,window_id,maxRetries:0,scheduled:new Map(),commitments:new Map(),aborted:false,hashes:[]});

// The one state machine: used by the live journal before appending and by the offline verifier on export.
export function apply(s:JournalState,entry:Entry){
  const e=exact(entry.event,['schema','issuer','window_id','sequence','previous_event_sha256','kind','subject_sha256','issued_at'],'event') as JournalEvent;
  const n=s.hashes.length;
  if(e.schema!==eventSchema || e.issuer!==s.issuer || e.window_id!==s.window_id || e.sequence!==String(n) || !decimal(e.issued_at) ||
    e.previous_event_sha256!==(n?s.hashes[n-1]:null) || !kinds.includes(e.kind))bad('event header at '+n);
  if(e.subject_sha256!==bodyHash(entry.body))bad('blob hash at '+n);
  if(!verifySr25519(Buffer.concat([Buffer.from(eventSchema+'\n'),jcsBytes(e)]),entry.signature,s.issuer))bad('signature at '+n);
  if((n===0)!==(e.kind==='window_open'))bad('genesis');
  if(s.aborted && e.kind!=='appeal')bad('event after abort');
  const b=entry.body as any,now=BigInt(e.issued_at);
  const slot=()=>{const t=s.scheduled.get(tupleKey(tuple(b.tuple)));return t ?? bad('unscheduled tuple');};
  switch(e.kind){
    case 'window_open':{
      exact(b,['policy_sha256','round_id','max_infra_retries','schedule'],'window_open');
      if(!hex(b.policy_sha256) || !hex(b.round_id) || !decimal(b.max_infra_retries) || !Array.isArray(b.schedule))bad('window_open');
      s.maxRetries=Number(b.max_infra_retries);
      for(const t of b.schedule){const k=tupleKey(tuple(t));if(s.scheduled.has(k))bad('duplicate tuple');s.scheduled.set(k,{expires:-1n,retries:-1,output:null,quarantined:false,incomplete:false});}
      break;
    }
    case 'lease':{
      exact(b,['tuple','expires_at'],'lease');const t=slot();
      if(!decimal(b.expires_at) || BigInt(b.expires_at)<=now || t.output!==null || t.incomplete || now<t.expires)bad('lease transition');
      // A re-lease after expiry is an infrastructure retry of the same work, bounded by the opened policy.
      if(++t.retries>s.maxRetries)bad('retry beyond policy');t.expires=BigInt(b.expires_at);break;
    }
    case 'outcome':{
      exact(b,['tuple','output'],'outcome');const t=slot();
      if(t.output!==null || now>=t.expires)bad('outcome without live lease');t.output=bodyHash(b.output);break;
    }
    case 'quarantine':{
      exact(b,['tuple','output'],'quarantine');const t=slot();
      if(t.output===null || t.output===bodyHash(b.output))bad('quarantine without conflict');t.quarantined=true;break;
    }
    case 'incomplete':{
      exact(b,['tuple','reason'],'incomplete');const t=slot();
      if(t.output!==null || t.retries<s.maxRetries || now<t.expires)bad('premature incomplete');t.incomplete=true;break;
    }
    case 'commitment':{
      exact(b,['round_id','commitment'],'commitment');
      if(!hex(b.round_id) || !hex(b.commitment) || s.commitments.has(b.round_id))bad('second commitment for round');
      s.commitments.set(b.round_id,b.commitment);break;
    }
    case 'abort':exact(b,['reason'],'abort');s.aborted=true;break;
    default:if(!b || typeof b!=='object' || Array.isArray(b))bad(e.kind);
  }
  s.hashes.push(eventHash(e));
}
// Round status derived from the full log: incomplete or quarantined work blocks certification of the whole round.
export function roundStatus(s:JournalState){
  const tuples=[...s.scheduled.values()];
  if(s.aborted)return 'aborted';
  if(tuples.some(t=>t.quarantined))return 'disputed';
  if(tuples.some(t=>t.incomplete))return 'incomplete';
  return tuples.every(t=>t.output!==null)?'evaluated':'leased';
}

// ponytail: single-writer SQLite per validator; witnessing/mirroring of checkpoints is the caller's job.
export class EvaluationJournal{
  private constructor(private db:Database,private pair:Pair,readonly state:JournalState,private clock:()=>bigint){}
  static async open(path:string,pair:Pair,window_id:string,clock=()=>BigInt(Math.floor(Date.now()/1000))){
    await cryptoWaitReady();
    const db=new Database(path,{create:true,strict:true});
    db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS blobs(sha256 TEXT PRIMARY KEY,body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL,signature TEXT NOT NULL,blob TEXT NOT NULL REFERENCES blobs(sha256));
      CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'Journal is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'Journal is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS blobs_no_update BEFORE UPDATE ON blobs BEGIN SELECT RAISE(ABORT,'Blobs are immutable'); END;
      CREATE TRIGGER IF NOT EXISTS blobs_no_delete BEFORE DELETE ON blobs BEGIN SELECT RAISE(ABORT,'Blobs are immutable'); END;`);
    const journal=new EvaluationJournal(db,pair,newState(Buffer.from(pair.publicKey).toString('hex'),window_id),clock);
    // Crash recovery re-verifies the whole chain before any new event is signed.
    for(const entry of journal.entries())apply(journal.state,entry);
    return journal;
  }
  entries():Entry[]{
    return (this.db.query('SELECT e.event,e.signature,b.body,e.blob FROM events e JOIN blobs b ON b.sha256=e.blob ORDER BY e.sequence').all() as any[]).map(r=>{
      const body=JSON.parse(r.body);if(bodyHash(body)!==r.blob)bad('stored blob');return {event:JSON.parse(r.event),signature:r.signature,body};
    });
  }
  append(kind:Kind,body:unknown){
    const n=this.state.hashes.length;
    const event:JournalEvent={schema:eventSchema,issuer:this.state.issuer,window_id:this.state.window_id,sequence:String(n),
      previous_event_sha256:n?this.state.hashes[n-1]:null,kind,subject_sha256:bodyHash(body),issued_at:String(this.clock())};
    const entry={event,signature:signWith(this.pair,Buffer.concat([Buffer.from(eventSchema+'\n'),jcsBytes(event)])),body:structuredClone(body)};
    const trial=structuredClone({...this.state,scheduled:new Map([...this.state.scheduled].map(([k,v])=>[k,{...v}]))});
    apply(trial,entry); // Reject invalid transitions before anything durable happens.
    this.db.transaction(()=>{
      // Content-addressed blob first, then the referencing event, in one atomic transaction.
      this.db.query('INSERT OR IGNORE INTO blobs VALUES(?,?)').run(event.subject_sha256,jcs(body));
      this.db.query('INSERT INTO events VALUES(?,?,?,?)').run(n,jcs(event),entry.signature,event.subject_sha256);
    }).immediate();
    Object.assign(this.state,trial);
    return eventHash(event);
  }
  lease(t:Tuple,ttl:bigint):'leased'|'busy'|'done'|'incomplete'{
    const s=this.state.scheduled.get(tupleKey(t)) ?? bad('unscheduled tuple'),now=this.clock();
    if(s.output!==null)return 'done';
    if(s.incomplete)return 'incomplete';
    if(now<s.expires)return 'busy';
    if(s.retries>=this.state.maxRetries && s.retries>=0){this.append('incomplete',{tuple:t,reason:'infra_retries_exhausted'});return 'incomplete';}
    this.append('lease',{tuple:t,expires_at:String(now+ttl)});return 'leased';
  }
  // Duplicate completion is idempotent; a conflicting output is quarantined, never overwritten.
  complete(t:Tuple,output:unknown):'recorded'|'duplicate'|'quarantined'{
    const s=this.state.scheduled.get(tupleKey(t)) ?? bad('unscheduled tuple');
    if(s.output===bodyHash(output))return 'duplicate';
    if(s.output!==null){this.append('quarantine',{tuple:t,output});return 'quarantined';}
    this.append('outcome',{tuple:t,output});return 'recorded';
  }
  root(){return windowRoot(this.state.hashes);}
  export(){return jcsBytes(this.entries());}
  checkpoint(){return signCheckpoint(this.pair,{window_id:this.state.window_id,sequence:String(this.state.hashes.length-1),head_sha256:this.state.hashes.at(-1)!,window_root:this.root()});}
  close(){this.db.close();}
}

// Offline verification: bytes only, no database, no network.
export async function verifyJournalExport(bytes:Uint8Array,issuer:string,window_id:string){
  await cryptoWaitReady();
  const entries=parseCanonical(bytes,256<<20);
  if(!Array.isArray(entries) || !entries.length)bad('export');
  const s=newState(issuer,window_id);
  for(const x of entries as unknown[])apply(s,exact(x,['event','signature','body'],'entry') as Entry);
  return {state:s,root:windowRoot(s.hashes),head:s.hashes.at(-1)!,status:roundStatus(s)};
}

if(import.meta.main){
  const [action,file,issuer,window_id,...extra]=process.argv.slice(2);
  try{
    if(action!=='verify' || !file || !hex(issuer) || !ident(window_id) || extra.length)throw new Error('Usage: engine-journal.ts verify EXPORT ISSUER_HEX WINDOW_ID');
    const r=await verifyJournalExport(new Uint8Array(await Bun.file(file).arrayBuffer()),issuer,window_id);
    console.log(jcs({events:r.state.hashes.length,head:r.head,root:r.root,status:r.status}));
  }catch(error){console.error(error instanceof Error?error.message:'verify failed');process.exitCode=1;}
}

// ---- Signed head checkpoints; two different heads at one position from one issuer are equivocation evidence.
export type Checkpoint={payload:{schema:'sentinel-engine-journal-checkpoint/v1';issuer:string;window_id:string;sequence:string;head_sha256:string;window_root:string};signature:string};
const checkpointBytes=(p:Checkpoint['payload'])=>Buffer.concat([Buffer.from('sentinel-engine-journal-checkpoint/v1\n'),jcsBytes(p)]);
function signCheckpoint(pair:Pair,o:Omit<Checkpoint['payload'],'schema'|'issuer'>):Checkpoint{
  const payload={schema:'sentinel-engine-journal-checkpoint/v1' as const,issuer:Buffer.from(pair.publicKey).toString('hex'),...o};
  return {payload,signature:signWith(pair,checkpointBytes(payload))};
}
export function verifyCheckpoint(c:Checkpoint,hashes?:string[]){
  const p=exact(exact(c,['payload','signature'],'checkpoint').payload,['schema','issuer','window_id','sequence','head_sha256','window_root'],'checkpoint') as Checkpoint['payload'];
  if(p.schema!=='sentinel-engine-journal-checkpoint/v1' || !hex(p.issuer) || !decimal(p.sequence) || !verifySr25519(checkpointBytes(p),c.signature,p.issuer))bad('checkpoint signature');
  // Against a verified log: the checkpoint must name exactly that prefix.
  if(hashes && (hashes[Number(p.sequence)]!==p.head_sha256 || windowRoot(hashes.slice(0,Number(p.sequence)+1))!==p.window_root))bad('checkpoint does not match log');
  return p;
}
export function detectForks(checkpoints:Checkpoint[]){
  const seen=new Map<string,Checkpoint>(),forks:[Checkpoint,Checkpoint][]=[];
  for(const c of checkpoints){
    const p=verifyCheckpoint(c),k=jcs([p.issuer,p.window_id,p.sequence]),prior=seen.get(k);
    if(prior && prior.payload.head_sha256!==p.head_sha256)forks.push([prior,c]);else seen.set(k,c);
  }
  return forks;
}

// ---- `sentinel-engine-attestation/v1` (challenge roles, sr25519).
export const attestationTypes=['intake','freeze','evaluation','adjudication','weight_plan','weight_observation','release','revocation'] as const;
export type AttestationPayload={schema:'sentinel-engine-attestation/v1';type:typeof attestationTypes[number];issuer:string;role:string;network:unknown;window_id:string;policy_sha256:string;
  subject_sha256:string;predicate_sha256:string;previous_event_sha256:string|null;sequence:string;issued_at:string};
// role -> keys and types it may attest. Supplied from a signed policy; null means unresolved.
export type RoleRegistry=Record<string,{keys:string[];types:string[]}>|null;
export const predicateHash=(type:string,predicate:unknown)=>hashOf('sentinel-engine-predicate/v1',{type,predicate});
const attestationBytes=(p:AttestationPayload)=>Buffer.concat([Buffer.from('sentinel-engine-attestation/v1\n'),jcsBytes(p)]);
export function signAttestation(pair:Pair,p:AttestationPayload){
  return jcsBytes({payload:p,signature:{scheme:'sr25519',public_key:Buffer.from(pair.publicKey).toString('hex'),value:signWith(pair,attestationBytes(p))}});
}
export async function verifyAttestation(bytes:Uint8Array,registry:RoleRegistry,predicate:unknown){
  await cryptoWaitReady();
  const w=exact(parseCanonical(bytes,1<<20),['payload','signature'],'attestation');
  const p=exact(w.payload,['schema','type','issuer','role','network','window_id','policy_sha256','subject_sha256','predicate_sha256','previous_event_sha256','sequence','issued_at'],'attestation') as AttestationPayload;
  const sig=exact(w.signature,['scheme','public_key','value'],'attestation signature');
  if(p.schema!=='sentinel-engine-attestation/v1' || !attestationTypes.includes(p.type))bad('attestation type');
  // Product release keys are Ed25519 from a separate trust root; weight events need finalized chain state.
  if(p.type==='release' || p.type==='revocation')throw new PolicyUnresolved('product_release_trust_root_unresolved');
  if(p.type==='weight_plan' || p.type==='weight_observation')throw new PolicyUnresolved('finalized_chain_required');
  if(!registry)throw new PolicyUnresolved('role_registry_unresolved');
  if(!ident(p.window_id) || !hex(p.policy_sha256) || !hex(p.subject_sha256) || !decimal(p.sequence) || !decimal(p.issued_at) || !(p.previous_event_sha256===null || hex(p.previous_event_sha256)))bad('attestation fields');
  const role=registry[p.role];
  if(!role || !role.keys.includes(p.issuer) || !role.types.includes(p.type))bad('role authority');
  if(sig.scheme!=='sr25519' || sig.public_key!==p.issuer || !verifySr25519(attestationBytes(p),sig.value,p.issuer))bad('attestation signature');
  if(p.predicate_sha256!==predicateHash(p.type,predicate))bad('predicate binding');
  return {payload:p,attestation_sha256:hashOf('sentinel-engine-attestation/v1',p)};
}
