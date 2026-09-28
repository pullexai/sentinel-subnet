import {Database} from 'bun:sqlite';
import {randomBytes} from 'node:crypto';
import {lstatSync,mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {cryptoWaitReady,decodeAddress,sr25519Verify} from '@polkadot/util-crypto';
import {canonical,quorumPolicyDigest,scoreTarget,scoreAttestationPayload,type ScoreTarget} from './attestations';
import {evaluateSnapshot,validateSnapshot,sha256,snapshotByteLimit,type SnapshotExpectation} from './protocol';
import {executionIdentity} from './competition';
import {corpus} from './corpus';
import type {PracticeTuple} from './validator';

type Tuple=Omit<PracticeTuple,'paths'>;
export type TranscriptPolicy={schema:'sentinel-practice-transcript-policy/v2';profile:'sentinel-literal-single-trial/v1';
  expected:SnapshotExpectation;validators:string[];tuples:Tuple[];commitDeadline:number;openingDeadline:number};
type Phase='transcript'|'commit'|'list'|'set';
export type Signed<T=unknown>={schema:'sentinel-practice-signed/v2';phase:Phase;policySha256:string;validator:string;issuedAt:number;body:T;signature:string};
type Transcript={target:ScoreTarget;tuples:PracticeTuple[]};
export type Opening={schema:'sentinel-practice-opening/v2';validator:string;salt:string;transcript:Signed<Transcript>};
type Sign=(payload:Uint8Array)=>Promise<string>;
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v && typeof v==='object' && !Array.isArray(v) && Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k));
const hex=(v:unknown):v is string=>typeof v==='string' && /^[a-f0-9]{64}$/.test(v);
const integer=(v:unknown):v is number=>Number.isSafeInteger(v) && (v as number)>=0;
export const transcriptByteLimit=16*1024*1024;
export const transcriptDigest=(domain:string,value:unknown)=>sha256(Buffer.from(`sentinel/practice-${domain}/v2\n`+canonical(value)));
const raw=(validator:string)=>Buffer.from(decodeAddress(validator,false,42)).toString('hex');
const rosterSort=(validators:string[])=>[...validators].sort((a,b)=>raw(a)<raw(b)?-1:raw(a)>raw(b)?1:0);
const tupleKey=(t:Tuple)=>`${t.executionIdentity}:${t.caseId}:${t.trialIndex}:${t.role}`;
const tupleSort=(tuples:PracticeTuple[])=>[...tuples].sort((a,b)=>tupleKey(a)<tupleKey(b)?-1:tupleKey(a)>tupleKey(b)?1:0);
function bounded(value:unknown){if(Buffer.byteLength(canonical(value))>transcriptByteLimit)throw new Error('Transcript wire byte limit');}
export function parseTranscriptJSON(bytes:Uint8Array){
  if(bytes.length>transcriptByteLimit)throw new Error('Transcript wire byte limit');
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes),value=JSON.parse(text);
  if(JSON.stringify(value)!==text)throw new Error('Compact unambiguous JSON required');return value;
}
export function transcriptPolicyDigest(value:unknown):string{
  if(!exact(value,['schema','profile','expected','validators','tuples','commitDeadline','openingDeadline']) || value.schema!=='sentinel-practice-transcript-policy/v2' ||
    value.profile!=='sentinel-literal-single-trial/v1' || !Array.isArray(value.validators) || value.validators.length>8 ||
    !Array.isArray(value.tuples) || value.tuples.length<1 || value.tuples.length>4096 || !integer(value.commitDeadline) || !integer(value.openingDeadline) || value.openingDeadline<=value.commitDeadline)throw new Error('Invalid transcript policy');
  quorumPolicyDigest({schema:'sentinel-quorum-policy/v2',validators:value.validators,threshold:value.validators.length,maxFaultyValidators:0});
  if(canonical(value.validators)!==canonical(rosterSort(value.validators)))throw new Error('Roster requires raw-public-key order');
  let previous='';
  for(const t of value.tuples){
    if(!exact(t,['role','executionIdentity','caseId','trialIndex']) || !['baseline','candidate'].includes(t.role as string) || !hex(t.executionIdentity) || !hex(t.caseId) || t.trialIndex!==0)throw new Error('Invalid scheduled tuple');
    const key=tupleKey(t as Tuple);if(key<=previous)throw new Error('Duplicate or unordered scheduled tuple');previous=key;
  }
  bounded(value);return transcriptDigest('transcript-policy',value);
}
function schedule(f:Awaited<ReturnType<typeof validateSnapshot>>['f']):Tuple[]{
  const cases=corpus(f.seed,f.pairs).map(x=>x.input.id);
  const identities=[...new Set(f.contributions.map(c=>executionIdentity(c.submission)))];
  const bundles=[{role:'baseline' as const,executionIdentity:f.baseline},...identities.map(id=>({role:'candidate' as const,executionIdentity:id}))];
  return bundles.flatMap(bundle=>cases.map(caseId=>({...bundle,caseId,trialIndex:0 as const}))).sort((a,b)=>tupleKey(a)<tupleKey(b)?-1:tupleKey(a)>tupleKey(b)?1:0);
}
export async function planTranscripts(bytes:Uint8Array,expected:SnapshotExpectation,validators:string[],commitDeadline:number,openingDeadline:number):Promise<TranscriptPolicy>{
  validators=structuredClone(validators);
  const {f,expectations}=await validateSnapshot(bytes,expected);
  quorumPolicyDigest({validators,threshold:validators.length});
  const policy:TranscriptPolicy={schema:'sentinel-practice-transcript-policy/v2',profile:'sentinel-literal-single-trial/v1',expected:expectations,validators:rosterSort(validators),tuples:schedule(f),commitDeadline,openingDeadline};
  transcriptPolicyDigest(policy);return policy;
}
export function transcriptPayload(value:Omit<Signed,'signature'>){return Buffer.from('sentinel/practice-signature/v2\n'+canonical(value));}

// ponytail: one local round/validator per journal, unanimous roster, one deterministic trial,
// no execution retry after an interrupted run. New profiles need versioned attempts/leases.
export class TranscriptJournal{
  private db:Database;
  private policy:TranscriptPolicy;
  private policySha256:string;
  private validator:string;
  private constructor(directory:string,policy:TranscriptPolicy,validator:string,private clock:()=>number){
    this.policy=policy;this.policySha256=transcriptPolicyDigest(policy);this.validator=validator;
    if(!policy.validators.includes(validator))throw new Error('Unregistered practice validator');
    mkdirSync(directory,{recursive:true,mode:0o700});const info=lstatSync(directory);
    if(!info.isDirectory() || info.isSymbolicLink() || info.mode&0o077)throw new Error('Private transcript journal directory required');
    const path=join(directory,'transcripts.sqlite');
    try{const file=lstatSync(path);if(!file.isFile() || file.isSymbolicLink() || file.nlink!==1)throw new Error('Unsafe transcript journal file');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    this.db=new Database(path,{create:true,strict:true});
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS transcript_state(key TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL);
      CREATE TRIGGER IF NOT EXISTS transcript_no_update BEFORE UPDATE ON transcript_state BEGIN SELECT RAISE(ABORT,'Transcript state is immutable'); END;
      CREATE TRIGGER IF NOT EXISTS transcript_no_delete BEFORE DELETE ON transcript_state BEGIN SELECT RAISE(ABORT,'Transcript state is permanent'); END;
      CREATE TRIGGER IF NOT EXISTS transcript_no_replace BEFORE INSERT ON transcript_state WHEN EXISTS(SELECT 1 FROM transcript_state WHERE key=NEW.key)
        BEGIN SELECT RAISE(ABORT,'Transcript state cannot be replaced'); END;`);
    try{this.save('identity',{policy,validator});}catch(error){this.db.close();throw error;}
  }
  static async open(directory:string,policy:TranscriptPolicy,validator:string,bytes:Uint8Array,clock=Date.now){
    policy=structuredClone(policy);transcriptPolicyDigest(policy);
    const {f}=await validateSnapshot(bytes,policy.expected);
    if(canonical(schedule(f))!==canonical(policy.tuples))throw new Error('Incomplete or substituted execution schedule');
    return new TranscriptJournal(directory,policy,validator,clock);
  }
  private get<T=any>(key:string):T|undefined{
    const row=this.db.query('SELECT body,digest FROM transcript_state WHERE key=?').get(key) as {body:string;digest:string}|null;
    if(!row)return;
    const value=parseTranscriptJSON(Buffer.from(row.body));
    if(canonical(value)!==row.body || sha256(Buffer.from(row.body))!==row.digest)throw new Error('Transcript journal integrity failure');
    return value;
  }
  private save<T>(key:string,value:T):T{
    bounded(value);const body=canonical(value);
    return this.db.transaction(()=>{
      const prior=this.get<T>(key);
      if(prior!==undefined){if(canonical(prior)!==body)throw new Error(`Conflicting transcript state: ${key}`);return prior;}
      this.db.query('INSERT INTO transcript_state(key,body,digest) VALUES(?,?,?)').run(key,body,sha256(Buffer.from(body)));return structuredClone(value);
    }).immediate();
  }
  private healthy(){if(this.get('equivocation'))throw new Error('Transcript round equivocated');if(this.get('aborted') || this.get('late'))throw new Error('Transcript round aborted');}
  private now(){const now=this.clock();if(!integer(now))throw new Error('Invalid transcript clock');return now;}
  private deadline(phase:Phase){return phase==='set'?this.policy.openingDeadline:this.policy.commitDeadline;}
  private timely(phase:Phase){if(this.now()>=this.deadline(phase)){if(!this.get('late'))this.save('late',{phase,at:this.now()});throw new Error(`Late ${phase} evidence`);}}
  private verify(value:unknown,phase:Phase):Signed{
    if(!exact(value,['schema','phase','policySha256','validator','issuedAt','body','signature']) || value.schema!=='sentinel-practice-signed/v2' || value.phase!==phase ||
      value.policySha256!==this.policySha256 || typeof value.validator!=='string' || !this.policy.validators.includes(value.validator) || !integer(value.issuedAt) ||
      value.issuedAt>=this.deadline(phase) || value.issuedAt>this.now() || typeof value.signature!=='string' || !/^[a-f0-9]{128}$/.test(value.signature))throw new Error('Invalid transcript signature scope or time');
    const {signature,...payload}=value as Signed;
    let valid=false;
    try{valid=sr25519Verify(transcriptPayload(payload),Buffer.from(signature,'hex'),decodeAddress(payload.validator,false,42));}catch{}
    if(!valid)throw new Error('Invalid transcript signature');
    const b=payload.body;
    if(phase==='transcript'){
      if(!exact(b,['target','tuples']) || !Array.isArray(b.tuples) || b.tuples.length!==this.policy.tuples.length)throw new Error('Incomplete transcript');
      scoreAttestationPayload(b.target as ScoreTarget,this.policySha256,payload.validator);
      const expected=this.policy.expected,t=b.target as ScoreTarget;
      if(t.cohortSha256!==expected.cohortSha256 || t.genesis!==expected.scope.genesis || t.netuid!==expected.scope.netuid || t.round!==expected.scope.round)throw new Error('Transcript target mismatch');
      for(let i=0;i<b.tuples.length;i++){
        const tuple=b.tuples[i];
        if(!exact(tuple,['role','executionIdentity','caseId','trialIndex','paths']) || !Array.isArray(tuple.paths) || tuple.paths.length>100 ||
          tuple.paths.some(p=>typeof p!=='string' || !/^[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*\.[a-zA-Z0-9]+$/.test(p)) ||
          canonical([...new Set(tuple.paths)].sort())!==canonical(tuple.paths))throw new Error('Invalid transcript output');
        const {paths,...identity}=tuple;
        if(canonical(identity)!==canonical(this.policy.tuples[i]))throw new Error('Missing, duplicate or substituted transcript tuple');
      }
    }else if(phase==='commit'){
      if(!exact(b,['commitment']) || !hex(b.commitment))throw new Error('Invalid transcript commitment');
    }else if(phase==='list'){
      if(!exact(b,['root']) || !hex(b.root))throw new Error('Invalid commitment-list vote');
    }else if(!exact(b,['listRoot','root']) || !hex(b.listRoot) || !hex(b.root))throw new Error('Invalid transcript-set vote');
    return value as Signed;
  }
  private observe(vote:Signed){
    const key=`seen:${vote.phase}:${vote.validator}`;
    const conflict=this.db.transaction(()=>{
      const prior=this.get<Signed>(key);
      if(prior){this.verify(prior,vote.phase);if(canonical(prior.body)!==canonical(vote.body)){if(!this.get('equivocation'))this.save('equivocation',{first:prior,second:vote});return true;}}
      else this.save(key,vote);
      return false;
    }).immediate();
    if(conflict)throw new Error('Transcript round equivocated');
  }
  private roster(values:unknown,phase:Phase):Signed[]{
    bounded(values);
    if(!Array.isArray(values) || values.length>2*this.policy.validators.length)throw new Error('Complete execution roster required');
    const votes:Signed[]=[],errors:unknown[]=[];
    // Persist authenticated evidence even when another sibling invalidates the batch.
    for(const value of values)try{
      const vote=this.verify(value,phase);this.observe(vote);votes.push(vote);
    }catch(error){errors.push(error);}
    if(errors.length)throw errors[0];
    if(new Set(votes.map(v=>v.validator)).size!==votes.length)throw new Error('Duplicate roster member');
    if(votes.length!==this.policy.validators.length)throw new Error('Complete execution roster required');
    votes.sort((a,b)=>raw(a.validator)<raw(b.validator)?-1:1);
    this.healthy();return votes;
  }
  private async sign(phase:Phase,body:unknown,sign:Sign):Promise<Signed>{
    this.healthy();const key=`signed:${phase}`,stored=this.get<Signed>(key);
    if(stored){this.verify(stored,phase);if(canonical(stored.body)!==canonical(body) || stored.validator!==this.validator)throw new Error('Conflicting signing target');return stored;}
    this.timely(phase);
    const intentKey=`intent:${phase}`;
    const intent=this.db.transaction(()=>{
      const previous=this.get<Omit<Signed,'signature'>>(intentKey);
      if(previous){if(canonical(previous.body)!==canonical(body))throw new Error('Conflicting signing target');return previous;}
      return this.save(intentKey,{schema:'sentinel-practice-signed/v2' as const,phase,policySha256:this.policySha256,validator:this.validator,issuedAt:this.now(),body});
    }).immediate();
    const vote={...intent,signature:await sign(transcriptPayload(intent))};
    this.verify(vote,phase);this.healthy();this.timely(phase);
    this.observe(vote);
    return this.db.transaction(()=>{
      this.healthy();
      const first=this.get<Signed>(key);
      if(first){this.verify(first,phase);if(canonical(first.body)!==canonical(body))throw new Error('Conflicting signing target');return first;}
      return this.save(key,vote);
    }).immediate();
  }
  private commitment(opening:Opening){
    return transcriptDigest('transcript-opening',{policySha256:this.policySha256,validator:opening.validator,salt:opening.salt,
      transcriptSha256:transcriptDigest('transcript',opening.transcript.body),attestationSha256:transcriptDigest('attestation',opening.transcript)});
  }
  private local():Opening{
    const opening=this.get<Opening>('opening');if(!opening)throw new Error('Local execution commitment required');
    if(!exact(opening,['schema','validator','salt','transcript']) || opening.schema!=='sentinel-practice-opening/v2')throw new Error('Local opening integrity failure');
    this.verify(opening.transcript,'transcript');
    const commit=this.get<Signed<{commitment:string}>>('signed:commit');
    if(!commit || commit.validator!==this.validator || opening.transcript.validator!==this.validator || opening.validator!==this.validator || !hex(opening.salt) || this.commitment(opening)!==commit.body.commitment)throw new Error('Local commitment integrity failure');
    this.verify(commit,'commit');return opening;
  }
  private frozenList(){
    const list=this.get<{root:string;votes:Signed<{commitment:string}>[]}>('list');if(!list)throw new Error('Freeze complete commitment list first');
    const votes=this.roster(list.votes,'commit');
    if(transcriptDigest('commitment-list',votes.map(v=>({validator:raw(v.validator),commitment:(v.body as any).commitment})))!==list.root ||
      list.votes.find(v=>v.validator===this.validator)?.body.commitment!==this.commitment(this.local()))throw new Error('Commitment-list integrity failure');
    return list;
  }
  async execute(bytes:Uint8Array,sign:Sign){
    if(!(bytes instanceof Uint8Array) || bytes.length>snapshotByteLimit)throw new Error('Snapshot byte limit');
    bytes=Buffer.from(bytes);this.healthy();await cryptoWaitReady();
    if(sha256(bytes)!==this.policy.expected.cohortSha256)throw new Error('Snapshot digest mismatch');
    const stored=this.get<Signed>('signed:commit');if(stored){this.local();return stored;}
    this.timely('commit');
    let completed=this.get<{salt:string;body:Transcript}>('execution');
    if(!completed){
      this.db.transaction(()=>{
        if(this.get('started'))throw new Error('Incomplete execution; new practice round required');
        this.save('started',{at:this.now()});
      }).immediate();
      try{
        let tuples:PracticeTuple[]=[];
        const report=await evaluateSnapshot(bytes,this.policy.expected,value=>{tuples=tupleSort(value);});
        const body={target:scoreTarget(report),tuples};
        if(canonical(tuples.map(({paths,...identity})=>identity))!==canonical(this.policy.tuples))throw new Error('Execution schedule mismatch');
        completed=this.save('execution',{salt:randomBytes(32).toString('hex'),body});
      }catch(error){this.save('aborted',{reason:'execution-failed'});throw error;}
    }
    const transcript=await this.sign('transcript',completed.body,sign) as Signed<Transcript>;
    const opening=this.save('opening',{schema:'sentinel-practice-opening/v2' as const,validator:this.validator,salt:completed.salt,transcript});
    return this.sign('commit',{commitment:this.commitment(opening)},sign);
  }
  async freeze(values:unknown,sign:Sign){
    values=structuredClone(values);await cryptoWaitReady();this.healthy();
    const local=this.local(),votes=this.roster(values,'commit');
    if((votes.find(v=>v.validator===this.validator)!.body as any).commitment!==this.commitment(local))throw new Error('Local commitment missing');
    const root=transcriptDigest('commitment-list',votes.map(v=>({validator:raw(v.validator),commitment:(v.body as any).commitment})));
    if(!this.get('list'))this.timely('list');
    this.save('list',{root,votes});return this.sign('list',{root},sign);
  }
  async opening(values:unknown){
    values=structuredClone(values);await cryptoWaitReady();this.healthy();
    const list=this.frozenList();
    const votes=this.roster(values,'list');
    if(votes.some(v=>(v.body as any).root!==list.root))throw new Error('Conflicting commitment-list certificate');
    if(!this.get('list-certificate'))this.timely('list');
    return this.db.transaction(()=>{
      this.healthy();
      this.save('list-certificate',{root:list.root,votes});return this.local();
    }).immediate();
  }
  private validateOpenings(values:unknown){
    const list=this.frozenList(),certificate=this.get<{root:string;votes:Signed[]}>('list-certificate');
    if(!certificate || certificate.root!==list.root)throw new Error('Certified complete commitment list required');
    const certifiers=this.roster(certificate.votes,'list');
    if(certifiers.some(v=>(v.body as any).root!==list.root))throw new Error('Commitment-list integrity failure');
    bounded(values);
    if(!Array.isArray(values) || values.length>2*this.policy.validators.length)throw new Error('Complete execution roster required');
    const openings=values as Opening[],seen=new Set<string>(),local=this.local(),errors:unknown[]=[];
    for(const opening of openings)try{
      if(!exact(opening,['schema','validator','salt','transcript']) || opening.schema!=='sentinel-practice-opening/v2' || typeof opening.validator!=='string' || !hex(opening.salt))throw new Error('Invalid transcript opening');
      const vote=this.verify(opening.transcript,'transcript');
      if(vote.validator!==opening.validator)throw new Error('Mismatched opening validator');
      this.observe(vote);
      if(seen.has(opening.validator))throw new Error('Duplicate opening validator');
      seen.add(opening.validator);
      if(this.commitment(opening)!==list.votes.find(v=>v.validator===opening.validator)?.body.commitment)throw new Error('Transcript opening digest or salt mismatch');
      // This profile is deterministic: all normalized tuples and locally recomputed targets must match.
      if(canonical(vote.body)!==canonical(local.transcript.body))throw new Error('Deterministic transcript disagreement');
    }catch(error){errors.push(error);}
    if(errors.length)throw errors[0];
    if(openings.length!==this.policy.validators.length)throw new Error('Complete execution roster required');
    openings.sort((a,b)=>raw(a.validator)<raw(b.validator)?-1:1);
    const descriptors=openings.map(o=>({validator:raw(o.validator),transcriptSha256:transcriptDigest('transcript',o.transcript.body),attestationSha256:transcriptDigest('attestation',o.transcript)}));
    return {listRoot:list.root,root:transcriptDigest('transcript-set',descriptors),descriptors,openings};
  }
  async agree(values:unknown,sign:Sign){
    values=structuredClone(values);await cryptoWaitReady();this.healthy();
    const set=this.validateOpenings(values);
    if(!this.get('set'))this.timely('set');
    this.save('set',set);return this.sign('set',{listRoot:set.listRoot,root:set.root},sign);
  }
  async certify(values:unknown){
    values=structuredClone(values);await cryptoWaitReady();this.healthy();
    const set=this.get<ReturnType<TranscriptJournal['validateOpenings']>>('set');if(!set)throw new Error('Complete transcript set required');
    if(canonical(this.validateOpenings(set.openings))!==canonical(set))throw new Error('Transcript-set integrity failure');
    const votes=this.roster(values,'set');
    if(votes.some(v=>canonical(v.body)!==canonical({listRoot:set.listRoot,root:set.root})))throw new Error('Conflicting transcript-set certificate');
    if(!this.get('certificate'))this.timely('set');
    return this.db.transaction(()=>{
      this.healthy();
      return this.save('certificate',{schema:'sentinel-practice-transcript-set/v2',policySha256:this.policySha256,listRoot:set.listRoot,transcriptSetRoot:set.root,
        descriptors:set.descriptors,votes,target:this.local().transcript.body.target,weights:null,rewards:null});
    }).immediate();
  }
  close(){this.db.close();}
}
