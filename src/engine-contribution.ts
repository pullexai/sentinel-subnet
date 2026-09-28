import {Database} from 'bun:sqlite';
import {createHash} from 'node:crypto';
import {cryptoWaitReady,sr25519Verify} from '@polkadot/util-crypto';
import {jcs,jcsBytes,parseCanonical} from './jcs';

// EC-02 `sentinel-engine-contribution/v1`: strict signed envelope. Legacy practice formats
// (`sentinel-contribution/v1` etc. in protocol.ts) keep their own domains and are not accepted here.
export const contributionMediaType='application/vnd.sentinel.engine-contribution+json';
export const contributionProtocol='sentinel-engine-contribution/v1';
export const contributionDomain=contributionProtocol+'\n';
export const contributionByteLimit=256*1024; // Wire ceiling only; policy owns real admission limits.
export const formatIds=['structural-rule/v1','taint-rule/v1','retrieval-profile/v1','tensor-model/v1','lora-adapter/v1','fix-template/v1'] as const;
const modelFormats=new Set(['tensor-model/v1','lora-adapter/v1']);
const lanes=['detection','retrieval','fix','test'],scopes=['file','module','repository'],operations=['add_rules','replace'];
const componentRoles=['base_model','tokenizer','engine','grammar','retriever','prompt_adapter','output_adapter','build_fixture'];

export type Network={genesis_hash:string;subnet_creation_block_hash:string;subnet_creation_height:string;subnet_owner_public_key:string;netuid:string;mechanism_id:string};
export type ArtifactFile={path:string;sha256:string;bytes:string;media_type:string;role:string};
export type ContributionPayload={
  protocol:typeof contributionProtocol;network:Network;
  submitter:{hotkey_public_key:string;registration_block_hash:string;registration_height:string};
  window_id:string;policy_sha256:string;baseline_bundle_sha256:string;lane:string;
  format:{id:string;schema_sha256:string};
  artifact:{files:ArtifactFile[];files_sha256:string;entrypoint:string};
  origins:{origin_id:string;immutable_revision:string;file_path:string;artifact_path:string}[];
  components:{role:string;component_sha256:string}[];
  change:{slot:string;operation:string;replaces_sha256:string|null};
  capabilities:{languages:string[];build_variants:string[];categories:string[];analysis_profile_sha256:string;scope:string};
  execution_profile_sha256:string;output_schema_sha256:string;
  provenance:{license_expression:string;license_files:string[];source_revisions:string[];derived_from:string[];training_data_statement_sha256:string|null};
  nonce:string;issued_at:string;expires_at:string;
};
export type ContributionEnvelope={payload:ContributionPayload;signature:{scheme:'sr25519';public_key:string;value:string}};
export type ContributionExpectation={network:Network;window_id:string;policy_sha256:string;baseline_bundle_sha256:string;now:bigint;max_lifetime_seconds:bigint;max_skew_seconds:bigint};

const sha256=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const reject=(field:string):never=>{throw new Error('Invalid contribution '+field);};
function object(value:unknown,keys:string[],field:string):Record<string,unknown>{
  if(!value || typeof value!=='object' || Array.isArray(value))reject(field);
  const actual=Object.keys(value as object);
  if(actual.length!==keys.length || !keys.every(k=>Object.hasOwn(value as object,k)))reject(field);
  return value as Record<string,unknown>;
}
const digest=(v:unknown,f:string)=>typeof v==='string' && /^[0-9a-f]{64}$/.test(v)?v:reject(f);
const key=(v:unknown,f:string)=>digest(v,f); // Raw 32-byte sr25519 public key, lowercase hex.
const u64=2n**64n-1n;
// `0` or nonzero digit then digits; bounded to u64 so arbitrary big integers cannot pass.
function decimal(v:unknown,f:string,max=u64){
  if(typeof v!=='string' || !/^(0|[1-9][0-9]{0,19})$/.test(v) || BigInt(v)>max)reject(f);
  return BigInt(v as string);
}
const ident=(v:unknown,f:string)=>typeof v==='string' && /^[a-z0-9][a-z0-9._-]{0,127}$/.test(v)?v:reject(f);
const oneOf=(v:unknown,values:readonly string[],f:string)=>typeof v==='string' && values.includes(v)?v:reject(f);
// Manifest path grammar: ASCII segments, no hidden/traversal segments, no case collisions (checked per list).
const path=(v:unknown,f:string)=>typeof v==='string' && v.length<=255 && v.split('/').every(s=>/^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/.test(s))?v:reject(f);
// Set-like array: strictly ascending by UTF-16 order of its sort key, hence sorted and duplicate-free.
function sortedSet<T>(v:unknown,f:string,item:(x:unknown)=>T,sortKey:(x:T)=>string,min=0,max=1024):T[]{
  if(!Array.isArray(v) || v.length<min || v.length>max)reject(f);
  const items=(v as unknown[]).map(item),keys=items.map(sortKey);
  for(let i=1;i<keys.length;i++)if(!(keys[i-1]<keys[i]))reject(f+' order or duplicate');
  return items;
}
const tuple=(...parts:string[])=>jcs(parts);

export function validatePayload(value:unknown):ContributionPayload{
  const p=object(value,['protocol','network','submitter','window_id','policy_sha256','baseline_bundle_sha256','lane','format','artifact','origins','components','change','capabilities','execution_profile_sha256','output_schema_sha256','provenance','nonce','issued_at','expires_at'],'payload');
  if(p.protocol!==contributionProtocol)reject('protocol');
  const n=object(p.network,['genesis_hash','subnet_creation_block_hash','subnet_creation_height','subnet_owner_public_key','netuid','mechanism_id'],'network');
  digest(n.genesis_hash,'network');digest(n.subnet_creation_block_hash,'network');decimal(n.subnet_creation_height,'network');
  key(n.subnet_owner_public_key,'network');decimal(n.netuid,'netuid',65535n);decimal(n.mechanism_id,'mechanism_id',255n);
  const s=object(p.submitter,['hotkey_public_key','registration_block_hash','registration_height'],'submitter');
  key(s.hotkey_public_key,'submitter');digest(s.registration_block_hash,'submitter');decimal(s.registration_height,'submitter');
  ident(p.window_id,'window_id');digest(p.policy_sha256,'policy_sha256');digest(p.baseline_bundle_sha256,'baseline_bundle_sha256');
  oneOf(p.lane,lanes,'lane');
  const fmt=object(p.format,['id','schema_sha256'],'format');oneOf(fmt.id,formatIds,'format');digest(fmt.schema_sha256,'format');
  const a=object(p.artifact,['files','files_sha256','entrypoint'],'artifact');
  const files=sortedSet(a.files,'artifact.files',x=>{
    const file=object(x,['path','sha256','bytes','media_type','role'],'artifact file');
    path(file.path,'artifact path');digest(file.sha256,'artifact file');decimal(file.bytes,'artifact bytes');
    if(typeof file.media_type!=='string' || !/^[a-z0-9][a-z0-9.+-]{0,63}\/[a-z0-9][a-z0-9.+-]{0,63}$/.test(file.media_type))reject('media_type');
    ident(file.role,'artifact role');return file as ArtifactFile;
  },f=>f.path,1);
  const listed=new Set(files.map(f=>f.path));
  if(new Set(files.map(f=>f.path.toLowerCase())).size!==files.length)reject('case-colliding paths');
  if(digest(a.files_sha256,'files_sha256')!==sha256(jcsBytes(files)))reject('files_sha256');
  if(!listed.has(path(a.entrypoint,'entrypoint')))reject('entrypoint');
  sortedSet(p.origins,'origins',x=>{
    const o=object(x,['origin_id','immutable_revision','file_path','artifact_path'],'origin');
    ident(o.origin_id,'origin');ident(o.immutable_revision,'origin revision');path(o.file_path,'origin file_path');
    if(!listed.has(path(o.artifact_path,'origin artifact_path')))reject('origin artifact_path');return o;
  },o=>o.artifact_path as string);
  sortedSet(p.components,'components',x=>{
    const c=object(x,['role','component_sha256'],'component');oneOf(c.role,componentRoles,'component role');digest(c.component_sha256,'component');return c;
  },c=>tuple(c.role as string,c.component_sha256 as string),1);
  const ch=object(p.change,['slot','operation','replaces_sha256'],'change');ident(ch.slot,'change slot');oneOf(ch.operation,operations,'change operation');
  if(ch.operation==='replace')digest(ch.replaces_sha256,'replaces_sha256');else if(ch.replaces_sha256!==null)reject('replaces_sha256');
  const cap=object(p.capabilities,['languages','build_variants','categories','analysis_profile_sha256','scope'],'capabilities');
  for(const field of ['languages','build_variants','categories'])sortedSet(cap[field],'capabilities.'+field,x=>ident(x,'capability'),x=>x,1);
  digest(cap.analysis_profile_sha256,'capabilities');oneOf(cap.scope,scopes,'capabilities scope');
  digest(p.execution_profile_sha256,'execution_profile_sha256');digest(p.output_schema_sha256,'output_schema_sha256');
  const pr=object(p.provenance,['license_expression','license_files','source_revisions','derived_from','training_data_statement_sha256'],'provenance');
  if(typeof pr.license_expression!=='string' || !/^[A-Za-z0-9.+()-]+(?: [A-Za-z0-9.+()-]+){0,63}$/.test(pr.license_expression))reject('license_expression');
  sortedSet(pr.license_files,'license_files',x=>listed.has(path(x,'license file'))?x as string:reject('license file'),x=>x,1);
  sortedSet(pr.source_revisions,'source_revisions',x=>ident(x,'source revision'),x=>x);
  sortedSet(pr.derived_from,'derived_from',x=>digest(x,'derived_from'),x=>x);
  if(modelFormats.has(fmt.id as string))digest(pr.training_data_statement_sha256,'training statement');
  else if(pr.training_data_statement_sha256!==null)reject('training statement');
  decimal(p.nonce,'nonce');
  if(decimal(p.issued_at,'issued_at')>=decimal(p.expires_at,'expires_at'))reject('lifetime');
  return p as ContributionPayload;
}

export function contributionSigningBytes(payload:unknown){
  return Buffer.concat([Buffer.from(contributionDomain,'utf8'),jcsBytes(validatePayload(payload))]);
}
// Identity excludes signature bytes, so randomized sr25519 signatures cannot mint extra attempts.
export const contributionId=(payload:unknown)=>sha256(contributionSigningBytes(payload));

export function envelopeBytes(payload:ContributionPayload,signatureHex:string){
  return jcsBytes({payload,signature:{scheme:'sr25519',public_key:payload.submitter.hotkey_public_key,value:signatureHex}});
}

// Bounded canonical parse and schema checks, then signature, then trusted-policy binding.
// Registration/lineage against finalized chain state is the caller's next, separate step.
export async function verifyContribution(bytes:Uint8Array,expected:ContributionExpectation){
  const e=structuredClone(expected),wire=Buffer.from(bytes);
  const envelope=object(parseCanonical(wire,contributionByteLimit),['payload','signature'],'envelope');
  const payload=validatePayload(envelope.payload);
  const sig=object(envelope.signature,['scheme','public_key','value'],'signature');
  if(sig.scheme!=='sr25519' || key(sig.public_key,'signature key')!==payload.submitter.hotkey_public_key ||
    typeof sig.value!=='string' || !/^[0-9a-f]{128}$/.test(sig.value))reject('signature');
  const message=contributionSigningBytes(payload);
  await cryptoWaitReady();
  let valid=false;
  try{valid=sr25519Verify(message,Buffer.from(sig.value as string,'hex'),Buffer.from(sig.public_key as string,'hex'));}catch{}
  if(!valid)throw new Error('Invalid sr25519 signature');
  if(jcs(payload.network)!==jcs(e.network))reject('network domain');
  if(payload.window_id!==e.window_id || payload.policy_sha256!==e.policy_sha256 || payload.baseline_bundle_sha256!==e.baseline_bundle_sha256)reject('window or policy binding');
  const issued=BigInt(payload.issued_at),expires=BigInt(payload.expires_at);
  if(issued>e.now+e.max_skew_seconds || e.now>=expires || expires-issued>e.max_lifetime_seconds)reject('validity window');
  return {payload,contribution_id:sha256(message)};
}

// Durable replay fence keyed by (network domain, hotkey, nonce). Exact replay returns the same
// receipt; a different contribution under the same nonce is `nonce_conflict`.
export class ContributionNonceLedger{
  private db:Database;
  constructor(file:string){
    this.db=new Database(file,{create:true,strict:true});
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS engine_nonces(domain TEXT NOT NULL,hotkey TEXT NOT NULL,nonce TEXT NOT NULL,contribution_id TEXT NOT NULL,PRIMARY KEY(domain,hotkey,nonce));`);
  }
  record(verified:{payload:ContributionPayload;contribution_id:string}):'received'|'replay'{
    const {payload:p,contribution_id}=verified,domain=jcs(p.network);
    return this.db.transaction(()=>{
      const row=this.db.query('SELECT contribution_id FROM engine_nonces WHERE domain=? AND hotkey=? AND nonce=?').get(domain,p.submitter.hotkey_public_key,p.nonce) as {contribution_id:string}|null;
      if(row){if(row.contribution_id!==contribution_id)throw new Error('nonce_conflict');return 'replay' as const;}
      this.db.query('INSERT INTO engine_nonces VALUES(?,?,?,?)').run(domain,p.submitter.hotkey_public_key,p.nonce,contribution_id);return 'received' as const;
    }).immediate();
  }
  close(){this.db.close();}
}
