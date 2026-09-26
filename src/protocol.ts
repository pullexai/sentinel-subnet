import { Database } from 'bun:sqlite';
import { createHash,randomBytes } from 'node:crypto';
import { lstatSync,mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { cryptoWaitReady,decodeAddress,encodeAddress,sr25519Verify } from '@polkadot/util-crypto';
import { admit,type Submission } from './competition';

export type Challenge={schema:'sentinel-challenge/v1';genesis:string;netuid:number;round:string;validator:string;miner:string;nonce:string;issuedAt:number;expiresAt:number};
export type SignedChallenge={challenge:Challenge;signature:string};
export type Contribution={schema:'sentinel-contribution/v1';challenge:Challenge;artifactSha256:string;signature:string};
export type Scope={genesis:string;netuid:number;round:string;validator:string};
const hex=/^[a-f0-9]{64}$/;
const exact=(value:unknown,keys:string[]):value is Record<string,unknown>=>!!value && typeof value==='object' && !Array.isArray(value) && Object.keys(value).length===keys.length && keys.every(k=>Object.hasOwn(value,k));
export const sha256=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
function hotkey(value:unknown):value is string{
  try{return typeof value==='string' && value.length===48 && encodeAddress(decodeAddress(value,false,42),42)===value;}catch{return false;}
}
function scope(value:Scope){
  if(!hex.test(value.genesis) || !hex.test(value.round) || !Number.isInteger(value.netuid) || value.netuid<0 || value.netuid>65535 || !hotkey(value.validator))throw new Error('Invalid protocol scope');
}
function challenge(value:unknown):asserts value is Challenge{
  if(!exact(value,['schema','genesis','netuid','round','validator','miner','nonce','issuedAt','expiresAt']) || value.schema!=='sentinel-challenge/v1')throw new Error('Invalid challenge');
  const c=value as unknown as Challenge;scope(c);
  if(!hotkey(c.miner) || !hex.test(c.nonce) || !Number.isSafeInteger(c.issuedAt) || c.issuedAt<0 || !Number.isSafeInteger(c.expiresAt) || c.expiresAt<=c.issuedAt)throw new Error('Invalid challenge bounds');
}
function fields(c:Challenge){return [c.schema,c.genesis,c.netuid,c.round,c.validator,c.miner,c.nonce,c.issuedAt,c.expiresAt];}
export function challengePayload(c:Challenge){challenge(c);return Buffer.from('sentinel/challenge/sr25519/v1\n'+JSON.stringify(fields(c)));}
export function contributionPayload(c:Challenge,artifactSha256:string){
  challenge(c);if(!hex.test(artifactSha256))throw new Error('Invalid artifact digest');
  return Buffer.from('sentinel/contribution/sr25519/v1\n'+JSON.stringify([...fields(c),artifactSha256]));
}
function signature(message:Uint8Array,value:unknown,address:string){
  if(typeof value!=='string' || !/^[a-f0-9]{128}$/.test(value) || !sr25519Verify(message,Buffer.from(value,'hex'),decodeAddress(address,false,42)))throw new Error('Invalid sr25519 signature');
}
export async function verifyChallenge(value:unknown,expected:Scope,miner:string,now:number,maxLifetimeMs:number):Promise<Challenge>{
  await cryptoWaitReady();scope(expected);
  if(!exact(value,['challenge','signature']))throw new Error('Invalid signed challenge');
  challenge(value.challenge);const c=value.challenge;
  if(!Number.isSafeInteger(now) || !Number.isSafeInteger(maxLifetimeMs) || maxLifetimeMs<1 ||
    c.genesis!==expected.genesis || c.netuid!==expected.netuid || c.round!==expected.round || c.validator!==expected.validator || c.miner!==miner ||
    now<c.issuedAt || now>=c.expiresAt || c.expiresAt-c.issuedAt>maxLifetimeMs)throw new Error('Challenge scope or validity mismatch');
  signature(challengePayload(c),value.signature,c.validator);return c;
}

// Exact canonical JSON is the v1 artifact wire contract. No submitted code executes.
function artifact(bytes:Uint8Array):Submission{
  if(bytes.length>65536)throw new Error('Artifact limit exceeded');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=admit(JSON.parse(text));
  const canonical=JSON.stringify({schema:value.schema,rules:value.rules.map(r=>({id:r.id,literal:r.literal}))});
  if(text!==canonical)throw new Error('Noncanonical artifact');
  return JSON.parse(canonical);
}

export class ContributionInbox{
  private db:Database;
  private policy:Scope;
  private miners:Set<string>;
  constructor(directory:string,policy:Scope,miners:readonly string[],readonly lifetimeMs:number,private clock=Date.now){
    scope(policy);
    if(!Number.isSafeInteger(lifetimeMs) || lifetimeMs<1 || !miners.length || miners.some(m=>!hotkey(m)) || new Set(miners).size!==miners.length)throw new Error('Explicit eligible hotkeys and lifetime required');
    this.policy={...policy};this.miners=new Set(miners);
    mkdirSync(directory,{recursive:true,mode:0o700});
    const info=lstatSync(directory);
    if(!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077)throw new Error('Private inbox directory required');
    const path=join(directory,'inbox.sqlite');
    try{const info=lstatSync(path);if(!info.isFile() || info.isSymbolicLink() || info.nlink!==1)throw new Error('Unsafe inbox file');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
    this.db=new Database(path,{create:true,strict:true});
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS challenges(scope TEXT NOT NULL,miner TEXT NOT NULL,nonce TEXT NOT NULL UNIQUE,challenge TEXT NOT NULL,artifact TEXT,digest TEXT,signature TEXT,accepted_at INTEGER,PRIMARY KEY(scope,miner));`);
  }
  private scopeId(){return JSON.stringify([this.policy.genesis,this.policy.netuid,this.policy.round,this.policy.validator]);}
  issue(miner:string):Challenge{
    if(!this.miners.has(miner))throw new Error('Ineligible hotkey');
    return this.db.transaction(()=>{
      const existing=this.db.query('SELECT challenge FROM challenges WHERE scope=? AND miner=?').get(this.scopeId(),miner) as {challenge:string}|null;
      if(existing)return JSON.parse(existing.challenge);
      const issuedAt=this.clock();
      const c:Challenge={schema:'sentinel-challenge/v1',...this.policy,miner,nonce:randomBytes(32).toString('hex'),issuedAt,expiresAt:issuedAt+this.lifetimeMs};challenge(c);
      this.db.query('INSERT INTO challenges(scope,miner,nonce,challenge) VALUES(?,?,?,?)').run(this.scopeId(),miner,c.nonce,JSON.stringify(c));return c;
    }).immediate();
  }
  async accept(value:unknown,bytes:Uint8Array){
    await cryptoWaitReady();
    if(!(bytes instanceof Uint8Array) || bytes.length>65536)throw new Error('Artifact limit exceeded');
    if(!exact(value,['schema','challenge','artifactSha256','signature']) || value.schema!=='sentinel-contribution/v1')throw new Error('Invalid contribution');
    challenge(value.challenge);const c=value.challenge,digest=sha256(bytes);
    if(!this.miners.has(c.miner) || value.artifactSha256!==digest)throw new Error('Ineligible hotkey or artifact mismatch');
    const submission=artifact(bytes),payload=contributionPayload(c,digest);
    signature(payload,value.signature,c.miner);
    return this.db.transaction(()=>{
      const row=this.db.query('SELECT challenge,artifact FROM challenges WHERE scope=? AND miner=? AND nonce=?').get(this.scopeId(),c.miner,c.nonce) as {challenge:string;artifact:string|null}|null;
      const now=this.clock();
      if(!Number.isSafeInteger(now) || !row || !challengePayload(JSON.parse(row.challenge)).equals(challengePayload(c)) || now<c.issuedAt || now>=c.expiresAt)throw new Error('Unknown or expired challenge');
      if(row.artifact!==null)throw new Error('Contribution replay');
      this.db.query('UPDATE challenges SET artifact=?,digest=?,signature=?,accepted_at=? WHERE scope=? AND miner=?').run(JSON.stringify(submission),digest,value.signature as string,now,this.scopeId(),c.miner);
      return {hotkey:c.miner,artifactSha256:digest};
    }).immediate();
  }
  candidates(){
    const rows=this.db.query('SELECT miner,artifact FROM challenges WHERE scope=? AND artifact IS NOT NULL ORDER BY miner').all(this.scopeId()) as {miner:string;artifact:string}[];
    return rows.filter(row=>this.miners.has(row.miner)).map(row=>({participant:row.miner,submission:admit(JSON.parse(row.artifact))}));
  }
  async evaluatePractice(seed:string,pairs:number){
    const {evaluateCohort}=await import('./validator');
    const report=await evaluateCohort(seed,pairs,this.candidates());
    return {...report,authentication:{scheme:'sr25519',scope:{...this.policy},eligibility:'operator-supplied-hotkey-list'},
      limitation:'Signed public-template practice. Key possession verified; chain registration, validator independence and hidden generalization unqualified. No weights or rewards.'};
  }
  close(){this.db.close();}
}
