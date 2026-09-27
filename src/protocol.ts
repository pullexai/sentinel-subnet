import { Database } from 'bun:sqlite';
import { createHash,randomBytes } from 'node:crypto';
import { lstatSync,mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { cryptoWaitReady,decodeAddress,encodeAddress,sr25519Verify } from '@polkadot/util-crypto';
import { admit,executionIdentity,reference,type Submission } from './competition';
import { corpus } from './corpus';
import { verifyChainAdmission,chainCanonical,chainFresh,type ChainAdmission,type ChainPolicy,type ChainApproval } from './chain-admission';

export type Challenge={schema:'sentinel-challenge/v1';genesis:string;netuid:number;round:string;validator:string;miner:string;nonce:string;issuedAt:number;expiresAt:number};
export type SignedChallenge={challenge:Challenge;signature:string};
export type Contribution={schema:'sentinel-contribution/v1';challenge:Challenge;artifactSha256:string;signature:string};
export type Scope={genesis:string;netuid:number;round:string;validator:string};
type AdmissionProof={challengeSignature:string;acceptedAt:number;receiptSignature:string};
type FrozenPractice={schema:'sentinel-frozen-practice/v2'|'sentinel-frozen-practice/v3';chain?:ReturnType<typeof verifyChainAdmission>;scope:Scope;seed:string;pairs:number;generator:string;fixtureSha256:string;baseline:string;
  salt:string;contract:PracticeContract;scorer:string;eligible:string[];closedAt:number;contributions:{miner:string;challenge:Challenge;artifactSha256:string;signature:string;submission:Submission;admission:AdmissionProof}[]};
export type PracticeContract={schema:'sentinel-practice-contract/v1';commitment:string;pairs:number;generator:'sentinel-corpus/v1';baseline:string;scorer:'sentinel-pareto/v1'};
const hex=/^[a-f0-9]{64}$/;
const exact=(value:unknown,keys:string[]):value is Record<string,unknown>=>!!value && typeof value==='object' && !Array.isArray(value) && Object.keys(value).length===keys.length && keys.every(k=>Object.hasOwn(value,k));
export const sha256=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
export function practiceContract(seed:string,salt:string,pairs:number):PracticeContract{
  if(typeof seed!=='string' || typeof salt!=='string' || !hex.test(seed) || !hex.test(salt) || !Number.isSafeInteger(pairs) || pairs<1 || pairs>250)throw new Error('Invalid practice commitment inputs');
  return {schema:'sentinel-practice-contract/v1',commitment:sha256(Buffer.from('sentinel/practice-reveal/v1\n'+JSON.stringify([seed,salt,pairs]))),
    pairs,generator:'sentinel-corpus/v1',baseline:executionIdentity(reference),scorer:'sentinel-pareto/v1'};
}
export function practiceRound(value:unknown):string{
  if(!exact(value,['schema','commitment','pairs','generator','baseline','scorer']) || value.schema!=='sentinel-practice-contract/v1' ||
    typeof value.commitment!=='string' || !hex.test(value.commitment) || typeof value.pairs!=='number' || !Number.isSafeInteger(value.pairs) || value.pairs<1 || value.pairs>250 ||
    value.generator!=='sentinel-corpus/v1' || value.baseline!==executionIdentity(reference) || value.scorer!=='sentinel-pareto/v1')throw new Error('Invalid practice contract');
  return sha256(Buffer.from('sentinel/practice-contract/v1\n'+JSON.stringify([value.schema,value.commitment,value.pairs,value.generator,value.baseline,value.scorer])));
}
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
export function admissionPayload(c:Challenge,artifactSha256:string,minerSignature:string,acceptedAt:number){
  challenge(c);
  if(typeof artifactSha256!=='string' || !hex.test(artifactSha256) || !/^[a-f0-9]{128}$/.test(minerSignature) ||
    !Number.isSafeInteger(acceptedAt) || acceptedAt<c.issuedAt || acceptedAt>=c.expiresAt)throw new Error('Invalid admission receipt');
  return Buffer.from('sentinel/admission/sr25519/v1\n'+JSON.stringify([...fields(c),artifactSha256,minerSignature,acceptedAt]));
}
function signature(message:Uint8Array,value:unknown,address:string){
  try{if(typeof value==='string' && /^[a-f0-9]{128}$/.test(value) && sr25519Verify(message,Buffer.from(value,'hex'),decodeAddress(address,false,42)))return;}catch{}
  throw new Error('Invalid sr25519 signature');
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

export type SnapshotExpectation={cohortSha256:string;scope:Scope;eligible:string[];chain?:{policy:ChainPolicy;approval:ChainApproval}};
export const snapshotByteLimit=8*1024*1024; // Wire ceiling, not a deployment capacity objective.
export async function evaluateSnapshot(bytes:Uint8Array,expected:SnapshotExpectation){
  if(!(bytes instanceof Uint8Array) || bytes.length>snapshotByteLimit)throw new Error('Snapshot byte limit');
  if(!exact(expected,['cohortSha256','scope','eligible',...(Object.hasOwn(expected,'chain')?['chain']:[])]) || typeof expected.cohortSha256!=='string' || !hex.test(expected.cohortSha256) ||
    !exact(expected.scope,['genesis','netuid','round','validator']) || !Array.isArray(expected.eligible) || expected.eligible.length<1 || expected.eligible.length>10000 ||
    expected.eligible.some(v=>!hotkey(v)) || new Set(expected.eligible).size!==expected.eligible.length)throw new Error('Invalid snapshot expectations');
  scope(expected.scope);
  const expectations=structuredClone(expected),input=Buffer.from(bytes);
  if(sha256(input)!==expectations.cohortSha256)throw new Error('Snapshot digest mismatch');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(input),value=JSON.parse(text);
  if(JSON.stringify(value)!==text || !exact(value,['schema','scope','seed','pairs','salt','contract','generator','fixtureSha256','baseline','scorer','eligible','closedAt','contributions',...(expectations.chain?['chain']:[])]))throw new Error('Invalid snapshot schema or noncanonical JSON');
  const f=value as unknown as FrozenPractice;
  if(f.schema!==(expectations.chain?'sentinel-frozen-practice/v3':'sentinel-frozen-practice/v2') || !exact(f.scope,['genesis','netuid','round','validator']) ||
    ['genesis','netuid','round','validator'].some(k=>f.scope[k as keyof Scope]!==expectations.scope[k as keyof Scope]) ||
    !Array.isArray(f.eligible) || JSON.stringify(f.eligible)!==JSON.stringify([...expectations.eligible].sort()) ||
    !Number.isSafeInteger(f.closedAt) || f.closedAt<0 || !Array.isArray(f.contributions) || f.contributions.length<1 || f.contributions.length>100)throw new Error('Snapshot scope or cohort mismatch');
  if(practiceRound(f.contract)!==f.scope.round || practiceRound(practiceContract(f.seed,f.salt,f.pairs))!==f.scope.round ||
    f.generator!=='sentinel-corpus/v1' || f.scorer!=='sentinel-pareto/v1' || f.baseline!==executionIdentity(reference) ||
    f.fixtureSha256!==sha256(Buffer.from(JSON.stringify(corpus(f.seed,f.pairs)))))throw new Error('Snapshot benchmark mismatch');
  if(expectations.chain){
    if(!exact(expectations.chain,['policy','approval']) || !exact(f.chain,['policy','approval','observation']) || typeof f.chain!.observation!=='string' ||
      chainCanonical(f.chain!.policy)!==chainCanonical(expectations.chain.policy) || chainCanonical(f.chain!.approval)!==chainCanonical(expectations.chain.approval) ||
      chainCanonical(expectations.chain.policy.scope)!==chainCanonical(expectations.scope) ||
      chainCanonical([...expectations.chain.policy.eligible].sort())!==chainCanonical([...expectations.eligible].sort()))throw new Error('Chain replay expectations mismatch');
    verifyChainAdmission({bytes:Buffer.from(f.chain!.observation),...expectations.chain},f.closedAt);
  }
  await cryptoWaitReady();
  const miners=new Set<string>(),nonces=new Set<string>();
  for(const contribution of f.contributions){
    if(!exact(contribution,['miner','challenge','artifactSha256','signature','submission','admission']))throw new Error('Invalid snapshot contribution');
    const c=contribution.challenge;challenge(c);
    if(!expectations.eligible.includes(c.miner) || contribution.miner!==c.miner || miners.has(c.miner) || nonces.has(c.nonce) || c.issuedAt>f.closedAt ||
      ['genesis','netuid','round','validator'].some(k=>c[k as keyof Scope]!==expectations.scope[k as keyof Scope]))throw new Error('Snapshot contribution scope mismatch');
    const artifactBytes=Buffer.from(JSON.stringify(contribution.submission));artifact(artifactBytes);
    if(sha256(artifactBytes)!==contribution.artifactSha256)throw new Error('Snapshot artifact mismatch');
    signature(contributionPayload(c,contribution.artifactSha256 as string),contribution.signature,c.miner);
    const proof=contribution.admission;
    if(!exact(proof,['challengeSignature','acceptedAt','receiptSignature']) || typeof proof.acceptedAt!=='number' || proof.acceptedAt>f.closedAt)throw new Error('Invalid snapshot admission');
    if(expectations.chain){chainFresh(expectations.chain.approval,c.issuedAt);chainFresh(expectations.chain.approval,proof.acceptedAt);}
    signature(challengePayload(c),proof.challengeSignature,c.validator);
    signature(admissionPayload(c,contribution.artifactSha256 as string,contribution.signature as string,proof.acceptedAt),proof.receiptSignature,c.validator);
    miners.add(c.miner);nonces.add(c.nonce);
  }
  const {evaluateCohort}=await import('./validator');
  const report=await evaluateCohort(f.seed,f.pairs,f.contributions.map(c=>({participant:c.miner,submission:c.submission})));
  return {...report,cohortSha256:expectations.cohortSha256,closedAt:f.closedAt,commitment:f.contract,reveal:{seed:f.seed,salt:f.salt},
    authentication:{scheme:'sr25519',scope:expectations.scope,eligibility:expectations.chain?'operator-approved-rpc-observed-registration':'legacy-operator-supplied-hotkey-list',...(expectations.chain?{chain:expectations.chain,evidenceUse:'historical-replay',currentEligibility:'not-assessed',revocationStatus:'not-assessed'}: {})},
    limitation:'Signed public-template practice. Chain evidence, when required, is operator-approved RPC observation, not independent finality or economic eligibility. Validator independence and hidden generalization unqualified. No weights or rewards.'};
}

export class ContributionInbox{
  private db:Database;
  private policy:Scope;
  private miners:Set<string>;
  private chain?:ReturnType<typeof verifyChainAdmission>;
  static chainQualified(directory:string,input:ChainAdmission,lifetimeMs:number,clock=Date.now){
    return new ContributionInbox(directory,input.policy.scope,input.policy.eligible,lifetimeMs,clock,input);
  }
  // Without chain input this is explicitly legacy, operator-list-only practice.
  constructor(directory:string,policy:Scope,miners:readonly string[],readonly lifetimeMs:number,private clock=Date.now,chainInput?:ChainAdmission){
    scope(policy);
    if(chainInput){
      // Existing bindings may reopen for historical export or local revocation after expiry.
      this.chain=verifyChainAdmission(chainInput,chainInput.approval.observedAt);
      if(chainCanonical(policy)!==chainCanonical(this.chain.policy.scope) || chainCanonical(miners)!==chainCanonical(this.chain.policy.eligible))throw new Error('Chain scope mismatch');
    }
    if(!Number.isSafeInteger(lifetimeMs) || lifetimeMs<1 || !miners.length || miners.length>10000 || miners.some(m=>!hotkey(m)) || new Set(miners).size!==miners.length)throw new Error('Explicit eligible hotkeys and lifetime required');
    this.policy={genesis:policy.genesis,netuid:policy.netuid,round:policy.round,validator:policy.validator};this.miners=new Set(miners);
    mkdirSync(directory,{recursive:true,mode:0o700});
    const info=lstatSync(directory);
    if(!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077)throw new Error('Private inbox directory required');
    const path=join(directory,'inbox.sqlite');
    try{const info=lstatSync(path);if(!info.isFile() || info.isSymbolicLink() || info.nlink!==1)throw new Error('Unsafe inbox file');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
    this.db=new Database(path,{create:true,strict:true});
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS challenges(scope TEXT NOT NULL,miner TEXT NOT NULL,nonce TEXT NOT NULL UNIQUE,challenge TEXT NOT NULL,artifact TEXT,digest TEXT,signature TEXT,accepted_at INTEGER,PRIMARY KEY(scope,miner));
      CREATE TABLE IF NOT EXISTS frozen_practice(scope TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS practice_contracts(scope TEXT PRIMARY KEY,body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS admission_proofs(scope TEXT NOT NULL,miner TEXT NOT NULL,proof TEXT NOT NULL,PRIMARY KEY(scope,miner));
      CREATE TABLE IF NOT EXISTS chain_bindings(scope TEXT PRIMARY KEY,body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS chain_revocations(scope TEXT PRIMARY KEY,revoked_at INTEGER NOT NULL);`);
    try{this.db.transaction(()=>{
      const row=this.db.query('SELECT body FROM chain_bindings WHERE scope=?').get(this.scopeId()) as {body:string}|null;
      if(row){if(!this.chain || row.body!==chainCanonical(this.chain))throw new Error('Persisted chain binding mismatch');}
      else if(this.chain){
        chainFresh(this.chain.approval,this.clock());
        if(this.db.query('SELECT 1 FROM practice_contracts WHERE scope=? UNION ALL SELECT 1 FROM challenges WHERE scope=? UNION ALL SELECT 1 FROM frozen_practice WHERE scope=?').get(this.scopeId(),this.scopeId(),this.scopeId()))throw new Error('Cannot qualify existing legacy round');
        this.db.query('INSERT INTO chain_bindings(scope,body) VALUES(?,?)').run(this.scopeId(),chainCanonical(this.chain));
      }
    }).immediate();}catch(error){this.db.close();throw error;}
  }
  private scopeId(){return JSON.stringify([this.policy.genesis,this.policy.netuid,this.policy.round,this.policy.validator]);}
  private ensureChain(active=true){
    const row=this.db.query('SELECT body FROM chain_bindings WHERE scope=?').get(this.scopeId()) as {body:string}|null;
    if((row?.body ?? null)!==(this.chain?chainCanonical(this.chain):null))throw new Error('Persisted chain binding mismatch');
    if(this.chain && active){
      if(this.db.query('SELECT 1 FROM chain_revocations WHERE scope=?').get(this.scopeId()))throw new Error('Chain approval revoked');
      chainFresh(this.chain.approval,this.clock());
    }
  }
  // ponytail: revocation is permanent for this scope; refresh requires a new round.
  revokeChainApproval(){
    return this.db.transaction(()=>{
      this.ensureChain(false);
      if(!this.chain)throw new Error('Chain approval required for revocation');
      const existing=this.db.query('SELECT revoked_at FROM chain_revocations WHERE scope=?').get(this.scopeId()) as {revoked_at:number}|null;
      if(existing)return {revokedAt:existing.revoked_at};
      const revokedAt=this.clock();
      if(!Number.isSafeInteger(revokedAt) || revokedAt<0)throw new Error('Invalid revocation time');
      this.db.query('INSERT INTO chain_revocations(scope,revoked_at) VALUES(?,?)').run(this.scopeId(),revokedAt);
      return {revokedAt};
    }).immediate();
  }
  private ensureOpen(){this.ensureChain();if(this.db.query('SELECT 1 FROM frozen_practice WHERE scope=?').get(this.scopeId()))throw new Error('Practice cohort closed');}
  registerPractice(contract:PracticeContract){
    if(practiceRound(contract)!==this.policy.round)throw new Error('Practice round commitment mismatch');
    return this.db.transaction(()=>{
      this.ensureChain();
      const existing=this.db.query('SELECT body FROM practice_contracts WHERE scope=?').get(this.scopeId()) as {body:string}|null;
      if(existing){if(practiceRound(JSON.parse(existing.body))!==this.policy.round)throw new Error('Stored practice contract mismatch');return this.policy.round;}
      if(this.db.query('SELECT 1 FROM challenges WHERE scope=?').get(this.scopeId()) || this.db.query('SELECT 1 FROM frozen_practice WHERE scope=?').get(this.scopeId()))throw new Error('Cannot retroactively commit practice');
      this.db.query('INSERT INTO practice_contracts(scope,body) VALUES(?,?)').run(this.scopeId(),JSON.stringify(contract));return this.policy.round;
    }).immediate();
  }
  private committedPractice(active=true){
    this.ensureChain(active);
    const row=this.db.query('SELECT body FROM practice_contracts WHERE scope=?').get(this.scopeId()) as {body:string}|null;
    if(!row)throw new Error('Commit practice before admission');
    const contract=JSON.parse(row.body) as PracticeContract;
    if(practiceRound(contract)!==this.policy.round)throw new Error('Stored practice contract mismatch');
    return contract;
  }
  issue(miner:string):Challenge{
    if(!this.miners.has(miner))throw new Error('Ineligible hotkey');
    return this.db.transaction(()=>{
      this.ensureOpen();
      this.committedPractice();
      const existing=this.db.query('SELECT challenge FROM challenges WHERE scope=? AND miner=?').get(this.scopeId(),miner) as {challenge:string}|null;
      if(existing)return JSON.parse(existing.challenge);
      const issuedAt=this.clock();
      if(this.chain)chainFresh(this.chain.approval,issuedAt);
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
      this.ensureOpen();
      this.committedPractice();
      const row=this.db.query('SELECT challenge,artifact FROM challenges WHERE scope=? AND miner=? AND nonce=?').get(this.scopeId(),c.miner,c.nonce) as {challenge:string;artifact:string|null}|null;
      const now=this.clock();
      if(this.chain)chainFresh(this.chain.approval,now);
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
  async attestAdmission(signed:SignedChallenge,sign:(payload:Uint8Array)=>Promise<string>){
    const value=structuredClone(signed);
    await cryptoWaitReady();
    if(!exact(value,['challenge','signature']))throw new Error('Invalid signed challenge');
    const c=value.challenge;challenge(c);signature(challengePayload(c),value.signature,c.validator);
    this.ensureOpen();this.committedPractice();
    if(!this.miners.has(c.miner))throw new Error('Ineligible hotkey');
    const row=this.db.query('SELECT challenge,digest,signature,accepted_at FROM challenges WHERE scope=? AND miner=? AND artifact IS NOT NULL').get(this.scopeId(),c.miner) as {challenge:string;digest:string;signature:string;accepted_at:number}|null;
    if(!row || !challengePayload(JSON.parse(row.challenge)).equals(challengePayload(c)))throw new Error('Unknown admitted contribution');
    const existing=this.db.query('SELECT proof FROM admission_proofs WHERE scope=? AND miner=?').get(this.scopeId(),c.miner) as {proof:string}|null;
    if(existing)return JSON.parse(existing.proof) as AdmissionProof;
    const payload=admissionPayload(c,row.digest,row.signature,row.accepted_at);
    const receiptSignature=await sign(payload);
    // Signers may mutate their input buffer; verify freshly reconstructed bytes.
    signature(admissionPayload(c,row.digest,row.signature,row.accepted_at),receiptSignature,c.validator);
    return this.db.transaction(()=>{
      this.ensureOpen();this.committedPractice();
      const current=this.db.query('SELECT challenge,digest,signature,accepted_at FROM challenges WHERE scope=? AND miner=? AND artifact IS NOT NULL').get(this.scopeId(),c.miner);
      if(JSON.stringify(current)!==JSON.stringify(row))throw new Error('Admission changed while signing');
      const proof:AdmissionProof={challengeSignature:value.signature,acceptedAt:row.accepted_at,receiptSignature};
      this.db.query('INSERT OR IGNORE INTO admission_proofs(scope,miner,proof) VALUES(?,?,?)').run(this.scopeId(),c.miner,JSON.stringify(proof));
      return JSON.parse((this.db.query('SELECT proof FROM admission_proofs WHERE scope=? AND miner=?').get(this.scopeId(),c.miner) as {proof:string}).proof) as AdmissionProof;
    }).immediate();
  }
  closePractice(seed:string,pairs:number,salt:string){
    const revealed=practiceContract(seed,salt,pairs);
    const fixtureSha256=sha256(Buffer.from(JSON.stringify(corpus(seed,pairs))));
    return this.db.transaction(()=>{
      this.committedPractice();
      if(practiceRound(revealed)!==this.policy.round)throw new Error('Practice reveal conflict');
      const stored=this.db.query('SELECT body,digest FROM frozen_practice WHERE scope=?').get(this.scopeId()) as {body:string;digest:string}|null;
      if(stored){
        const frozen=this.readFrozen();
        if(frozen.seed!==seed || frozen.pairs!==pairs || frozen.fixtureSha256!==fixtureSha256)throw new Error('Frozen practice contract conflict');
        return {cohortSha256:stored.digest,participants:frozen.contributions.length,closedAt:frozen.closedAt};
      }
      const rows=this.db.query('SELECT miner,challenge,artifact,digest,signature FROM challenges WHERE scope=? AND artifact IS NOT NULL ORDER BY miner').all(this.scopeId()) as {miner:string;challenge:string;artifact:string;digest:string;signature:string}[];
      const contributions=rows.filter(row=>this.miners.has(row.miner)).map(row=>{
        const proof=this.db.query('SELECT proof FROM admission_proofs WHERE scope=? AND miner=?').get(this.scopeId(),row.miner) as {proof:string}|null;
        if(!proof)throw new Error('Admission receipt required before closure');
        return {miner:row.miner,challenge:JSON.parse(row.challenge),artifactSha256:row.digest,signature:row.signature,submission:artifact(Buffer.from(row.artifact)),admission:JSON.parse(proof.proof) as AdmissionProof};
      });
      if(contributions.length<1 || contributions.length>100)throw new Error('Frozen practice requires 1–100 admitted miners');
      const closedAt=this.clock();if(!Number.isSafeInteger(closedAt) || closedAt<0)throw new Error('Invalid closure time');
      if(this.chain)chainFresh(this.chain.approval,closedAt);
      if(contributions.some(c=>c.admission.acceptedAt>closedAt))throw new Error('Closure precedes admission');
      const frozen:FrozenPractice={schema:this.chain?'sentinel-frozen-practice/v3':'sentinel-frozen-practice/v2',...(this.chain?{chain:this.chain}:{}),scope:{...this.policy},seed,pairs,salt,contract:revealed,generator:'sentinel-corpus/v1',fixtureSha256,
        baseline:executionIdentity(reference),scorer:'sentinel-pareto/v1',eligible:[...this.miners].sort(),closedAt,contributions};
      const body=JSON.stringify(frozen),digest=sha256(Buffer.from(body));
      if(Buffer.byteLength(body)>snapshotByteLimit)throw new Error('Snapshot byte limit');
      this.db.query('INSERT INTO frozen_practice(scope,body,digest) VALUES(?,?,?)').run(this.scopeId(),body,digest);
      return {cohortSha256:digest,participants:contributions.length,closedAt};
    }).immediate();
  }
  private readFrozen():FrozenPractice{
    const stored=this.db.query('SELECT body,digest FROM frozen_practice WHERE scope=?').get(this.scopeId()) as {body:string;digest:string}|null;
    if(!stored)throw new Error('Close practice cohort before evaluation');
    if(sha256(Buffer.from(stored.body))!==stored.digest)throw new Error('Frozen practice integrity failure');
    const frozen=JSON.parse(stored.body) as FrozenPractice;
    this.committedPractice(false);
    if(practiceRound(frozen.contract)!==this.policy.round || practiceRound(practiceContract(frozen.seed,frozen.salt,frozen.pairs))!==this.policy.round)throw new Error('Frozen practice commitment mismatch');
    if(JSON.stringify(frozen.eligible)!==JSON.stringify([...this.miners].sort()))throw new Error('Frozen practice eligibility conflict');
    if(frozen.schema!==(this.chain?'sentinel-frozen-practice/v3':'sentinel-frozen-practice/v2') || chainCanonical(frozen.chain??null)!==chainCanonical(this.chain??null) || JSON.stringify(frozen.scope)!==JSON.stringify(this.policy) ||
      frozen.generator!=='sentinel-corpus/v1' || frozen.scorer!=='sentinel-pareto/v1' || frozen.baseline!==executionIdentity(reference) ||
      frozen.fixtureSha256!==sha256(Buffer.from(JSON.stringify(corpus(frozen.seed,frozen.pairs)))))throw new Error('Frozen practice implementation mismatch');
    return frozen;
  }
  exportPractice(){
    const bytes=Buffer.from(JSON.stringify(this.readFrozen()));
    if(bytes.length>snapshotByteLimit)throw new Error('Snapshot byte limit');
    return bytes;
  }
  async evaluatePractice(){
    const bytes=this.exportPractice();
    return evaluateSnapshot(bytes,{cohortSha256:sha256(bytes),scope:{...this.policy},eligible:[...this.miners],...(this.chain?{chain:{policy:this.chain.policy,approval:this.chain.approval}}:{})});
  }
  close(){this.db.close();}
}
