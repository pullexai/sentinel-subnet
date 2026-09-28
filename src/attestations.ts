import { cryptoWaitReady,decodeAddress,encodeAddress,sr25519Verify } from '@polkadot/util-crypto';
import { sha256,type ContributionInbox } from './protocol';

export type ScoreTarget={genesis:string;netuid:number;round:string;cohortSha256:string;resultSha256:string};
export type QuorumPolicy={validators:string[];threshold:number} | {schema:'sentinel-quorum-policy/v2';validators:string[];threshold:number;maxFaultyValidators:number};
export type ScoreAttestation={schema:'sentinel-score-attestation/v1';target:ScoreTarget;policySha256:string;validator:string;signature:string};
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v && typeof v==='object' && !Array.isArray(v) && Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k));
const hex=(v:unknown):v is string=>typeof v==='string' && /^[a-f0-9]{64}$/.test(v);
function address(v:unknown):v is string{
  try{return typeof v==='string' && v.length===48 && encodeAddress(decodeAddress(v,false,42),42)===v;}catch{return false;}
}
function targetFields(v:unknown){
  if(!exact(v,['genesis','netuid','round','cohortSha256','resultSha256']) || !hex(v.genesis) || !hex(v.round) || !hex(v.cohortSha256) || !hex(v.resultSha256) ||
    typeof v.netuid!=='number' || !Number.isInteger(v.netuid) || v.netuid<0 || v.netuid>65535)throw new Error('Invalid score target');
  return [v.genesis,v.netuid,v.round,v.cohortSha256,v.resultSha256];
}
export function quorumPolicyDigest(value:unknown){
  if((!exact(value,['schema','validators','threshold','maxFaultyValidators']) && !exact(value,['validators','threshold'])) || !Array.isArray(value.validators) || value.validators.length<1 || value.validators.length>100 ||
    value.validators.some(v=>!address(v)) || new Set(value.validators).size!==value.validators.length ||
    typeof value.threshold!=='number' || !Number.isInteger(value.threshold) || value.threshold<1 || value.threshold>value.validators.length)throw new Error('Invalid explicit quorum policy');
  if(Object.hasOwn(value,'schema')){
    const n=value.validators.length,f=value.maxFaultyValidators,q=value.threshold;
    if(value.schema!=='sentinel-quorum-policy/v2' || typeof f!=='number' || !Number.isInteger(f) || f<0 || f>=n || q>n-f || 2*q<=n+f)
      throw new Error('Invalid quorum fault bound or honest intersection');
    return sha256(Buffer.from('sentinel/quorum-policy/v2\n'+JSON.stringify([[...value.validators].sort(),q,f])));
  }
  return sha256(Buffer.from('sentinel/quorum-policy/v1\n'+JSON.stringify([[...value.validators].sort(),value.threshold])));
}
// Sorted object keys; preserve array order because tiers and contribution order are meaningful.
export function canonical(value:unknown):string{
  if(value===null || typeof value==='boolean' || typeof value==='string')return JSON.stringify(value);
  if(typeof value==='number' && Number.isFinite(value))return JSON.stringify(value);
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value && typeof value==='object' && Object.getPrototypeOf(value)===Object.prototype)return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
  throw new Error('Non-JSON deterministic result');
}
// Use on a locally recomputed report, not as an assertion that received scores are correct.
export function scoreTarget(report:Awaited<ReturnType<ContributionInbox['evaluatePractice']>>):ScoreTarget{
  const result={schema:report.schema,comparisonId:report.comparisonId,generator:report.generator,seed:report.seed,pairs:report.pairs,cases:report.cases,
    tiers:report.tiers,results:report.results.map(r=>({digest:r.digest,participants:r.participants,comparison:r.comparison})),
    commitment:report.commitment,reveal:report.reveal,weights:report.weights,rewards:report.rewards};
  const {genesis,netuid,round}=report.authentication.scope;
  const target={genesis,netuid,round,cohortSha256:report.cohortSha256,resultSha256:sha256(Buffer.from('sentinel/deterministic-practice-score/v1\n'+canonical(result)))};
  targetFields(target);return target;
}
export function scoreAttestationPayload(target:ScoreTarget,policySha256:string,validator:string){
  if(!hex(policySha256) || !address(validator))throw new Error('Invalid score attestation identity');
  return Buffer.from('sentinel/score-attestation/sr25519/v1\n'+JSON.stringify([...targetFields(target),policySha256,validator]));
}
function verifyVote(value:unknown,policySha256:string,allowed:Set<string>):asserts value is ScoreAttestation{
  if(!exact(value,['schema','target','policySha256','validator','signature']) || value.schema!=='sentinel-score-attestation/v1' ||
    typeof value.validator!=='string' || !allowed.has(value.validator) || value.policySha256!==policySha256 ||
    typeof value.signature!=='string' || !/^[a-f0-9]{128}$/.test(value.signature))throw new Error('Untrusted score attestation');
  const payload=scoreAttestationPayload(value.target as ScoreTarget,policySha256,value.validator);
  if(!sr25519Verify(payload,Buffer.from(value.signature,'hex'),decodeAddress(value.validator,false,42)))throw new Error('Invalid score signature');
}
export async function verifyScoreAttestation(value:unknown,policy:QuorumPolicy){
  const policySha256=quorumPolicyDigest(policy),allowed=new Set(policy.validators),vote=structuredClone(value);
  await cryptoWaitReady();verifyVote(vote,policySha256,allowed);return vote;
}
export async function verifyScoreQuorum(values:unknown,expected:ScoreTarget,policy:QuorumPolicy){
  // Snapshot caller inputs before verifying so asynchronous mutation cannot change expectations.
  const fields=JSON.stringify(targetFields(expected)),target=structuredClone(expected);
  const policySha256=quorumPolicyDigest(policy),allowed=new Set(policy.validators),threshold=policy.threshold;
  const faultBound='schema' in policy?{maxFaultyValidators:policy.maxFaultyValidators}:null;
  if(!Array.isArray(values) || values.length>allowed.size)throw new Error('Invalid attestation set');
  const attestations=structuredClone(values);
  await cryptoWaitReady();
  const signers=new Set<string>();
  for(const value of attestations){
    verifyVote(value,policySha256,allowed);
    if(signers.has(value.validator) || JSON.stringify(targetFields(value.target))!==fields)throw new Error('Duplicate or conflicting score attestation');
    signers.add(value.validator);
  }
  if(signers.size<threshold)throw new Error('Insufficient score attestations');
  return {schema:faultBound?'sentinel-score-quorum/v2':'sentinel-score-quorum/v1',target,policySha256,threshold,...faultBound,signers:[...signers].sort(),weights:null,rewards:null};
}
