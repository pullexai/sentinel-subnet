import { createHash } from 'node:crypto';
import { decodeAddress,encodeAddress } from '@polkadot/util-crypto';
import type { Scope } from './protocol';

export type ChainPolicy={scope:Scope;eligible:string[];creationHeight:number;creationHash:string;owner:string;ownerHotkey:string;runtime:number;metadataSha256:string};
export type ChainApproval={snapshotSha256:string;policySha256:string;observedAt:number;maxAgeMs:number;finalizedHeight:number;finalizedHash:string};
export type ChainAdmission={bytes:Uint8Array;policy:ChainPolicy;approval:ChainApproval};
const hex=(v:unknown):v is string=>typeof v==='string' && /^[a-f0-9]{64}$/.test(v);
const integer=(v:unknown):v is number=>Number.isSafeInteger(v) && (v as number)>=0;
const address=(v:unknown):v is string=>{try{return typeof v==='string' && v.length===48 && encodeAddress(decodeAddress(v,false,42),42)===v;}catch{return false;}};
const exact=(v:any,keys:string[])=>v && typeof v==='object' && !Array.isArray(v) && Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k));
export function chainCanonical(v:any):string{return JSON.stringify(v && typeof v==='object'?Array.isArray(v)?v.map(x=>JSON.parse(chainCanonical(x))):Object.fromEntries(Object.keys(v).sort().map(k=>[k,JSON.parse(chainCanonical(v[k]))])):v);}
export const chainDigest=(v:unknown)=>createHash('sha256').update(chainCanonical(v)).digest('hex');
export function chainFresh(approval:ChainApproval,now:number){
  if(!integer(now) || now<approval.observedAt || now-approval.observedAt>=approval.maxAgeMs)throw new Error('Chain approval expired or future-dated');
}
// Approval is private operator input, never derived from the received envelope.
export function verifyChainAdmission(input:ChainAdmission,now:number){
  const p=structuredClone(input.policy),a=structuredClone(input.approval);
  if(!exact(p,['scope','eligible','creationHeight','creationHash','owner','ownerHotkey','runtime','metadataSha256']) ||
    !exact(p.scope,['genesis','netuid','round','validator']) || !hex(p.scope.genesis) || !hex(p.scope.round) ||
    !integer(p.scope.netuid) || p.scope.netuid>65535 || !address(p.scope.validator) ||
    !Array.isArray(p.eligible) || p.eligible.length<1 || p.eligible.length>100 || p.eligible.some(x=>!address(x)) || new Set(p.eligible).size!==p.eligible.length ||
    !integer(p.creationHeight) || !hex(p.creationHash) || !address(p.owner) || !address(p.ownerHotkey) || !integer(p.runtime) || !hex(p.metadataSha256))throw new Error('Invalid chain policy');
  if(!exact(a,['snapshotSha256','policySha256','observedAt','maxAgeMs','finalizedHeight','finalizedHash']) || !hex(a.snapshotSha256) || !hex(a.policySha256) ||
    !integer(a.observedAt) || !integer(a.maxAgeMs) || a.maxAgeMs<1 || !integer(a.finalizedHeight) || !hex(a.finalizedHash) || chainDigest(p)!==a.policySha256)throw new Error('Invalid chain approval');
  chainFresh(a,now);
  if(!(input.bytes instanceof Uint8Array) || input.bytes.length>131072)throw new Error('Chain snapshot byte limit');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(input.bytes),envelope=JSON.parse(text);
  if(!exact(envelope,['sha256','observation']) || (text!==chainCanonical(envelope) && text!==chainCanonical(envelope)+'\n'))throw new Error('Noncanonical chain envelope');
  const o=envelope.observation;
  if(chainDigest(o)!==a.snapshotSha256 || envelope.sha256!==a.snapshotSha256)throw new Error('Unapproved chain snapshot');
  if(!exact(o,['schema','genesis','netuid','finalizedHeight','finalizedHash','creationHeight','creationHash','owner','ownerHotkey','runtime','metadataSha256','validator','members','limitation']) ||
    o.schema!=='sentinel-chain-observation/v1' || o.genesis!==p.scope.genesis || o.netuid!==p.scope.netuid || o.validator!==p.scope.validator ||
    o.finalizedHeight!==a.finalizedHeight || o.finalizedHash!==a.finalizedHash || p.creationHeight>o.finalizedHeight ||
    (['creationHeight','creationHash','owner','ownerHotkey','runtime','metadataSha256'] as const).some(k=>o[k]!==p[k]) ||
    typeof o.limitation!=='string' || !Array.isArray(o.members) || o.members.length<1 || o.members.length>100)throw new Error('Chain identity mismatch');
  const keys=new Set<string>(),uids=new Set<number>();
  for(const m of o.members){
    if(!exact(m,['hotkey','uid','owner','registrationHeight','registrationHash','validatorPermit']) || !address(m.hotkey) || !address(m.owner) ||
      !integer(m.uid) || m.uid>65535 || keys.has(m.hotkey) || uids.has(m.uid) || !integer(m.registrationHeight) ||
      m.registrationHeight<p.creationHeight || m.registrationHeight>o.finalizedHeight || !hex(m.registrationHash) || typeof m.validatorPermit!=='boolean')throw new Error('Invalid observed registration');
    keys.add(m.hotkey);uids.add(m.uid);
  }
  if(p.eligible.some(k=>!keys.has(k)) || !o.members.some((m:any)=>m.hotkey===p.scope.validator && m.validatorPermit))throw new Error('Approved participants not observed');
  return {policy:p,approval:a,observation:text};
}
