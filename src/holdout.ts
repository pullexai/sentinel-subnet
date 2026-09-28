import {cryptoWaitReady,decodeAddress,encodeAddress,sr25519Verify} from '@polkadot/util-crypto';
import {canonical} from './attestations';
import {compare,executionIdentity,mine,type Finding} from './competition';
import {corpus,families,proveFixture,type Fixture} from './corpus';
import {parseInput} from './miner';
import {evaluateSnapshot,sha256,snapshotByteLimit,validateSnapshot,type SnapshotExpectation} from './protocol';
import {paretoTiers} from './validator';

// Sealed holdout lane: an independent holdout owner commits a salted bank before intake;
// validators open it only after cohort closure and rank on it. No weights or rewards.
export type HoldoutCase={input:Fixture['input'];family:string;lineage:string;buggy:boolean;defectPath:string;fixedFiles:Record<string,string>;oracle:Fixture['oracle']};
export type HoldoutBank={schema:'sentinel-holdout-bank/v1';salt:string;cases:HoldoutCase[]};
export type HoldoutCommitment={schema:'sentinel-holdout-commitment/v1';round:string;owner:string;bankSha256:string;cases:number;committedAt:number;signature:string};
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v && typeof v==='object' && !Array.isArray(v) && Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k));
const hex=(v:unknown):v is string=>typeof v==='string' && /^[a-f0-9]{64}$/.test(v);
const label=/^[a-z][a-z0-9-]{1,59}$/,flat=/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$/;
export const holdoutByteLimit=snapshotByteLimit;
function address(v:unknown):v is string{
  try{return typeof v==='string' && v.length===48 && encodeAddress(decodeAddress(v,false,42),42)===v;}catch{return false;}
}
export function parseHoldoutJSON(bytes:Uint8Array){
  if(!(bytes instanceof Uint8Array) || bytes.length>holdoutByteLimit)throw new Error('Holdout byte limit');
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes),value=JSON.parse(text);
  if(JSON.stringify(value)!==text)throw new Error('Compact unambiguous JSON required');return value;
}
export const holdoutBankDigest=(bank:HoldoutBank)=>sha256(Buffer.from('sentinel/holdout-bank/v1\n'+canonical(bank)));
export function holdoutCommitmentPayload(c:Omit<HoldoutCommitment,'signature'>){
  if(!exact(c,['schema','round','owner','bankSha256','cases','committedAt']) || c.schema!=='sentinel-holdout-commitment/v1' || !hex(c.round) || !address(c.owner) ||
    !hex(c.bankSha256) || !Number.isSafeInteger(c.cases) || c.cases<2 || c.cases>1000 || !Number.isSafeInteger(c.committedAt) || c.committedAt<0)throw new Error('Invalid holdout commitment');
  return Buffer.from('sentinel/holdout-commitment/v1\n'+canonical(c));
}
// Miner and validator both call this: the bank must be committed by the trusted owner for this round.
export async function verifyHoldoutCommitment(value:unknown,round:string,owner:string):Promise<HoldoutCommitment>{
  value=structuredClone(value);
  if(!exact(value,['schema','round','owner','bankSha256','cases','committedAt','signature']))throw new Error('Invalid holdout commitment');
  const {signature,...payload}=value as HoldoutCommitment,bytes=holdoutCommitmentPayload(payload);
  if(payload.round!==round || payload.owner!==owner)throw new Error('Holdout commitment scope mismatch');
  await cryptoWaitReady();let valid=false;
  try{valid=typeof signature==='string' && /^[a-f0-9]{128}$/.test(signature) && sr25519Verify(bytes,Buffer.from(signature,'hex'),decodeAddress(owner,false,42));}catch{}
  if(!valid)throw new Error('Invalid holdout commitment signature');
  return value as HoldoutCommitment;
}
export function admitHoldoutBank(value:unknown,commitment:HoldoutCommitment,publicFixtures:Fixture[]):HoldoutBank{
  if(!exact(value,['schema','salt','cases']) || value.schema!=='sentinel-holdout-bank/v1' || !hex(value.salt) || !Array.isArray(value.cases))throw new Error('Invalid holdout bank');
  const bank=value as HoldoutBank;
  if(bank.cases.length!==commitment.cases || holdoutBankDigest(bank)!==commitment.bankSha256)throw new Error('Holdout opening does not match commitment');
  const publicTexts=new Set(publicFixtures.flatMap(f=>[...Object.values(f.input.files),...Object.values(f.fixedFiles)]));
  const publicIds=new Set(publicFixtures.map(f=>f.input.id)),ids=new Set<string>(),lineageFamily=new Map<string,string>(),polarity=new Map<string,Set<boolean>>();
  for(const c of bank.cases){
    if(!exact(c,['input','family','lineage','buggy','defectPath','fixedFiles','oracle']) || typeof c.family!=='string' || !label.test(c.family) || typeof c.lineage!=='string' || !label.test(c.lineage) ||
      typeof c.buggy!=='boolean' || !exact(c.oracle,['entry','expression','expected']) || typeof c.oracle.expression!=='string' || c.oracle.expression.length>1000 || !c.fixedFiles || typeof c.fixedFiles!=='object')throw new Error('Invalid holdout case');
    parseInput(c.input);
    const paths=Object.keys(c.input.files);
    if(paths.some(p=>!flat.test(p)) || canonical(Object.keys(c.fixedFiles).sort())!==canonical([...paths].sort()) || Object.values(c.fixedFiles).some(t=>typeof t!=='string' || !t.isWellFormed()) ||
      !paths.includes(c.defectPath) || !paths.includes(c.oracle.entry as string))throw new Error('Invalid holdout case files');
    // Independent lineage: no public template family, case identity or file bytes may reappear.
    if((families as readonly string[]).includes(c.family))throw new Error('Holdout family overlaps public templates');
    if(publicIds.has(c.input.id) || ids.has(c.input.id))throw new Error('Duplicate or public holdout case');
    if([...Object.values(c.input.files),...Object.values(c.fixedFiles)].some(t=>publicTexts.has(t)))throw new Error('Holdout file leaks public template bytes');
    if((lineageFamily.get(c.lineage) ?? c.family)!==c.family)throw new Error('Holdout lineage spans families');
    ids.add(c.input.id);lineageFamily.set(c.lineage,c.family);
    polarity.set(c.family,(polarity.get(c.family) ?? new Set()).add(c.buggy));
  }
  if([...polarity.values()].some(s=>s.size!==2))throw new Error('Every holdout family requires defective and clean cases');
  return bank;
}
export type HoldoutExpectation={snapshot:SnapshotExpectation;owner:string};
export async function evaluateHoldout(snapshotBytes:Uint8Array,expected:HoldoutExpectation,commitmentValue:unknown,bankBytes:Uint8Array){
  expected=structuredClone(expected);snapshotBytes=Buffer.from(snapshotBytes);bankBytes=Buffer.from(bankBytes);
  if(!exact(expected,['snapshot','owner']) || !address(expected.owner))throw new Error('Invalid holdout expectation');
  const {f,baseline}=await validateSnapshot(snapshotBytes,expected.snapshot);
  const commitment=await verifyHoldoutCommitment(commitmentValue,f.scope.round,expected.owner);
  // Commitment must predate every admitted challenge: no artifact was issued a challenge after seeing its digest.
  // ponytail: owner clock statement vs coordinator-signed issuedAt; add witnessed pre-intake publication before network use.
  if(f.contributions.some(c=>commitment.committedAt>=c.challenge.issuedAt))throw new Error('Holdout committed after intake opened');
  const bank=admitHoldoutBank(parseHoldoutJSON(bankBytes),commitment,corpus(f.seed,f.pairs));
  const fixtures=structuredClone(bank.cases) as unknown as Fixture[];
  for(const fixture of fixtures)await proveFixture(fixture);
  const publicReport=await evaluateSnapshot(snapshotBytes,expected.snapshot);
  // Miner code sees only `input`; gold, lineage, family and oracle never reach `mine`.
  const run=(submission:Parameters<typeof mine>[1])=>new Map<string,Finding[]>(fixtures.map(x=>[x.input.id,mine(structuredClone(x.input),submission)]));
  const baselineOutputs=run(baseline),groups=new Map<string,{submission:Parameters<typeof mine>[1];participants:string[]}>();
  for(const c of f.contributions){const id=executionIdentity(c.submission),g=groups.get(id);if(g)g.participants.push(c.miner);else groups.set(id,{submission:c.submission,participants:[c.miner]});}
  const results=[...groups.entries()].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([digest,g])=>{
    const holdout=compare(fixtures,baselineOutputs,run(g.submission)),pub=publicReport.results.find(r=>r.digest===digest)!.comparison.candidate;
    // Deterministic anti-memorization signal, not a penalty weight: detects public defects, none of the sealed ones.
    return {digest,participants:g.participants.sort(),holdout,public:{tp:pub.tp,fp:pub.fp,fn:pub.fn},memorizationSuspect:pub.tp>0 && holdout.candidate.tp===0};
  });
  const tiers=paretoTiers(results.map(r=>({digest:r.digest,tp:r.holdout.candidate.tp,fp:r.holdout.candidate.fp,regressed:r.holdout.regressed})));
  const report={schema:'sentinel-holdout-report/v1',round:f.scope.round,cohortSha256:expected.snapshot.cohortSha256,owner:commitment.owner,bankSha256:commitment.bankSha256,
    cases:fixtures.length,families:[...new Set(bank.cases.map(c=>c.family))].sort(),baseline:executionIdentity(baseline),results,tiers,weights:null,rewards:null};
  return {...report,resultSha256:sha256(Buffer.from('sentinel/holdout-report/v1\n'+canonical(report)))};
}

if(import.meta.main){
  try{
    const {boundedFile}=await import('./replay');
    const [action,...args]=process.argv.slice(2);
    const json=async(path:string)=>parseHoldoutJSON(await boundedFile(path,holdoutByteLimit));
    if(action==='commit' && args.length===4){
      // commit BANK ROUND OWNER PRIVATE_SEED  (holdout owner only; prints signed commitment, never the bank)
      const [bankPath,round,owner,key]=args,{signPractice}=await import('./validator-attest');
      const bank=await json(bankPath) as HoldoutBank;
      const payload={schema:'sentinel-holdout-commitment/v1' as const,round,owner,bankSha256:holdoutBankDigest(bank),cases:Array.isArray(bank.cases)?bank.cases.length:0,committedAt:Date.now()};
      console.log(JSON.stringify({...payload,signature:await signPractice(holdoutCommitmentPayload(payload),owner,key)}));
    }else if(action==='verify' && args.length===3){
      // verify COMMITMENT ROUND OWNER  (miner checks the sealed bank exists for its round before contributing)
      console.log(JSON.stringify(await verifyHoldoutCommitment(await json(args[0]),args[1],args[2])));
    }else if(action==='evaluate' && args.length===4){
      // evaluate SNAPSHOT HOLDOUT_EXPECTATIONS COMMITMENT BANK
      const [snapshot,expectations,commitment,bank]=args;
      console.log(JSON.stringify(await evaluateHoldout(await boundedFile(snapshot,snapshotByteLimit),await json(expectations) as HoldoutExpectation,await json(commitment),await boundedFile(bank,holdoutByteLimit))));
    }else throw new Error('Usage: holdout.ts commit BANK ROUND OWNER PRIVATE_SEED | verify COMMITMENT ROUND OWNER | evaluate SNAPSHOT EXPECTATIONS COMMITMENT BANK');
  }catch(error){console.error(error instanceof Error?error.message:'Holdout evaluation failed');process.exitCode=1;}
}
