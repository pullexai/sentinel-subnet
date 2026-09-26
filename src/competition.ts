import { createHash } from 'node:crypto';
import { corpus,families,proveFixture,type Fixture,type Input } from './corpus';

export type Submission = { schema:'sentinel-literal-miner/v1'; rules:{ id:string; literal:string }[] };
export type Finding = { path:string; ruleId:string };
const exact = (value: unknown,keys: string[]): value is Record<string,unknown> => !!value && typeof value==='object' && !Array.isArray(value) &&
  Object.keys(value).length===keys.length && keys.every(k => Object.hasOwn(value,k));
export function admit(value: unknown): Submission {
  if (!exact(value,['schema','rules']) || value.schema!=='sentinel-literal-miner/v1' || !Array.isArray(value.rules) ||
    value.rules.length>100 || value.rules.length<1) throw new Error('Unsupported submission');
  const ids = new Set<string>();
  for (const rule of value.rules) {
    if (!exact(rule,['id','literal']) || typeof rule.id!=='string' || !/^[a-z][a-z0-9-]{1,59}$/.test(rule.id) || ids.has(rule.id) ||
      typeof rule.literal!=='string' || !/^[\x20-\x7e]{1,160}$/.test(rule.literal) || !rule.literal.trim()) throw new Error('Invalid literal rule');
    ids.add(rule.id);
  }
  return value as Submission;
}
// Content identity excludes rule labels/order; exact clones cannot create a new
// execution identity by renaming rules. Not semantic clone or Sybil detection.
export function executionIdentity(submission: Submission) {
  return createHash('sha256').update('sentinel-literal-miner/v1\n'+JSON.stringify([...new Set(submission.rules.map(r => r.literal))].sort())).digest('hex');
}
export function mine(input: Input,submission: Submission): Finding[] {
  const result: Finding[] = [];
  for (const path of Object.keys(input.files).sort()) for (const rule of submission.rules) {
    if (input.files[path].includes(rule.literal)) result.push({ path,ruleId:rule.id });
  }
  return result;
}
export type Counts = { tp:number; fp:number; fn:number; clean:number; cleanFlagged:number };
const empty = (): Counts => ({ tp:0,fp:0,fn:0,clean:0,cleanFlagged:0 });
export function measure(fixtures: Fixture[],outputs: ReadonlyMap<string,readonly Finding[]>) {
  const ids = new Set(fixtures.map(f => f.input.id));
  if (ids.size!==fixtures.length || [...outputs.keys()].some(id => !ids.has(id))) throw new Error('Invalid evaluation cohort');
  const total = empty(), byFamily = Object.fromEntries(families.map(f => [f,empty()]));
  for (const fixture of fixtures) {
    const findings = outputs.get(fixture.input.id) || [];
    if (findings.length>10000 || findings.some(f => !exact(f,['path','ruleId']) || typeof f.path!=='string' ||
      !Object.hasOwn(fixture.input.files,f.path) || typeof f.ruleId!=='string' || !/^[a-z][a-z0-9-]{1,59}$/.test(f.ruleId))) throw new Error('Invalid finding');
    // One defect per fixture. Repeating its location never multiplies reward.
    const paths = new Set(findings.map(f => f.path));
    const hit = fixture.buggy && paths.has(fixture.defectPath);
    for (const counts of [total,byFamily[fixture.family]]) {
      counts.tp+=Number(hit); counts.fn+=Number(fixture.buggy && !hit); counts.fp+=paths.size-Number(hit);
      counts.clean+=Number(!fixture.buggy); counts.cleanFlagged+=Number(!fixture.buggy && paths.size>0);
    }
  }
  return { ...total,precision:total.tp+total.fp ? total.tp/(total.tp+total.fp) : null,
    recall:total.tp+total.fn ? total.tp/(total.tp+total.fn) : null,byFamily };
}
export function compare(fixtures: Fixture[],baseline: ReadonlyMap<string,readonly Finding[]>,candidate: ReadonlyMap<string,readonly Finding[]>) {
  const base = measure(fixtures,baseline), current = measure(fixtures,candidate);
  let recovered=0,regressed=0,newFalsePositiveCases=0;
  for (const fixture of fixtures) {
    const a=baseline.get(fixture.input.id)||[],b=candidate.get(fixture.input.id)||[];
    const ahit=fixture.buggy && a.some(f => f.path===fixture.defectPath),bhit=fixture.buggy && b.some(f => f.path===fixture.defectPath);
    recovered+=Number(bhit && !ahit); regressed+=Number(ahit && !bhit);
    newFalsePositiveCases+=Number(!fixture.buggy && !a.length && b.length>0);
  }
  return { baseline:base,candidate:current,recovered,regressed,newFalsePositiveCases };
}

export const reference: Submission = { schema:'sentinel-literal-miner/v1',rules:[
  { id:'double-scale',literal:') * 100;' },{ id:'tenant-key',literal:'const key = id;' },
  { id:'path-prefix',literal:'return path.startsWith(root);' },{ id:'expiry-edge',literal:'now <= expires' },
] };

export async function benchmark(seed: string,pairs: number,submission: Submission) {
  const fixtures = corpus(seed,pairs);
  for (const fixture of fixtures) await proveFixture(fixture);
  const run = (candidate: Submission) => {
    const cpu = process.cpuUsage(),start=performance.now();
    const outputs = new Map(fixtures.map(f => [f.input.id,mine(f.input,candidate)]));
    return { outputs,resources:{ elapsedMs:performance.now()-start,cpuMicroseconds:process.cpuUsage(cpu),
      processRssBytes:process.memoryUsage.rss(),inputBytes:fixtures.reduce((n,f)=>n+Buffer.byteLength(JSON.stringify(f.input)),0) } };
  };
  const measured=run(submission),control=run(reference);
  return { schema:'sentinel-practice-report/v1',syntheticOnly:true,publicTemplateFamilies:true,
    generator:'sentinel-corpus/v1',seed,cases:fixtures.length,executionIdentity:executionIdentity(submission),
    versusEmpty:compare(fixtures,new Map(),measured.outputs),versusTemplateReference:compare(fixtures,control.outputs,measured.outputs),
    resources:measured.resources,referenceResources:control.resources,
    limitation:'Shared-template practice only; not hidden-lineage generalization, hostile-code isolation, chain weights, rewards or product promotion.' };
}

if (import.meta.main) {
  const [seed,pairs,path] = process.argv.slice(2);
  let submission = reference;
  if (path) {
    const { readSubmission } = await import('./miner');
    submission = await readSubmission(path);
  }
  console.log(JSON.stringify(await benchmark(seed,Number(pairs),submission),null,2));
}
