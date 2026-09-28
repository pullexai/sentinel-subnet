import { createHash } from 'node:crypto';
import { corpus,proveFixture } from './corpus';
import { admit,compare,executionIdentity,mine,reference,type Submission } from './competition';

export type Candidate = { participant:string; submission:Submission };
export type PracticeTuple = {role:'baseline'|'candidate';executionIdentity:string;caseId:string;trialIndex:0;paths:string[]};
// Pareto tiers avoid inventing utility weights: more TP, fewer FP, fewer lost
// baseline detections. Resource observations are reported, not noisy tie-breaks.
export function paretoTiers(results:{digest:string;tp:number;fp:number;regressed:number}[]) {
  const remaining=new Set(results.map(r => r.digest)),tiers:string[][]=[];
  const dominates=(x:typeof results[number],y:typeof results[number]) =>
    x.tp>=y.tp && x.fp<=y.fp && x.regressed<=y.regressed && (x.tp>y.tp || x.fp<y.fp || x.regressed<y.regressed);
  while (remaining.size) {
    const tier=results.filter(r => remaining.has(r.digest) && !results.some(other => remaining.has(other.digest) && dominates(other,r))).map(r => r.digest);
    tiers.push(tier); for (const id of tier) remaining.delete(id);
  }
  return tiers;
}
const participant = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
export async function evaluateCohort(seed: string,pairs: number,candidates: Candidate[],baseline: Submission=reference,capture?:(tuples:PracticeTuple[])=>void) {
  if (!Array.isArray(candidates) || candidates.length<1 || candidates.length>100 ||
    candidates.some(c => !c || Object.keys(c).sort().join(',')!=='participant,submission' || typeof c.participant!=='string' || !participant.test(c.participant)) ||
    new Set(candidates.map(c => c.participant)).size!==candidates.length) throw new Error('Invalid practice cohort');
  // Freeze clone groups before evaluation. No advantage from a renamed rule set.
  const groups = new Map<string,{ submission:Submission; participants:string[] }>();
  for (const c of candidates) {
    const submission=structuredClone(admit(c.submission)),digest=executionIdentity(submission);
    const group=groups.get(digest);
    if (group) group.participants.push(c.participant);
    else groups.set(digest,{ submission,participants:[c.participant] });
  }
  const baselineSubmission=structuredClone(admit(baseline)),baselineDigest=executionIdentity(baselineSubmission);
  const fixtures=corpus(seed,pairs);
  for (const fixture of fixtures) await proveFixture(fixture);
  const tuples:PracticeTuple[]=[];
  const run=(role:PracticeTuple['role'],submission:Submission)=>new Map(fixtures.map(f=>{
    const findings=mine(f.input,submission);
    if(capture)tuples.push({role,executionIdentity:executionIdentity(submission),caseId:f.input.id,trialIndex:0,paths:[...new Set(findings.map(x=>x.path))].sort()});
    return [f.input.id,findings];
  }));
  const baselineOutputs=run('baseline',baselineSubmission);
  const results=[...groups.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([digest,group]) => {
    const start=performance.now(),cpu=process.cpuUsage();
    const outputs=run('candidate',group.submission);
    const resources={ elapsedMs:performance.now()-start,cpuMicroseconds:process.cpuUsage(cpu),processRssBytes:process.memoryUsage.rss() };
    return { digest,participants:group.participants.sort(),comparison:compare(fixtures,baselineOutputs,outputs),resources };
  });
  const tiers=paretoTiers(results.map(r=>({digest:r.digest,tp:r.comparison.candidate.tp,fp:r.comparison.candidate.fp,regressed:r.comparison.regressed})));
  const comparisonId=createHash('sha256').update(JSON.stringify({ generator:'sentinel-corpus/v1',seed,pairs,
    baseline:baselineDigest,candidates:results.map(r=>r.digest) })).digest('hex');
  capture?.(tuples);
  return { schema:'sentinel-practice-cohort/v1',comparisonId,generator:'sentinel-corpus/v1',seed,pairs,
    cases:fixtures.length,tiers,results,weights:null,rewards:null,
    limitation:'Public-template practice. Participant labels are not authenticated hotkeys. Pareto tiers are not calibrated incentives or network weights.' };
}

if (import.meta.main) {
  const [seed,pairs,...paths]=process.argv.slice(2);
  const { readSubmission } = await import('./miner');
  const candidates = await Promise.all(paths.map(async (path,i) => ({ participant:`local-${i}`,submission:await readSubmission(path) })));
  console.log(JSON.stringify(await evaluateCohort(seed,Number(pairs),candidates),null,2));
}
