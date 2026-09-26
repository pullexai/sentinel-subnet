import { createHash } from 'node:crypto';

export type Case = {
  id: string; family: 'amount-unit-contract';
  files: Record<string,string>; changedFiles: string[];
  truth: { buggy: boolean; observed: number; expected: number; location: string };
};

// Independently synthetic only. Never accepts repositories, traces or customer input.
// ponytail: one executable unit-contract family; add independent bug families before network scoring.
export function generate(seed: string, count: number): Case[] {
  if (!/^[a-f0-9]{64}$/.test(seed) || !Number.isSafeInteger(count) || count < 1 || count > 1000) throw new Error('Invalid generator inputs');
  return Array.from({ length: count }, (_,i) => {
    const hash = createHash('sha256').update(`${seed}:${i}`).digest('hex');
    const amount = 101 + parseInt(hash.slice(0,6),16) % 9000;
    const buggy = i % 2 === 0;
    const field = `charge_${hash.slice(0,8)}`;
    return {
      id: hash, family: 'amount-unit-contract',
      files: {
        'pricing.js': `export function ${field}(units) { return units * 100; }`,
        'invoice.js': `import { ${field} } from './pricing.js';\nexport function invoice(units) { return ${field}(units)${buggy ? ' * 100' : ''}; }`,
      },
      changedFiles: ['pricing.js'],
      truth: { buggy, observed: amount * 100 * (buggy ? 100 : 1), expected: amount * 100, location: 'invoice.js' },
    };
  });
}

export function score(cases: Case[], findings: ReadonlyMap<string,readonly string[]>) {
  if (new Set(cases.map(c => c.id)).size !== cases.length || [...findings.keys()].some(id => !cases.some(c => c.id === id))) throw new Error('Invalid evaluation cohort');
  let tp = 0, fp = 0, fn = 0;
  for (const c of cases) {
    const paths = findings.get(c.id) || [];
    if (new Set(paths).size !== paths.length || paths.some(p => !Object.hasOwn(c.files,p))) throw new Error('Invalid finding location');
    const hit = c.truth.buggy && paths.includes(c.truth.location);
    tp += Number(hit); fn += Number(c.truth.buggy && !hit);
    fp += paths.length - Number(hit);
  }
  return { tp, fp, fn, precision: tp + fp ? tp/(tp+fp) : null, recall: tp+fn ? tp/(tp+fn) : null };
}

if (import.meta.main) {
  const cases = generate('0'.repeat(64),20);
  const baseline = new Map(cases.map(c => [c.id, [] as string[]]));
  const reference = new Map(cases.map(c => [c.id, c.files['invoice.js'].includes(' * 100') ? ['invoice.js'] : []]));
  console.log(JSON.stringify({ generator: 'amount-unit-contract/v1', publicOnly: true,
    baseline: score(cases,baseline), reference: score(cases,reference),
    limitation: 'Template-aware reference, not independent holdout generalization or network weights' },null,2));
}
