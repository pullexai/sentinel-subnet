import { expect,test } from 'bun:test';
import { corpus,proveFixture,families } from '../src/corpus';
import { admit,benchmark,compare,executionIdentity,measure,mine,reference } from '../src/competition';
import { evaluateCohort } from '../src/validator';
import { parseInput } from '../src/miner';

test('four independently synthetic practice families demonstrate bugs, fixes and clean controls',async () => {
  const fixtures = corpus('a'.repeat(64),2);
  expect(corpus('a'.repeat(64),2)).toEqual(fixtures);
  expect(new Set(fixtures.map(f => f.input.id)).size).toBe(16);
  for (const fixture of fixtures) {
    const proof = await proveFixture(fixture);
    expect(proof.corrected).toEqual(fixture.oracle.expected);
    expect(proof.buggy).toBe(fixture.buggy);
    expect(Object.keys(fixture.input).sort()).toEqual(['changedFiles','files','id','schema']);
  }
  expect(new Set(fixtures.map(f => f.family))).toEqual(new Set(families));
  const outputs = new Map(fixtures.map(f => [f.input.id,mine(f.input,reference)]));
  expect(measure(fixtures,outputs)).toMatchObject({ tp:8,fp:0,fn:0,clean:8,cleanFlagged:0 });
  const report = compare(fixtures,outputs,new Map());
  expect(report).toMatchObject({ recovered:0,regressed:8,newFalsePositiveCases:0 });
  const all = new Map(fixtures.map(f => [f.input.id,[{ path:f.defectPath,ruleId:'all-files' }]]));
  expect(compare(fixtures,outputs,all)).toMatchObject({ recovered:0,regressed:0,newFalsePositiveCases:8 });
  expect(measure(fixtures,all)).toMatchObject({ tp:8,fp:8,fn:0,precision:0.5 });
  expect(() => measure(fixtures,new Map([['unknown',[]]]))).toThrow('cohort');
  expect(() => measure(fixtures,new Map([[fixtures[0].input.id,[{ path:'../secret',ruleId:'fake' }]]]))).toThrow('finding');
  const duplicate = new Map(outputs);
  duplicate.set(fixtures[0].input.id,[...outputs.get(fixtures[0].input.id)!,...outputs.get(fixtures[0].input.id)!]);
  expect(measure(fixtures,duplicate)).toEqual(measure(fixtures,outputs));
},30000);

test('bounded data-only miner admission and label-independent clone identity',() => {
  expect(admit(reference)).toEqual(reference);
  const clone = { ...reference,rules:[...reference.rules].reverse().map((r,i)=>({ ...r,id:`renamed-${i}` })) };
  expect(executionIdentity(admit(clone))).toBe(executionIdentity(reference));
  expect(() => admit({ ...reference,command:'run.js' })).toThrow('Unsupported');
  expect(() => admit({ ...reference,rules:[{ ...reference.rules[0],url:'https://example.com' }] })).toThrow('Invalid');
  expect(() => admit({ ...reference,rules:[reference.rules[0],reference.rules[0]] })).toThrow('Invalid');
  expect(() => admit({ ...reference,rules:[{ id:'bad',literal:'x'.repeat(161) }] })).toThrow('Invalid');
  expect(() => corpus('customer text',1)).toThrow('parameters');
  expect(() => corpus('a'.repeat(64),0)).toThrow('parameters');
  expect(() => parseInput({ ...corpus('a'.repeat(64),1)[0].input,truth:'leaked' })).toThrow('schema');
  expect(() => parseInput({ ...corpus('a'.repeat(64),1)[0].input,files:{ '../escape.js':'x' },changedFiles:['../escape.js'] })).toThrow('file');
});

test('validator deduplicates clones and ranks reproducibly without generating weights',async () => {
  const candidates=[{ participant:'reference',submission:reference },{ participant:'clone',submission:{ ...reference,rules:[...reference.rules].reverse() } },
    { participant:'empty',submission:{ ...reference,rules:[{ id:'nothing',literal:'no-matching-content' }] } }];
  const report=await evaluateCohort('b'.repeat(64),1,candidates);
  expect(report.results).toHaveLength(2);
  expect(report.tiers).toEqual([[executionIdentity(reference)],[executionIdentity(candidates[2].submission)]]);
  expect(report.results.find(r=>r.digest===executionIdentity(reference))?.participants).toEqual(['clone','reference']);
  const replay=await evaluateCohort('b'.repeat(64),1,[...candidates].reverse());
  expect(replay.comparisonId).toBe(report.comparisonId);
  expect(replay.tiers).toEqual(report.tiers);
  expect(report.weights).toBeNull(); expect(report.rewards).toBeNull();
  await expect(evaluateCohort('b'.repeat(64),1,[candidates[0],candidates[0]])).rejects.toThrow('cohort');
},30000);

test('evaluation seals admitted bytes before asynchronous oracle execution',async()=>{
  const submission=structuredClone(reference),digest=executionIdentity(submission);
  const pending=evaluateCohort('c'.repeat(64),1,[{participant:'sealed',submission}]);
  submission.rules[0].literal='no-matching-content';
  const report=await pending;
  expect(report.results[0].digest).toBe(digest);
  expect(report.results[0].comparison.candidate).toMatchObject({tp:4,fp:0,fn:0});
  const single=structuredClone(reference),measured=benchmark('c'.repeat(64),1,single);
  single.rules.splice(0,single.rules.length,{id:'changed',literal:'no-matching-content'});
  expect(await measured).toMatchObject({executionIdentity:digest,versusEmpty:{candidate:{tp:4,fp:0,fn:0}}});
  const saved=structuredClone(reference),baselineRun=evaluateCohort('c'.repeat(64),1,[{participant:'sealed',submission:saved}]),singleRun=benchmark('c'.repeat(64),1,saved);
  try{
    reference.rules[0].literal='mutated-baseline';
    const [cohort,individual]=await Promise.all([baselineRun,singleRun]);
    expect(cohort.comparisonId).toBe(report.comparisonId);
    expect(cohort.results[0].comparison.baseline).toMatchObject({tp:4,fp:0,fn:0});
    expect(individual.versusTemplateReference.baseline).toMatchObject({tp:4,fp:0,fn:0});
  }finally{reference.rules=saved.rules;}
},30000);
