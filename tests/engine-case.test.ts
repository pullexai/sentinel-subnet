import {expect,test} from 'bun:test';
import {caseFromPractice,validateCaseBundle,caseInputId,fileTableDigest,type CaseBundle} from '../src/engine-case';
import {Unqualified,registry,requiredEvidence,runProfile,scoreRetrieval,validateOutput,validateProfile} from '../src/engine-retrieval';
import {baselineProfile,caseQuery,runSandbox} from '../src/engine-intake';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';

const input={id:'a'.repeat(64),files:{'main.js':'export function run(i, n) {\n  const x = i % n;\n  return x;\n}\n','util.js':'export const unrelated = 1;\n'},changedFiles:['main.js']};
const make=()=>caseFromPractice(input,'5'.repeat(64),'fam','retrieval',caseQuery);
const profile=(f:(p:any)=>void=()=>{})=>{const p=structuredClone(baselineProfile) as any;f(p);return Buffer.from(JSON.stringify(p));};
const reseal=(b:CaseBundle)=>{b.case.file_table_sha256=fileTableDigest(b.file_table);const {case_input_id,...rest}=b.case;b.case.case_input_id=caseInputId(rest);return b;};

test('sentinel-engine-case/v1 binds base/head trees, unchanged files and every digest',()=>{
  const {bundle}=make(),{table}=validateCaseBundle(bundle);
  // Unchanged util.js is addressable in base and head; changed main.js only in head (added).
  expect(table.map(e=>e.revision).sort()).toEqual(['base','head','head']);
  expect(bundle.case.query.changed_file_ids).toHaveLength(1);
  expect(JSON.stringify(bundle.case.query)).not.toContain('%'); // Query is synthetic task text, never the answer.
  const tamper=(f:(b:any)=>void,msg:string)=>{const b=structuredClone(bundle) as any;f(b);expect(()=>validateCaseBundle(b)).toThrow(msg);};
  tamper(b=>{b.case.extra=1;},'case');
  tamper(b=>{b.case.task='exec';},'task');
  tamper(b=>{b.case.case_input_id='0'.repeat(64);},'case_input_id');
  tamper(b=>{b.file_table.reverse();},'order');
  tamper(b=>{b.file_table[0].bytes='01';},'bytes');
  tamper(b=>{b.file_table[0].path_bytes_hex='2e2e2f00';},'path bytes');
  tamper(b=>{b.file_table[0].path_bytes_hex='ff';reseal(b);},'path encoding');
  tamper(b=>{b.blobs[0].base64=Buffer.from('evil').toString('base64');},'blob digest');
  tamper(b=>{b.blobs.push({content_sha256:'f'.repeat(64),base64:''});},'blob');
  tamper(b=>{b.case.query.changed_file_ids=[];reseal(b);},'changed_file_ids');
  tamper(b=>{b.file_table=b.file_table.filter((e:any)=>e.revision==='head');reseal(b);},'tree digest'); // Dropping unchanged base file.
  tamper(b=>{b.case.query.text='\u0000';reseal(b);},'query text');
  tamper(b=>{b.file_table[1].file_id=b.file_table[2].file_id;b.file_table.sort((x:any,y:any)=>JSON.stringify([x.revision,x.file_id])<JSON.stringify([y.revision,y.file_id])?-1:1);reseal(b);},'');
});

test('retrieval-profile/v1 admission is strict and external engines are unqualified-engine',()=>{
  expect(validateProfile(profile()).stages).toHaveLength(2);
  const reject=(f:(p:any)=>void,cls:any=Error)=>expect(()=>validateProfile(profile(f))).toThrow(cls);
  reject(p=>{p.embedding_component_sha256='1'.repeat(64);},Unqualified);
  reject(p=>{p.stages.unshift({operator:'embedding_rank',params:{}});},Unqualified);
  reject(p=>{p.stages.unshift({operator:'resolved_symbol_neighbors',params:{depth:'9'}});},Unqualified);
  reject(p=>{p.stages[0].operator='exec';});
  reject(p=>{p.stages[0].params.k1={numerator:'12',denominator:'10'};}); // Unreduced rational.
  reject(p=>{p.stages[0].params.b={numerator:'3',denominator:'2'};}); // b > 1.
  reject(p=>{p.stages[0].params.top_k='01';});
  reject(p=>{p.stages[0].params.extra=1;});
  reject(p=>{p.stages.reverse();});
  reject(p=>{p.stages.splice(1,0,structuredClone(p.stages[0]));}); // Two rankers without fuse_rrf.
  reject(p=>{p.stages[1].params.max_ranges=String(registry.output_limit.max_ranges+1);});
  reject(p=>{p.chunker_component_sha256='0'.repeat(64);});
  expect(()=>validateProfile(Buffer.from('{"schema":"retrieval-profile/v1","schema":1}'))).toThrow('duplicate key');
});

test('lexical retrieval is deterministic, fuses exactly and scores against an independent oracle',()=>{
  const {bundle,fileId}=make();
  const fused=validateProfile(profile(p=>{p.stages=[p.stages[0],{...structuredClone(p.stages[0]),params:{...p.stages[0].params,query_source:'changed_files'}},{operator:'fuse_rrf',params:{k:'60'}},{operator:'deduplicate',params:{}},p.stages[1]];}));
  const a=runProfile(fused,bundle),b=runProfile(fused,structuredClone(bundle));
  expect(a).toEqual(b);expect(a.status).toBe('ok');
  expect(validateOutput(a,bundle.case.case_input_id,bundle.file_table)).toBe(a);
  const bad=(f:(o:any)=>void)=>{const o=structuredClone(a) as any;f(o);expect(()=>validateOutput(o,bundle.case.case_input_id,bundle.file_table)).toThrow('Invalid engine output');};
  bad(o=>{o.retrieval[0].end_byte=1e6;});
  bad(o=>{o.retrieval[0].revision='base';});
  bad(o=>{o.retrieval[0].rank=2;});
  bad(o=>{o.retrieval.push({...o.retrieval[0],rank:o.retrieval.length+1});});
  bad(o=>{o.findings=[];});
  bad(o=>{o.case_input_id='0'.repeat(64);});
  const span=requiredEvidence(input.files['main.js'],input.files['main.js'].replace('i % n','((i % n) + n) % n'));
  expect(Buffer.from(input.files['main.js']).subarray(span.start_byte,span.end_byte).toString()).toBe('i');
  const gold=[{case_input_id:bundle.case.case_input_id,evidence:{file_id:fileId('main.js'),...span}}];
  const s=scoreRetrieval(gold,new Map([[bundle.case.case_input_id,a]]));
  expect(s).toMatchObject({required:1,covered:1,evidence_recall:{numerator:'1',denominator:'1'}});
  expect(scoreRetrieval(gold,new Map()).missed).toBe(1); // Missing output is a miss, not removal.
});

test('sandboxed adapter process rejects hostile profiles and bundles',async()=>{
  const dir=await mkdtemp('/tmp/opencode/engine-case-');
  try{
    const run=async(artifact:string,stdin:unknown)=>{
      await Bun.write(join(dir,'a','rules.json'),artifact);
      return runSandbox({appDir:new URL('../src',import.meta.url).pathname,script:'engine-sandbox.ts',args:['retrieval-profile/v1','rules.json'],artifactDir:join(dir,'a'),stdin:Buffer.from(JSON.stringify(stdin)),timeoutMs:10000,maxOutput:1<<20});
    };
    const {bundle}=make();
    const out=JSON.parse(await run(profile().toString(),[bundle]));
    expect(out[0]).toEqual(runProfile(validateProfile(profile()),bundle));
    await expect(run(profile(p=>{p.stages[0].operator='exec';}).toString(),[bundle])).rejects.toThrow('sandbox_failed');
    await expect(run('{"__proto__":{"polluted":1},'+'['.repeat(100000),[bundle])).rejects.toThrow('sandbox_failed');
    const forged=structuredClone(bundle);forged.blobs[0].base64=Buffer.from('x').toString('base64');
    await expect(run(profile().toString(),[forged])).rejects.toThrow('sandbox_failed');
    await expect(run(profile().toString(),'x')).rejects.toThrow('sandbox_failed');
  }finally{await rm(dir,{recursive:true,force:true});}
},30000);
