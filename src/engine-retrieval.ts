import {createHash} from 'node:crypto';
import {jcs,parseJson} from './jcs';
import {validateCaseBundle,type FileEntry} from './engine-case';

// EC-05 `retrieval-profile/v1`, lexical subset, plus the retrieval branch of EC-07 `sentinel-engine-output/v1`.
// The artifact is data only: an ordered list of trusted operators with validated parameters.
// Operators that need an embedding model or a symbol resolver are `unqualified-engine`, never simulated.
export const profileSchema='retrieval-profile/v1';
export const outputSchema='sentinel-engine-output/v1';
const sha256=(s:string)=>createHash('sha256').update(s).digest('hex');
export class Unqualified extends Error{reason='unqualified-engine';}
const bad=(f:string):never=>{throw new Error('Invalid retrieval profile '+f);};
const unqualified=(what:string):never=>{throw new Unqualified('unqualified-engine: '+what);};

// Trusted registry. Digests are SHA-256 of the descriptor JCS so that the identity is the behavior.
const component=<T extends object>(d:T)=>({id:sha256(jcs(d)),...d});
export const registry={
  chunker:component({name:'sentinel-line-chunker/v1',lines:20,overlap:0,revisions:['head']}),
  index:component({name:'sentinel-lexical-index/v1',token:'[A-Za-z_][A-Za-z0-9_]*',min_length:2,case:'lower',idf:'log2(1+(N-n+1/2)/(n+1/2)) fixed-point 2^-32'}),
  output_limit:component({name:'sentinel-context-envelope/v1',max_ranges:16,max_bytes:16384}),
};
const qualified=['lexical_bm25','fuse_rrf','deduplicate','pack_context'],knownUnqualified=['embedding_rank','resolved_symbol_neighbors'];
type Rational={numerator:string;denominator:string};
type Stage={operator:'lexical_bm25';params:{query_source:'query_text'|'changed_files';k1:Rational;b:Rational;top_k:string}}
  |{operator:'fuse_rrf';params:{k:string}}|{operator:'deduplicate';params:Record<string,never>}|{operator:'pack_context';params:{max_ranges:string}};
export type Profile={schema:typeof profileSchema;chunker_component_sha256:string;index_schema_sha256:string;embedding_component_sha256:null;stages:Stage[];output_limit_ref:string};

function exact(v:unknown,keys:string[],f:string):Record<string,unknown>{
  if(!v || typeof v!=='object' || Array.isArray(v) || Object.keys(v).length!==keys.length || !keys.every(k=>Object.hasOwn(v,k)))bad(f);
  return v as Record<string,unknown>;
}
const integer=(v:unknown,f:string,min:number,max:number)=>typeof v==='string' && /^(0|[1-9][0-9]{0,6})$/.test(v) && +v>=min && +v<=max?BigInt(v):bad(f);
const gcd=(a:bigint,b:bigint):bigint=>b?gcd(b,a%b):a;
// Reduced rational with positive denominator; bounded to [0, max].
function rational(v:unknown,f:string,max:bigint):[bigint,bigint]{
  const r=exact(v,['numerator','denominator'],f),n=integer(r.numerator,f,0,1e6),d=integer(r.denominator,f,1,1e6);
  if(gcd(n,d)!==1n || n>max*d)bad(f);return [n,d];
}

export function validateProfile(bytes:Uint8Array):Profile{
  const p=exact(parseJson(bytes,65536,16),['schema','chunker_component_sha256','index_schema_sha256','embedding_component_sha256','stages','output_limit_ref'],'fields');
  if(p.schema!==profileSchema)bad('schema');
  if(p.embedding_component_sha256!==null)unqualified('embedding component (needs a qualified tensor-model/v1 embedding head)');
  if(p.chunker_component_sha256!==registry.chunker.id)bad('chunker component');
  if(p.index_schema_sha256!==registry.index.id)bad('index schema');
  if(p.output_limit_ref!==registry.output_limit.id)bad('output limit');
  if(!Array.isArray(p.stages) || p.stages.length<2 || p.stages.length>8)bad('stages');
  let rankers=0,fused=false;const stages=p.stages as Stage[];
  stages.forEach((s,i)=>{
    const st=exact(s,['operator','params'],'stage');
    if(knownUnqualified.includes(st.operator as string))unqualified(String(st.operator));
    if(!qualified.includes(st.operator as string))bad('operator');
    const last=i===stages.length-1;
    if(st.operator==='lexical_bm25'){
      if(fused || i && stages[i-1].operator!=='lexical_bm25')bad('ranker order');
      const q=exact(st.params,['query_source','k1','b','top_k'],'bm25 params');
      if(q.query_source!=='query_text' && q.query_source!=='changed_files')bad('query_source');
      rational(q.k1,'k1',10n);rational(q.b,'b',1n);integer(q.top_k,'top_k',1,1000);rankers++;
    }else if(st.operator==='fuse_rrf'){
      if(fused || rankers<2)bad('fuse_rrf needs two or more rankers');integer(exact(st.params,['k'],'rrf params').k,'rrf k',1,1000);fused=true;
    }else if(st.operator==='deduplicate'){exact(st.params,[],'deduplicate params');if(last)bad('deduplicate position');}
    else{
      if(!last)bad('pack_context must be last');
      integer(exact(st.params,['max_ranges'],'pack params').max_ranges,'max_ranges',1,registry.output_limit.max_ranges);
    }
  });
  if(!rankers || rankers>1 && !fused || stages.at(-1)!.operator!=='pack_context')bad('pipeline');
  return p as unknown as Profile;
}

// Deterministic fixed-point log2 of a positive rational, 32 fractional bits. No floating point.
const F=32n,ONE=1n<<F; // ONE: fixed-point 1.0
function log2Fixed(n:bigint,d:bigint){
  let int=0n;
  while(n>=2n*d){d*=2n;int++;}
  let x=(n<<F)/d,frac=0n; // x in [1,2) as fixed-point
  for(let bit=F-1n;bit>=0n;bit--){x=(x*x)>>F;if(x>=2n*ONE){x>>=1n;frac|=1n<<bit;}}
  return (int<<F)|frac;
}
// Exact nonnegative rationals as [numerator, denominator].
type Q=[bigint,bigint];
const add=(a:Q,b:Q):Q=>[a[0]*b[1]+b[0]*a[1],a[1]*b[1]];
const cmp=(a:Q,b:Q)=>{const l=a[0]*b[1],r=b[0]*a[1];return l<r?-1:l>r?1:0;};
type Range={file_id:string;revision:'head';start_byte:number;end_byte:number};
const rangeKey=(r:Range)=>jcs([r.revision,r.file_id,r.start_byte,r.end_byte]);
const tokens=(text:string)=>(text.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []).filter(t=>t.length>=2).map(t=>t.toLowerCase());

export function runProfile(profile:Profile,bundleValue:unknown){
  const {case:c,table,content}=validateCaseBundle(bundleValue);
  const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
  const chunks:{range:Range;tokens:string[]}[]=[];let skipped=0;const text=new Map<string,string>();
  for(const e of table.filter(e=>e.revision==='head')){
    let source:string;
    try{source=decoder.decode(content.get(e.content_sha256)!);}catch{skipped++;continue;} // Unsupported encoding: explicit partial coverage.
    text.set(e.file_id,source);
    const bytes=Buffer.from(source),lines=[0];
    for(let i=0;i<bytes.length;i++)if(bytes[i]===10 && i+1<bytes.length)lines.push(i+1);
    for(let i=0;i<lines.length;i+=registry.chunker.lines){
      const start=lines[i],end=lines[i+registry.chunker.lines] ?? bytes.length;
      chunks.push({range:{file_id:e.file_id,revision:'head',start_byte:start,end_byte:end},tokens:tokens(bytes.subarray(start,end).toString())});
    }
  }
  const N=BigInt(chunks.length),total=BigInt(chunks.reduce((n,x)=>n+x.tokens.length,0)) || 1n,df=new Map<string,bigint>();
  for(const x of chunks)for(const t of new Set(x.tokens))df.set(t,(df.get(t) ?? 0n)+1n);
  const byKey=(a:{range:Range},b:{range:Range})=>rangeKey(a.range)<rangeKey(b.range)?-1:1;
  const lists:Range[][]=[];let current:Range[]=[];
  for(const stage of profile.stages){
    if(stage.operator==='lexical_bm25'){
      const {query_source,k1,b,top_k}=stage.params,[kn,kd]=[BigInt(k1.numerator),BigInt(k1.denominator)],[bn,bd]=[BigInt(b.numerator),BigInt(b.denominator)];
      const query=[...new Set(query_source==='query_text'?tokens(c.query.text):c.query.changed_file_ids.flatMap(id=>tokens(text.get(id) ?? '')))];
      const scored=chunks.map(x=>{
        let s=0n;const tf=new Map<string,bigint>();for(const t of x.tokens)tf.set(t,(tf.get(t) ?? 0n)+1n);
        for(const t of query){
          const f=tf.get(t);if(!f)continue;
          const n=df.get(t)!,idf=log2Fixed(2n*N+2n,2n*n+1n); // log2(1+(N-n+1/2)/(n+1/2))
          const dl=BigInt(x.tokens.length);
          // Floor of the exact BM25 term in 2^-32 units: integer arithmetic only, identical on every host.
          s+=idf*f*(kn+kd)*bd*total/(f*kd*bd*total+kn*((bd-bn)*total+bn*dl*N));
        }
        return {range:x.range,score:s};
      }).filter(x=>x.score>0n).sort((a,b)=>a.score===b.score?byKey(a,b):a.score<b.score?1:-1);
      lists.push(scored.slice(0,Number(top_k)).map(x=>x.range));current=lists[0];
    }else if(stage.operator==='fuse_rrf'){
      const k=BigInt(stage.params.k),sum=new Map<string,{range:Range;score:Q}>();
      for(const list of lists)list.forEach((r,i)=>{const e=sum.get(rangeKey(r)) ?? {range:r,score:[0n,1n] as Q};e.score=add(e.score,[1n,k+BigInt(i+1)]);sum.set(rangeKey(r),e);});
      current=[...sum.values()].sort((a,b)=>cmp(b.score,a.score) || byKey(a,b)).map(x=>x.range);
    }else if(stage.operator==='deduplicate'){
      const kept:Range[]=[];
      for(const r of current)if(!kept.some(k=>k.file_id===r.file_id && k.start_byte<r.end_byte && r.start_byte<k.end_byte))kept.push(r);
      current=kept;
    }else{
      const packed:Range[]=[];let bytes=0;
      for(const r of current){
        if(packed.length>=Number(stage.params.max_ranges) || bytes+r.end_byte-r.start_byte>registry.output_limit.max_bytes)break;
        packed.push(r);bytes+=r.end_byte-r.start_byte;
      }
      current=packed;
    }
  }
  return {case_input_id:c.case_input_id,status:current.length?'ok':'abstain',coverage:skipped?'partial':'complete',retrieval:current.map((r,i)=>({...r,rank:i+1}))};
}

// Trusted side: re-validate every adapter output against the verified file table and envelope.
export type RetrievalOutput=ReturnType<typeof runProfile>;
export function validateOutput(value:unknown,caseInputId:string,table:FileEntry[]):RetrievalOutput{
  const bad=(f:string):never=>{throw Object.assign(new Error('Invalid engine output '+f),{reason:'sandbox_output_invalid'});};
  const o=value as Record<string,unknown>;
  if(!o || typeof o!=='object' || Array.isArray(o) || jcs(Object.keys(o).sort())!==jcs(['case_input_id','coverage','retrieval','status']))bad('fields');
  if(o.case_input_id!==caseInputId || !['ok','abstain','unsupported','partial','invalid'].includes(o.status as string) || !['complete','partial'].includes(o.coverage as string))bad('status');
  const list=o.retrieval as unknown[];
  if(!Array.isArray(list) || list.length>registry.output_limit.max_ranges || (o.status==='ok')!==(list.length>0))bad('retrieval');
  let bytes=0;
  (list as unknown[]).forEach((x,i)=>{
    const r=x as Record<string,unknown>;
    if(!r || typeof r!=='object' || jcs(Object.keys(r).sort())!==jcs(['end_byte','file_id','rank','revision','start_byte']) || r.rank!==i+1)bad('range');
    const entry=table.find(e=>e.file_id===r.file_id && e.revision===r.revision);
    if(!entry || !Number.isSafeInteger(r.start_byte) || !Number.isSafeInteger(r.end_byte) || (r.start_byte as number)<0 || (r.start_byte as number)>=(r.end_byte as number) || (r.end_byte as number)>Number(entry.bytes))bad('location');
    if(list.slice(0,i).some((y:any)=>y.file_id===r.file_id && y.revision===r.revision && y.start_byte<(r.end_byte as number) && (r.start_byte as number)<y.end_byte))bad('overlap');
    bytes+=(r.end_byte as number)-(r.start_byte as number);
  });
  if(bytes>registry.output_limit.max_bytes)bad('envelope');
  return o as RetrievalOutput;
}

// Oracle, trusted side only. Required evidence is the byte span where the executable-oracle-proven
// defective head file differs from its independently corrected version; clean cases require none.
export function requiredEvidence(buggy:string,fixed:string){
  const a=Buffer.from(buggy),b=Buffer.from(fixed);let p=0,s=0;
  while(p<a.length && p<b.length && a[p]===b[p])p++;
  while(s<a.length-p && s<b.length-p && a[a.length-1-s]===b[b.length-1-s])s++;
  const end=Math.max(a.length-s,p+1);return {start_byte:Math.min(p,a.length-1),end_byte:Math.min(end,a.length)};
}
export type RetrievalGold={case_input_id:string;evidence:{file_id:string;start_byte:number;end_byte:number}|null};
export function scoreRetrieval(gold:RetrievalGold[],outputs:ReadonlyMap<string,RetrievalOutput>){
  const t={required:0,covered:0,missed:0,ranges:0,relevant_ranges:0,packed_bytes:0,partial:0};
  const hits=new Map<string,boolean>();
  for(const g of gold){
    const o=outputs.get(g.case_input_id),list=o?.retrieval ?? [];
    t.ranges+=list.length;t.packed_bytes+=list.reduce((n,r)=>n+r.end_byte-r.start_byte,0);t.partial+=Number(o?.coverage==='partial');
    if(!g.evidence)continue;
    const e=g.evidence,rel=list.filter(r=>r.file_id===e.file_id && r.revision==='head' && r.start_byte<e.end_byte && e.start_byte<r.end_byte).length;
    t.required++;t.relevant_ranges+=rel;hits.set(g.case_input_id,rel>0);rel?t.covered++:t.missed++;
  }
  // Rational metrics as reduced-free {numerator, denominator}; null when the denominator is zero.
  const ratio=(n:number,d:number)=>d?{numerator:String(n),denominator:String(d)}:null;
  return {...t,evidence_recall:ratio(t.covered,t.required),range_precision:ratio(t.relevant_ranges,t.ranges),hits};
}
