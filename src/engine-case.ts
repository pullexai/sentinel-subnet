import {createHash} from 'node:crypto';
import {jcs} from './jcs';

// EC-03 common evaluation input `sentinel-engine-case/v1` plus the file table and content blobs it binds.
// Gold, oracles and lineage never appear here; the trusted worker keeps them.
export const caseSchema='sentinel-engine-case/v1';
export const caseLimits={files:1000,fileBytes:1<<20,totalBytes:8<<20,queryChars:2048,pathBytes:1024} as const;
export const tasks=['detection','retrieval','fix','test'] as const;
export type FileEntry={file_id:string;revision:'base'|'head';path_bytes_hex:string;path_encoding:'utf-8'|'opaque';content_sha256:string;bytes:string;language:string};
export type EngineCase={case_input_id:string;repository_family_commitment:string;base_tree_sha256:string;head_tree_sha256:string;file_table_sha256:string;
  task:typeof tasks[number];query:{text:string;changed_file_ids:string[]};allowed_context_sha256:string;build_profile_sha256:string};
export type CaseBundle={case:EngineCase;file_table:FileEntry[];blobs:{content_sha256:string;base64:string}[]};

const sha256=(s:string|Uint8Array)=>createHash('sha256').update(s).digest('hex');
const domain=(d:string,v:unknown)=>sha256(d+'\n'+jcs(v));
const bad=(f:string):never=>{throw new Error('Invalid engine case '+f);};
function exact(v:unknown,keys:string[],f:string):Record<string,unknown>{
  if(!v || typeof v!=='object' || Array.isArray(v) || Object.keys(v).length!==keys.length || !keys.every(k=>Object.hasOwn(v,k)))bad(f);
  return v as Record<string,unknown>;
}
const digest=(v:unknown,f:string)=>typeof v==='string' && /^[0-9a-f]{64}$/.test(v)?v:bad(f);
const ident=(v:unknown,f:string)=>typeof v==='string' && /^[a-z0-9][a-z0-9._-]{0,127}$/.test(v)?v:bad(f);
const integer=(v:unknown,f:string,max:number)=>typeof v==='string' && /^(0|[1-9][0-9]{0,15})$/.test(v) && Number(v)<=max?Number(v):bad(f);
function sorted<T>(v:unknown,f:string,max:number,item:(x:unknown)=>T,key:(x:T)=>string){
  if(!Array.isArray(v) || v.length>max)bad(f);
  const items=(v as unknown[]).map(item),keys=items.map(key);
  for(let i=1;i<keys.length;i++)if(!(keys[i-1]<keys[i]))bad(f+' order or duplicate');
  return items;
}

// Tree identity: path bytes, encoding, content and language per revision; independent of opaque file IDs.
export const treeDigest=(entries:FileEntry[])=>domain('sentinel-engine-tree/v1',entries.map(({path_bytes_hex,path_encoding,content_sha256,bytes,language})=>({path_bytes_hex,path_encoding,content_sha256,bytes,language}))
  .sort((a,b)=>a.path_bytes_hex<b.path_bytes_hex?-1:1));
export const fileTableDigest=(table:FileEntry[])=>domain('sentinel-engine-file-table/v1',table);
export const contextDigest=(fileIds:string[])=>domain('sentinel-engine-context/v1',[...new Set(fileIds)].sort());
export const caseInputId=(c:Omit<EngineCase,'case_input_id'>)=>domain(caseSchema,c);
export const noBuildProfile=sha256('sentinel-engine-build-profile/none/v1');

export function validateCaseBundle(value:unknown){
  const b=exact(value,['case','file_table','blobs'],'bundle');
  const c=exact(b.case,['case_input_id','repository_family_commitment','base_tree_sha256','head_tree_sha256','file_table_sha256','task','query','allowed_context_sha256','build_profile_sha256'],'case');
  for(const k of ['case_input_id','repository_family_commitment','base_tree_sha256','head_tree_sha256','file_table_sha256','allowed_context_sha256','build_profile_sha256'])digest(c[k],k);
  if(!tasks.includes(c.task as never))bad('task');
  const table=sorted(b.file_table,'file_table',caseLimits.files,x=>{
    const e=exact(x,['file_id','revision','path_bytes_hex','path_encoding','content_sha256','bytes','language'],'file entry');
    ident(e.file_id,'file_id');if(e.revision!=='base' && e.revision!=='head')bad('revision');
    if(typeof e.path_bytes_hex!=='string' || !/^(?:[0-9a-f]{2}){1,1024}$/.test(e.path_bytes_hex) || e.path_bytes_hex.match(/../g)!.includes('00'))bad('path bytes');
    if(e.path_encoding==='utf-8'){try{new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Buffer.from(e.path_bytes_hex as string,'hex'));}catch{bad('path encoding');}}
    else if(e.path_encoding!=='opaque')bad('path encoding');
    digest(e.content_sha256,'content_sha256');integer(e.bytes,'bytes',caseLimits.fileBytes);ident(e.language,'language');
    return e as FileEntry;
  },e=>jcs([e.revision,e.file_id]));
  const byRev=(r:string)=>table.filter(e=>e.revision===r),base=byRev('base'),head=byRev('head');
  // Complete snapshots: one entry per path per revision; unchanged files stay addressable in both.
  for(const rev of [base,head])if(new Set(rev.map(e=>e.path_bytes_hex)).size!==rev.length)bad('duplicate path');
  if(!head.length)bad('empty head');
  // One opaque ID denotes one path across revisions.
  const idPath=new Map<string,string>();
  for(const e of table)if((idPath.get(e.file_id) ?? e.path_bytes_hex)!==e.path_bytes_hex)bad('file_id reuse');else idPath.set(e.file_id,e.path_bytes_hex);
  if(treeDigest(base)!==c.base_tree_sha256 || treeDigest(head)!==c.head_tree_sha256)bad('tree digest');
  if(fileTableDigest(table)!==c.file_table_sha256)bad('file_table_sha256');
  if(contextDigest(table.map(e=>e.file_id))!==c.allowed_context_sha256)bad('allowed_context_sha256');
  const q=exact(c.query,['text','changed_file_ids'],'query');
  if(typeof q.text!=='string' || q.text.length>caseLimits.queryChars || !q.text.isWellFormed() || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(q.text))bad('query text');
  const baseByPath=new Map(base.map(e=>[e.path_bytes_hex,e.content_sha256]));
  const changed=head.filter(e=>baseByPath.get(e.path_bytes_hex)!==e.content_sha256).map(e=>e.file_id).sort();
  if(jcs(sorted(q.changed_file_ids,'changed_file_ids',caseLimits.files,x=>ident(x,'changed id'),x=>x))!==jcs(changed))bad('changed_file_ids');
  const content=new Map<string,Buffer>();let total=0;
  sorted(b.blobs,'blobs',caseLimits.files*2,x=>{
    const o=exact(x,['content_sha256','base64'],'blob');digest(o.content_sha256,'blob digest');
    if(typeof o.base64!=='string' || o.base64.length>Math.ceil(caseLimits.fileBytes/3)*4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(o.base64) || o.base64.length%4)bad('blob encoding');
    const bytes=Buffer.from(o.base64 as string,'base64');
    if(sha256(bytes)!==o.content_sha256)bad('blob digest');
    if((total+=bytes.length)>caseLimits.totalBytes)bad('total bytes');
    content.set(o.content_sha256 as string,bytes);return o;
  },o=>o.content_sha256 as string);
  const referenced=new Set(table.map(e=>e.content_sha256));
  if(referenced.size!==content.size || table.some(e=>content.get(e.content_sha256)?.length!==Number(e.bytes)))bad('blob set');
  const {case_input_id,...rest}=c;
  if(caseInputId(rest as Omit<EngineCase,'case_input_id'>)!==case_input_id)bad('case_input_id');
  return {case:c as EngineCase,table,content};
}

// Trusted worker only: builds a case from a legacy practice input. Changed files are absent from base;
// all other files are identical in both revisions. Nothing about gold reaches the bundle.
const languages:Record<string,string>={js:'javascript',mjs:'javascript',ts:'typescript',py:'python'};
export function caseFromPractice(input:{id:string;files:Record<string,string>;changedFiles:string[]},salt:string,family:string,task:EngineCase['task'],text:string){
  const fileId=(path:string)=>sha256(salt+'\n'+input.id+'\n'+path).slice(0,32);
  const table:FileEntry[]=[],blobs=new Map<string,string>();
  for(const [path,source] of Object.entries(input.files)){
    const bytes=Buffer.from(source),content_sha256=sha256(bytes);blobs.set(content_sha256,bytes.toString('base64'));
    const entry={file_id:fileId(path),path_bytes_hex:Buffer.from(path).toString('hex'),path_encoding:'utf-8' as const,content_sha256,bytes:String(bytes.length),language:languages[path.split('.').pop()!] ?? 'unknown'};
    table.push({...entry,revision:'head'});
    if(!input.changedFiles.includes(path))table.push({...entry,revision:'base'});
  }
  table.sort((a,b)=>jcs([a.revision,a.file_id])<jcs([b.revision,b.file_id])?-1:1);
  const rest={repository_family_commitment:sha256('sentinel-engine-family/v1\n'+salt+'\n'+family),
    base_tree_sha256:treeDigest(table.filter(e=>e.revision==='base')),head_tree_sha256:treeDigest(table.filter(e=>e.revision==='head')),
    file_table_sha256:fileTableDigest(table),task,query:{text,changed_file_ids:input.changedFiles.map(fileId).sort()},
    allowed_context_sha256:contextDigest(table.map(e=>e.file_id)),build_profile_sha256:noBuildProfile};
  const bundle:CaseBundle={case:{case_input_id:caseInputId(rest),...rest},file_table:table,
    blobs:[...blobs].sort(([a],[b])=>a<b?-1:1).map(([content_sha256,base64])=>({content_sha256,base64}))};
  return {bundle,fileId};
}
