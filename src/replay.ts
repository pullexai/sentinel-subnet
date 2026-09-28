import {open,constants} from 'node:fs/promises';
import {evaluateSnapshot,snapshotByteLimit} from './protocol';
import {scoreTarget} from './attestations';

export async function boundedFile(path:string,limit:number,privateFile=false){
  const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const info=await file.stat();if(!info.isFile() || info.size>limit || privateFile && (info.mode & 0o077 || info.nlink!==1))throw new Error('Invalid replay file');
    const bytes=Buffer.alloc(limit+1);let length=0;
    while(length<bytes.length){const {bytesRead}=await file.read(bytes,length,bytes.length-length);if(!bytesRead)break;length+=bytesRead;}
    if(length>limit)throw new Error('Replay file byte limit');return bytes.subarray(0,length);
  }finally{await file.close();}
}
if(import.meta.main){
  const [snapshot,expectations,...extra]=process.argv.slice(2);
  if(!snapshot || !expectations || extra.length)throw new Error('Usage: replay.ts <snapshot.json> <trusted-expectations.json>');
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await boundedFile(expectations,1024*1024)),expected=JSON.parse(text);
  if(JSON.stringify(expected)!==text)throw new Error('Expectations require compact canonical JSON');
  const report=await evaluateSnapshot(await boundedFile(snapshot,snapshotByteLimit),expected);
  console.log(JSON.stringify({target:scoreTarget(report),report}));
}
