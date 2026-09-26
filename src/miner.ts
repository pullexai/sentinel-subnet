import { admit,mine,type Submission } from './competition';
import type { Input } from './corpus';

export function parseInput(value: unknown): Input {
  if (!value || typeof value!=='object' || Array.isArray(value)) throw new Error('Invalid miner input');
  const input = value as Input;
  if (Object.keys(input).sort().join(',')!=='changedFiles,files,id,schema' || input.schema!=='sentinel-practice-input/v1' ||
    typeof input.id!=='string' || !/^[a-f0-9]{64}$/.test(input.id) || !input.files || typeof input.files!=='object' || Array.isArray(input.files) ||
    Object.keys(input.files).length>100 || !Array.isArray(input.changedFiles) || input.changedFiles.some(p => typeof p!=='string' || !Object.hasOwn(input.files,p))) throw new Error('Invalid miner input schema');
  let bytes=0;
  for (const [path,text] of Object.entries(input.files)) {
    if (!/^[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*\.[a-zA-Z0-9]+$/.test(path) || typeof text!=='string') throw new Error('Invalid practice file');
    bytes+=Buffer.byteLength(text);
  }
  if (bytes>1_000_000) throw new Error('Practice source limit exceeded');
  return input;
}
export async function readSubmission(path: string): Promise<Submission> {
  const { open,constants } = await import('node:fs/promises');
  const file = await open(path,constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size>65536) throw new Error('Submission byte limit exceeded');
    const buffer = Buffer.alloc(65537);
    let length=0;
    while (length<buffer.length) {
      const { bytesRead } = await file.read(buffer,length,buffer.length-length);
      if (!bytesRead) break; length+=bytesRead;
    }
    if (length>65536) throw new Error('Submission byte limit exceeded');
    return admit(JSON.parse(new TextDecoder('utf-8',{ fatal:true }).decode(buffer.subarray(0,length))));
  } finally { await file.close(); }
}

if (import.meta.main) {
  const submission = await readSubmission(process.argv[2]);
  let buffered=Buffer.alloc(0);
  for await (const chunk of Bun.stdin.stream()) {
    buffered=Buffer.concat([buffered,chunk]);
    for (;;) {
      const newline=buffered.indexOf(10); if (newline<0) break;
      if (newline>1_100_000) throw new Error('Practice input limit exceeded');
      const input=parseInput(JSON.parse(new TextDecoder('utf-8',{ fatal:true }).decode(buffered.subarray(0,newline))));
      console.log(JSON.stringify({ schema:'sentinel-practice-output/v1',id:input.id,findings:mine(input,submission) }));
      buffered=buffered.subarray(newline+1);
    }
    if (buffered.length>1_100_000) throw new Error('Practice input limit exceeded');
  }
  if (buffered.length) throw new Error('Incomplete JSONL input');
}
