import {test,expect} from 'bun:test';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {parseInput} from '../src/miner';
import {reference} from '../src/competition';

test('miner JSONL bounds input and rejects ambiguous changed files and malformed Unicode',async()=>{
  const directory=await mkdtemp('/tmp/opencode/miner-cli-');
  const input={schema:'sentinel-practice-input/v1',id:'a'.repeat(64),files:{'a.ts':'now <= expires'},changedFiles:['a.ts']};
  try {
    await writeFile(directory+'/miner.json',JSON.stringify(reference));
    const run=async(source:string|Uint8Array)=>{
      const child=Bun.spawn([process.execPath,'src/miner.ts',directory+'/miner.json'],{stdin:'pipe',stdout:'pipe',stderr:'pipe'});
      child.stdin.write(source);child.stdin.end();
      const [code,stdout,stderr]=await Promise.all([child.exited,new Response(child.stdout).text(),new Response(child.stderr).text()]);
      return {code,stdout,stderr};
    };
    const valid=await run(JSON.stringify(input)+'\n'+JSON.stringify(input)+'\n');
    expect(valid.code).toBe(0);expect(valid.stderr).toBe('');
    const output=valid.stdout.trim().split('\n').map(line=>JSON.parse(line));
    expect(output).toHaveLength(2);expect(output[0].findings).toEqual([{path:'a.ts',ruleId:'expiry-edge'}]);
    for(const value of [{...input,changedFiles:['a.ts','a.ts']},{...input,files:{},changedFiles:[]},
      {...input,files:{'a.ts':'\ud800'}},{...input,changedFiles:Array(101).fill('a.ts')}]) {
      expect(()=>parseInput(value)).toThrow();
      const result=await run(JSON.stringify(value)+'\n');expect(result.code).not.toBe(0);expect(result.stdout).toBe('');
    }
    for(const bytes of [JSON.stringify(input),'x'.repeat(1_100_001),new Uint8Array([0xff,10])]) {
      const result=await run(bytes);expect(result.code).not.toBe(0);expect(result.stdout).toBe('');
    }
  } finally {await rm(directory,{recursive:true,force:true});}
});
