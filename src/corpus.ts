import { createHash } from 'node:crypto';
import { mkdtemp,writeFile,rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export const families = Object.freeze(['amount-unit','tenant-cache','path-boundary','expiry-boundary'] as const);
export type Family = typeof families[number];
export type Input = { schema:'sentinel-practice-input/v1'; id:string; files:Record<string,string>; changedFiles:string[] };
export type Fixture = { input:Input; family:Family; buggy:boolean; defectPath:string; fixedFiles:Record<string,string>;
  oracle:{ entry:string; expression:string; expected:unknown } };
const digest = (s: string) => createHash('sha256').update(s).digest('hex');

// No source/metadata intake: all bytes below are independently authored templates.
// Seed variation is not independent generator-lineage holdout evidence.
export function corpus(seed: string,pairsPerFamily: number): Fixture[] {
  if (!/^[a-f0-9]{64}$/.test(seed) || !Number.isSafeInteger(pairsPerFamily) || pairsPerFamily<1 || pairsPerFamily>250) throw new Error('Invalid corpus parameters');
  const fixtures: Fixture[] = [];
  for (const family of families) for (let pair=0;pair<pairsPerFamily;pair++) {
    const salt = digest(`${seed}:${family}:${pair}`).slice(0,12), name = `f_${salt}`;
    for (const buggy of [true,false]) {
      let files: Record<string,string>, fixedFiles: Record<string,string>, entry: string, expression: string, expected: unknown, changedFiles: string[];
      if (family === 'amount-unit') {
        const amount = parseInt(salt.slice(0,4),16)+1;
        entry = 'invoice.js'; changedFiles=['pricing.js'];
        const dependency = `export const ${name} = units => units * 100;\n`;
        const fixed = `import { ${name} } from './pricing.js';\nexport const run = units => ${name}(units);\n`;
        files = { 'pricing.js':dependency,[entry]:buggy ? fixed.replace(`${name}(units);`,`${name}(units) * 100;`) : fixed };
        fixedFiles = { ...files,[entry]:fixed }; expression=`run(${amount})`; expected=amount*100;
      } else if (family === 'tenant-cache') {
        entry='cache.js'; changedFiles=[entry];
        const fixed = `const ${name} = new Map();\nexport function run() {\n  function read(tenant, id, value) {\n    const key = JSON.stringify([tenant, id]);\n    if (!${name}.has(key)) ${name}.set(key, value);\n    return ${name}.get(key);\n  }\n  return [read('alpha', '${salt}', 'alpha-only'), read('beta', '${salt}', 'beta-only')];\n}\n`;
        files = { [entry]:buggy ? fixed.replace('JSON.stringify([tenant, id])','id') : fixed };
        fixedFiles = { [entry]:fixed }; expression='run()'; expected=['alpha-only','beta-only'];
      } else if (family === 'path-boundary') {
        entry='paths.js'; changedFiles=[entry];
        const fixed = `import { resolve, sep } from 'node:path';\nexport function run(candidate) {\n  const root = resolve('/workspace/${salt}');\n  const path = resolve(root, candidate);\n  return path === root || path.startsWith(root + sep);\n}\n`;
        files = { [entry]:buggy ? fixed.replace('path === root || path.startsWith(root + sep)','path.startsWith(root)') : fixed };
        fixedFiles = { [entry]:fixed }; expression=`[run('../${salt}-neighbor/secret'), run('src/main.js'), run('../../outside')]`; expected=[false,true,false];
      } else {
        entry='expiry.js'; changedFiles=[entry];
        const expires = parseInt(salt.slice(0,6),16)+100;
        const fixed = `export function run(now, expires) { return now < expires; }\n`;
        files = { [entry]:buggy ? fixed.replace('now < expires','now <= expires') : fixed };
        fixedFiles = { [entry]:fixed }; expression=`[run(${expires-1},${expires}),run(${expires},${expires}),run(${expires+1},${expires})]`; expected=[true,false,false];
      }
      const id = digest(JSON.stringify([family,seed,pair,buggy,files]));
      fixtures.push({ input:{ schema:'sentinel-practice-input/v1',id,files,changedFiles },family,buggy,defectPath:entry,fixedFiles,oracle:{ entry,expression,expected } });
    }
  }
  return fixtures;
}

export async function proveFixture(fixture: Fixture) {
  // This runner executes this module's trusted templates only. Never pass miner
  // files or customer code here: subprocess != hostile-code sandbox.
  const directory = await mkdtemp(join(tmpdir(),'sentinel-oracle-'));
  const execute = async (files: Record<string,string>) => {
    for (const [path,text] of Object.entries(files)) await writeFile(join(directory,path),text);
    const script = `import { run } from './${fixture.oracle.entry}'; process.stdout.write(JSON.stringify(${fixture.oracle.expression}));`;
    const child = Bun.spawn(['bun','--eval',script],{ cwd:directory,stdout:'pipe',stderr:'ignore',timeout:5000 });
    const output = await new Response(child.stdout).text();
    if (await child.exited !== 0) throw new Error('Oracle execution failed');
    return JSON.parse(output);
  };
  try {
    const observed = await execute(fixture.input.files);
    const corrected = await execute(fixture.fixedFiles);
    const defective = JSON.stringify(observed)!==JSON.stringify(fixture.oracle.expected);
    if (defective !== fixture.buggy || JSON.stringify(corrected)!==JSON.stringify(fixture.oracle.expected)) throw new Error('Oracle did not demonstrate injection and repair');
    return { id:fixture.input.id,buggy:fixture.buggy,observed,corrected,expected:fixture.oracle.expected };
  } finally { await rm(directory,{ recursive:true,force:true }); }
}

if (import.meta.main) {
  const [seed,count] = process.argv.slice(2);
  for (const fixture of corpus(seed,Number(count))) console.log(JSON.stringify(fixture.input));
}
