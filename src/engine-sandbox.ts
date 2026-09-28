import {admit,mine,type Finding} from './competition';
import {parseInput} from './miner';

// Runs inside the artifact sandbox (see runSandbox in engine-intake.ts). It sees only the sealed
// artifact at /artifact and case inputs on stdin; gold, oracles, lineage and the queue are not mounted.
const [entrypoint]=process.argv.slice(2);
if(!entrypoint || !/^[A-Za-z0-9_][A-Za-z0-9._\/-]*$/.test(entrypoint) || entrypoint.includes('..'))throw new Error('Invalid entrypoint');
// ponytail: practice stand-in adapter reading a `sentinel-literal-miner/v1` entrypoint; real EC-04..07 adapters replace this per format.
const submission=admit(JSON.parse(await Bun.file('/artifact/'+entrypoint).text()));
const inputs=JSON.parse(await Bun.stdin.text());
if(!Array.isArray(inputs) || inputs.length>1000)throw new Error('Invalid case inputs');
const out:Record<string,Finding[]>={};
for(const value of inputs){const input=parseInput(value);out[input.id]=mine(input,submission);}
process.stdout.write(JSON.stringify(out));
