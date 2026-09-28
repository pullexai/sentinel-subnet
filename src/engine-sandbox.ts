import {runProfile,validateProfile} from './engine-retrieval';
import {parseJson} from './jcs';

// Runs inside the artifact sandbox (see runSandbox in engine-intake.ts). It sees only the sealed
// artifact at /artifact and `sentinel-engine-case/v1` bundles on stdin; gold, oracles, lineage and the queue are not mounted.
const [mode,entrypoint]=process.argv.slice(2);
if(!entrypoint || !/^[A-Za-z0-9_][A-Za-z0-9._\/-]*$/.test(entrypoint) || entrypoint.includes('..'))throw new Error('Invalid entrypoint');
const artifact=new Uint8Array(await Bun.file('/artifact/'+entrypoint).arrayBuffer());
const bundles=parseJson(new Uint8Array(await Bun.stdin.arrayBuffer()),64<<20);
if(!Array.isArray(bundles) || bundles.length>1000)throw new Error('Invalid case inputs');
if(mode==='retrieval-profile/v1'){
  const profile=validateProfile(artifact);
  process.stdout.write(JSON.stringify(bundles.map(b=>runProfile(profile,b))));
}else throw new Error('Unknown adapter');
