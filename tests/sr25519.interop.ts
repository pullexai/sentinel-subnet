// Optional independent native-Python crypto check; application runtime remains Bun.
import {expect,test} from 'bun:test';
import {cryptoWaitReady,sr25519PairFromSeed,sr25519Sign,sr25519Verify} from '@polkadot/util-crypto';
import {randomBytes} from 'node:crypto';

test.skipIf(!process.env.SR25519_PYTHON)('native py-sr25519-bindings verifies Bun signatures and vice versa',async()=>{
  await cryptoWaitReady();
  const pair=sr25519PairFromSeed(randomBytes(32));
  const message=Buffer.from('sentinel/contribution/sr25519/v1\n["independent-runtime-fixture"]');
  const signed=sr25519Sign(message,pair);
  const child=Bun.spawn([process.env.SR25519_PYTHON!,'-c',`
import json,sys,secrets,sr25519,importlib.metadata
assert importlib.metadata.version('py-sr25519-bindings') == '0.2.4'
v=json.load(sys.stdin)
message=bytes.fromhex(v['message'])
assert sr25519.verify(bytes.fromhex(v['signature']),message,bytes.fromhex(v['publicKey']))
public,private=sr25519.pair_from_seed(secrets.token_bytes(32))
print(json.dumps({'publicKey':public.hex(),'signature':sr25519.sign((public,private),message).hex()}))
`],{stdin:'pipe',stdout:'pipe',stderr:'pipe'});
  child.stdin.write(JSON.stringify({message:message.toString('hex'),signature:Buffer.from(signed).toString('hex'),publicKey:Buffer.from(pair.publicKey).toString('hex')}));
  child.stdin.end();
  const output=await new Response(child.stdout).text();
  expect(await child.exited).toBe(0);
  const result=JSON.parse(output);
  expect(sr25519Verify(message,Buffer.from(result.signature,'hex'),Buffer.from(result.publicKey,'hex'))).toBe(true);
});

test.skipIf(!process.env.SR25519_PYTHON)('native Python verifies EC-02 envelope and recomputes JCS bytes independently',async()=>{
  await cryptoWaitReady();
  const {contributionSigningBytes}=await import('../src/engine-contribution');
  const pair=sr25519PairFromSeed(randomBytes(32)),hotkey=Buffer.from(pair.publicKey).toString('hex');
  const payload=JSON.parse(await Bun.file(import.meta.dir+'/fixtures/engine-contribution-payload.json').text());
  payload.submitter.hotkey_public_key=hotkey;
  const message=contributionSigningBytes(payload),signed=Buffer.from(sr25519Sign(message,pair)).toString('hex');
  // Python json.dumps(sort_keys, compact, ensure_ascii=False) equals JCS for this ASCII, string-only payload.
  const child=Bun.spawn([process.env.SR25519_PYTHON!,'-c',`
import json,sys,sr25519
v=json.load(sys.stdin)
m=b'sentinel-engine-contribution/v1\\n'+json.dumps(v['payload'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
assert m.hex()==v['message'],'JCS mismatch'
assert sr25519.verify(bytes.fromhex(v['signature']),m,bytes.fromhex(v['payload']['submitter']['hotkey_public_key']))
print('ok')
`],{stdin:'pipe',stdout:'pipe',stderr:'pipe'});
  child.stdin.write(JSON.stringify({payload,message:message.toString('hex'),signature:signed}));child.stdin.end();
  expect((await new Response(child.stdout).text()).trim()).toBe('ok');
  expect(await child.exited).toBe(0);
});
