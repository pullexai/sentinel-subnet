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
