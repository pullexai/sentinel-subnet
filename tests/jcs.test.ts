import {expect,test} from 'bun:test';
import {readdirSync,readFileSync} from 'node:fs';
import {jcs,jcsBytes,parseCanonical,parseJson} from '../src/jcs';

// tests/fixtures/jcs: testdata/{input,output} copied unmodified from the RFC 8785 author's reference
// repository https://github.com/cyberphone/json-canonicalization at 19d51d7fe467d4706a3ff08adf8a748f29fc21e0
// (Apache-2.0, Copyright 2018 Anders Rundgren).
const dir=new URL('./fixtures/jcs/',import.meta.url).pathname;
test('reference repository vectors',()=>{
  const names=readdirSync(dir+'input');expect(names.length).toBe(6);
  for(const name of names){
    const out=readFileSync(dir+'output/'+name);
    expect(jcsBytes(parseJson(readFileSync(dir+'input/'+name),1<<20))).toEqual(out);
    expect(jcs(parseCanonical(out,1<<20))).toBe(out.toString('utf8'));
  }
});

test('RFC 8785 §3.2.3 sorting and §3.2.4 UTF-8 bytes',()=>{
  const sample=parseJson(Buffer.from(String.raw`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`),1024);
  // Read values textually: JSON.parse would move the integer-like key "1" first.
  expect([...jcs(sample).matchAll(/:"([^"]*)"/g)].map(m=>m[1])).toEqual(['Carriage Return','One','Control','Latin Small Letter O With Diaeresis','Euro Sign','Emoji: Grinning Face','Hebrew Letter Dalet With Dagesh']);
  const input=String.raw`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`;
  const hex=`7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72 75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
    5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31 65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
    5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30 30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d`;
  expect(jcsBytes(parseJson(Buffer.from(input),1024)).toString('hex')).toBe(hex.replace(/\s/g,''));
});

test('RFC 8785 Appendix B number samples',()=>{
  const samples:[string,string|null][]=[['0000000000000000','0'],['8000000000000000','0'],['0000000000000001','5e-324'],['8000000000000001','-5e-324'],
    ['7fefffffffffffff','1.7976931348623157e+308'],['ffefffffffffffff','-1.7976931348623157e+308'],['4340000000000000','9007199254740992'],
    ['c340000000000000','-9007199254740992'],['4430000000000000','295147905179352830000'],['7fffffffffffffff',null],['7ff0000000000000',null],
    ['44b52d02c7e14af5','9.999999999999997e+22'],['44b52d02c7e14af6','1e+23'],['44b52d02c7e14af7','1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e','999999999999999700000'],['444b1ae4d6e2ef4f','999999999999999900000'],['444b1ae4d6e2ef50','1e+21'],
    ['3eb0c6f7a0b5ed8c','9.999999999999997e-7'],['3eb0c6f7a0b5ed8d','0.000001'],['41b3de4355555553','333333333.3333332'],
    ['41b3de4355555554','333333333.33333325'],['41b3de4355555555','333333333.3333333'],['41b3de4355555556','333333333.3333334'],
    ['41b3de4355555557','333333333.33333343'],['becbf647612f3696','-0.0000033333333333333333'],['43143ff3c1cb0959','1424953923781206.2']];
  for(const [ieee,expected] of samples){
    const n=Buffer.from(ieee,'hex').readDoubleBE();
    if(expected===null)expect(()=>jcs(n)).toThrow('non-finite');else expect(jcs(n)).toBe(expected);
  }
  expect(()=>jcs(-Infinity)).toThrow();
});

test('strict parser and canonical wire rejection',()=>{
  const bad=['{"a":1,"a":1}','{"a":1,"\\u0061":2}','"\\ud800"','["\\udc00x"]','{"a":NaN}','[Infinity]','[1e999]','[01]','[1.]','[+1]',
    '{"a":1,}','[1] 2','"\t"',"{'a':1}",'\ufeff[]'];
  for(const text of bad)expect(()=>parseJson(Buffer.from(text),1024)).toThrow('JCS');
  expect(()=>parseJson(Buffer.from([0x22,0xc3,0x28,0x22]),16)).toThrow('UTF-8');
  expect(()=>parseJson(Buffer.from('[]'),1)).toThrow('byte limit');
  expect(()=>parseJson(Buffer.from('['.repeat(100)+']'.repeat(100)),1024)).toThrow('depth');
  for(const text of ['{"b":1,"a":2}','{"a": 1}','[-0]','[1.0]','[1E2]','["\\u0041"]','["\\/"]','{"a":1}\n'])expect(()=>parseCanonical(Buffer.from(text),1024)).toThrow('noncanonical');
  expect(jcs(parseJson(Buffer.from('[-0]'),16))).toBe('[0]');
  const proto=parseCanonical(Buffer.from('{"__proto__":{"x":1}}'),64) as Record<string,unknown>;
  expect(Object.keys(proto)).toEqual(['__proto__']);expect(jcs(proto)).toBe('{"__proto__":{"x":1}}');
  for(const value of ['\ud800',NaN,1n,undefined,new Date(0),[()=>1]])expect(()=>jcs(value)).toThrow();
});
