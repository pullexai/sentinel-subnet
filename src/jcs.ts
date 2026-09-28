// RFC 8785 JSON Canonicalization Scheme plus a strict, bounded I-JSON parser.
// JSON.parse is unsuitable for signed input: it silently keeps the last duplicate key
// and accepts escaped lone surrogates.
const fail=(message:string):never=>{throw new Error('JCS: '+message);};

export function jcs(value:unknown):string{
  if(value===null || typeof value==='boolean')return String(value);
  // ECMAScript Number::toString, as required by RFC 8785 §3.2.2.3; -0 serializes as 0.
  if(typeof value==='number')return Number.isFinite(value)?JSON.stringify(value):fail('non-finite number');
  // JSON.stringify string escaping is RFC 8785 §3.2.2.2 once lone surrogates are excluded.
  if(typeof value==='string')return value.isWellFormed()?JSON.stringify(value):fail('lone surrogate');
  if(Array.isArray(value))return '['+Array.from(value,jcs).join(',')+']';
  if(typeof value==='object' && [Object.prototype,null].includes(Object.getPrototypeOf(value))){
    const record=value as Record<string,unknown>;
    // Default sort compares UTF-16 code units, exactly RFC 8785 §3.2.3.
    return '{'+Object.keys(record).sort().map(k=>jcs(k)+':'+jcs(record[k])).join(',')+'}';
  }
  return fail('unsupported value');
}
export const jcsBytes=(value:unknown)=>Buffer.from(jcs(value),'utf8');

export function parseJson(bytes:Uint8Array,limit:number,maxDepth=64):unknown{
  if(bytes.length>limit)fail('byte limit');
  let text='';
  try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{fail('invalid UTF-8');}
  let i=0;
  const ws=()=>{while(text[i]===' ' || text[i]==='\t' || text[i]==='\n' || text[i]==='\r')i++;};
  const expect=(c:string)=>{if(text[i]!==c)fail(`expected ${c} at ${i}`);i++;};
  const escapes:Record<string,string>={'"':'"','\\':'\\','/':'/',b:'\b',f:'\f',n:'\n',r:'\r',t:'\t'};
  const string=()=>{
    expect('"');let out='';
    for(;;){
      const c=text[i++];
      if(c===undefined)fail('unterminated string');
      if(c==='"')break;
      if(c<' ')fail('control character in string');
      if(c!=='\\'){out+=c;continue;}
      const e=text[i++];
      if(e==='u'){const h=text.slice(i,i+4);if(!/^[0-9a-fA-F]{4}$/.test(h))fail('bad unicode escape');out+=String.fromCharCode(parseInt(h,16));i+=4;}
      else if(e!==undefined && Object.hasOwn(escapes,e))out+=escapes[e];
      else fail('bad escape');
    }
    return out.isWellFormed()?out:fail('lone surrogate');
  };
  const number=/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  const value=(depth:number):unknown=>{
    if(depth>maxDepth)fail('depth limit');
    ws();const c=text[i];
    if(c==='{'){
      i++;const out:Record<string,unknown>={};const seen=new Set<string>();ws();
      if(text[i]==='}'){i++;return out;}
      for(;;){
        ws();const key=string();if(seen.has(key))fail('duplicate key');seen.add(key);
        ws();expect(':');
        // defineProperty keeps "__proto__" an ordinary data key.
        Object.defineProperty(out,key,{value:value(depth+1),enumerable:true,writable:true,configurable:true});
        ws();if(text[i]===','){i++;continue;}expect('}');return out;
      }
    }
    if(c==='['){
      i++;const out:unknown[]=[];ws();
      if(text[i]===']'){i++;return out;}
      for(;;){out.push(value(depth+1));ws();if(text[i]===','){i++;continue;}expect(']');return out;}
    }
    if(c==='"')return string();
    for(const [word,literal] of [['true',true],['false',false],['null',null]] as const)if(text.startsWith(word,i)){i+=word.length;return literal;}
    number.lastIndex=i;const match=number.exec(text);
    if(!match)fail(`unexpected token at ${i}`);
    i+=match![0].length;const n=Number(match![0]);
    return Number.isFinite(n)?n:fail('number out of IEEE 754 range');
  };
  const result=value(0);ws();
  if(i!==text.length)fail('trailing data');
  return result;
}
// Signed wire bytes must already be canonical: one accepted byte string per value.
export function parseCanonical(bytes:Uint8Array,limit:number):unknown{
  const value=parseJson(bytes,limit);
  if(Buffer.compare(jcsBytes(value),Buffer.from(bytes.buffer,bytes.byteOffset,bytes.byteLength)))fail('noncanonical bytes');
  return value;
}
