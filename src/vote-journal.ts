import {Database} from 'bun:sqlite';
import {lstatSync,mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {quorumPolicyDigest,verifyScoreAttestation,verifyScoreQuorum,type QuorumPolicy,type ScoreAttestation,type ScoreTarget} from './attestations';

export class VoteJournal{
  private db:Database;
  private policy:QuorumPolicy;
  private policySha256:string;
  constructor(directory:string,policy:QuorumPolicy){
    this.policySha256=quorumPolicyDigest(policy);this.policy=structuredClone(policy);
    mkdirSync(directory,{recursive:true,mode:0o700});
    const info=lstatSync(directory);
    if(!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077)throw new Error('Private journal directory required');
    const path=join(directory,'votes.sqlite');
    try{const file=lstatSync(path);if(!file.isFile() || file.isSymbolicLink() || file.nlink!==1)throw new Error('Unsafe journal file');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    this.db=new Database(path,{create:true,strict:true});
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS votes(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,validator TEXT NOT NULL,target TEXT NOT NULL,body TEXT NOT NULL,
        UNIQUE(scope,validator,target));`);
  }
  private scope(target:ScoreTarget){return JSON.stringify([target.genesis,target.netuid,target.round,this.policySha256]);}
  private target(target:ScoreTarget){return JSON.stringify([target.cohortSha256,target.resultSha256]);}
  async observe(value:unknown){
    const vote=await verifyScoreAttestation(value,this.policy),scope=this.scope(vote.target),target=this.target(vote.target);
    return this.db.transaction(()=>{
      const count=(this.db.query('SELECT count(*) AS n FROM votes WHERE scope=? AND validator=?').get(scope,vote.validator) as {n:number}).n;
      const prior=this.db.query('SELECT id FROM votes WHERE scope=? AND validator=? AND target=?').get(scope,vote.validator,target);
      // ponytail: retain the first two distinct signed targets as sufficient equivocation proof; no unbounded conflicting-vote archive.
      if(!prior && count<2)this.db.query('INSERT INTO votes(scope,validator,target,body) VALUES(?,?,?,?)').run(scope,vote.validator,target,JSON.stringify(vote));
      return {validator:vote.validator,equivocated:count>=2 || count===1 && !prior,replay:!!prior};
    }).immediate();
  }
  async certify(expected:ScoreTarget){
    const target=structuredClone(expected),scope=this.scope(target);
    const rows=this.db.query('SELECT id,validator,target,body FROM votes WHERE scope=? ORDER BY id').all(scope) as {id:number;validator:string;target:string;body:string}[];
    const groups=new Map<string,ScoreAttestation[]>();
    for(const row of rows){
      const vote=await verifyScoreAttestation(JSON.parse(row.body),this.policy);
      if(vote.validator!==row.validator || this.scope(vote.target)!==scope || this.target(vote.target)!==row.target)throw new Error('Journal vote integrity failure');
      const group=groups.get(vote.validator)||[];group.push(vote);groups.set(vote.validator,group);
    }
    const evidence=[...groups.entries()].filter(([,votes])=>votes.length>1).map(([validator,votes])=>({validator,votes}));
    const attestations=[...groups.values()].filter(votes=>votes.length===1 && this.target(votes[0].target)===this.target(target)).map(votes=>votes[0]);
    const certificate=await verifyScoreQuorum(attestations,target,this.policy);
    // A conflict arriving during asynchronous verification invalidates this attempt.
    return this.db.transaction(()=>{
      const latest=this.db.query('SELECT id FROM votes WHERE scope=? ORDER BY id').all(scope) as {id:number}[];
      if(JSON.stringify(latest.map(r=>r.id))!==JSON.stringify(rows.map(r=>r.id)))throw new Error('Journal changed during certification; retry');
      return {certificate,attestations,evidence,journalRevision:rows.at(-1)?.id||0};
    }).immediate();
  }
  async equivocations(target:ScoreTarget){
    const scope=this.scope(target);
    const rows=this.db.query('SELECT validator,target,body FROM votes WHERE scope=? ORDER BY validator,id').all(scope) as {validator:string;target:string;body:string}[];
    const groups=new Map<string,ScoreAttestation[]>();
    for(const row of rows){
      const vote=await verifyScoreAttestation(JSON.parse(row.body),this.policy);
      if(vote.validator!==row.validator || this.scope(vote.target)!==scope || this.target(vote.target)!==row.target)throw new Error('Journal vote integrity failure');
      const group=groups.get(vote.validator)||[];group.push(vote);groups.set(vote.validator,group);
    }
    return [...groups.entries()].filter(([,votes])=>votes.length>1).map(([validator,votes])=>({validator,votes}));
  }
  close(){this.db.close();}
}
