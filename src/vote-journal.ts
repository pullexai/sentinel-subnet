import {Database} from 'bun:sqlite';
import {lstatSync,mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {quorumPolicyDigest,scoreTarget,scoreAttestationPayload,verifyScoreAttestation,verifyScoreQuorum,type QuorumPolicy,type ScoreAttestation,type ScoreTarget} from './attestations';
import {evaluateSnapshot,type SnapshotExpectation} from './protocol';

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
        UNIQUE(scope,validator,target));
      CREATE TABLE IF NOT EXISTS signing_locks(scope TEXT NOT NULL,validator TEXT NOT NULL,target TEXT NOT NULL,vote TEXT,
        PRIMARY KEY(scope,validator));
      CREATE TRIGGER IF NOT EXISTS signing_lock_no_delete BEFORE DELETE ON signing_locks BEGIN SELECT RAISE(ABORT,'Signing locks are permanent'); END;
      CREATE TRIGGER IF NOT EXISTS signing_lock_no_rebind BEFORE UPDATE ON signing_locks
        WHEN NEW.scope<>OLD.scope OR NEW.validator<>OLD.validator OR NEW.target<>OLD.target OR OLD.vote IS NOT NULL
        BEGIN SELECT RAISE(ABORT,'Signing locks are immutable'); END;
      CREATE TRIGGER IF NOT EXISTS signing_lock_no_replace BEFORE INSERT ON signing_locks
        WHEN EXISTS(SELECT 1 FROM signing_locks WHERE scope=NEW.scope AND validator=NEW.validator)
        BEGIN SELECT RAISE(ABORT,'Signing locks cannot be replaced'); END;`);
  }
  private scope(target:ScoreTarget){return JSON.stringify([target.genesis,target.netuid,target.round,this.policySha256]);}
  private target(target:ScoreTarget){return JSON.stringify([target.cohortSha256,target.resultSha256]);}
  async evaluateAndSign(bytes:Uint8Array,expected:SnapshotExpectation,validator:string,sign:(payload:Uint8Array)=>Promise<string>){
    if(!this.policy.validators.includes(validator))throw new Error('Untrusted signing validator');
    // Recompute from separately trusted frozen inputs; received scores are never signing inputs.
    const report=await evaluateSnapshot(bytes,expected),target=scoreTarget(report),scope=this.scope(target),identity=this.target(target);
    const stored=this.db.transaction(()=>{
      const prior=this.db.query('SELECT target,vote FROM signing_locks WHERE scope=? AND validator=?').get(scope,validator) as {target:string;vote:string|null}|null;
      if(prior && prior.target!==identity)throw new Error('Conflicting signing target');
      if(!prior)this.db.query('INSERT INTO signing_locks(scope,validator,target) VALUES(?,?,?)').run(scope,validator,identity);
      return prior?.vote;
    }).immediate();
    // The FULL-synchronized lock survives a crash or lost response from the signer.
    // Retrying the same target is allowed; no recovery path chooses a different one.
    const candidate=stored?JSON.parse(stored):{schema:'sentinel-score-attestation/v1',target,policySha256:this.policySha256,validator,
      signature:await sign(scoreAttestationPayload(target,this.policySha256,validator))};
    const verified=await verifyScoreAttestation(candidate,this.policy);
    if(verified.validator!==validator || this.scope(verified.target)!==scope || this.target(verified.target)!==identity)throw new Error('Stored signing vote mismatch');
    const vote=this.db.transaction(()=>{
      const row=this.db.query('SELECT target,vote FROM signing_locks WHERE scope=? AND validator=?').get(scope,validator) as {target:string;vote:string|null}|null;
      if(!row || row.target!==identity)throw new Error('Signing lock changed');
      if(row.vote)return JSON.parse(row.vote) as ScoreAttestation;
      this.db.query('UPDATE signing_locks SET vote=? WHERE scope=? AND validator=?').run(JSON.stringify(verified),scope,validator);
      return verified;
    }).immediate();
    await this.observe(vote);
    return {target,vote,report};
  }
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
