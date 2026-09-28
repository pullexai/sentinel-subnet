import {boundedFile} from './replay';
import {snapshotByteLimit,type SnapshotExpectation} from './protocol';
import {signPractice} from './validator-attest';
import {parseTranscriptJSON,planTranscripts,TranscriptJournal,transcriptByteLimit,type TranscriptPolicy} from './transcripts';

if(import.meta.main){
  let journal:TranscriptJournal|undefined;
  try{
    const [action,snapshot,policyPath,validator,directory,input,...extra]=process.argv.slice(2);
    const json=async(path:string)=>parseTranscriptJSON(await boundedFile(path,transcriptByteLimit));
    if(action==='plan'){
      // plan SNAPSHOT EXPECTATIONS ROSTER COMMIT_DEADLINE_MS OPENING_DEADLINE_MS
      if(!snapshot || !policyPath || !validator || !directory || !input || extra.length || !/^[1-9][0-9]*$/.test(directory) || !/^[1-9][0-9]*$/.test(input))throw new Error('Usage: validator-transcript.ts plan SNAPSHOT EXPECTATIONS ROSTER COMMIT_DEADLINE_MS OPENING_DEADLINE_MS');
      console.log(JSON.stringify(await planTranscripts(await boundedFile(snapshot,snapshotByteLimit),await json(policyPath) as SnapshotExpectation,await json(validator),Number(directory),Number(input))));
    }else{
      if(!['commit','freeze','open','agree','certify'].includes(action) || !snapshot || !policyPath || !validator || !directory || !input ||
        (['freeze','agree'].includes(action)?extra.length!==1:extra.length!==0))throw new Error('Usage: validator-transcript.ts commit|freeze|open|agree|certify SNAPSHOT POLICY VALIDATOR JOURNAL INPUT [PRIVATE_SEED]');
      const bytes=await boundedFile(snapshot,snapshotByteLimit),policy=await json(policyPath) as TranscriptPolicy;
      journal=await TranscriptJournal.open(directory,policy,validator,bytes);
      const sign=(payload:Uint8Array)=>signPractice(payload,validator,action==='commit'?input:extra[0]);
      const result=action==='commit'?await journal.execute(bytes,sign):action==='freeze'?await journal.freeze(await json(input),sign):
        action==='open'?await journal.opening(await json(input)):action==='agree'?await journal.agree(await json(input),sign):await journal.certify(await json(input));
      console.log(JSON.stringify(result));
    }
  }catch(error){console.error(error instanceof Error?error.message:'Transcript agreement failed');process.exitCode=1;}
  finally{journal?.close();}
}
