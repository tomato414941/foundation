import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

interface Job {command:string[];stdin?:string;timeoutSeconds:number;environment:Record<string,string>;files:Record<string,string>}
export async function runAgent(directory:string) {
  const job=JSON.parse(await readFile(join(directory,'input.json'),'utf8')) as Job;
  const environment={...process.env,...job.environment};
  await mkdir(join(directory,'files'),{recursive:true,mode:0o700});
  for(const [name,data] of Object.entries(job.files)) {
    if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))throw new Error('Invalid file variable.');
    const path=join(directory,'files',name);await writeFile(path,Buffer.from(data,'base64'),{mode:0o600});environment[name]=path;
  }
  const output:{exitCode:number|null;stdout:string;stderr:string;timedOut:boolean;truncated:boolean}={exitCode:null,stdout:'',stderr:'',timedOut:false,truncated:false};
  await new Promise<void>(resolve=>{
    let finished=false;
    const child=spawn(job.command[0]!,job.command.slice(1),{env:environment,detached:true,stdio:['pipe','pipe','pipe'],cwd:process.env.HOME??'/tmp'});
    let total=0;
    const collect=(target:'stdout'|'stderr',chunk:string)=>{const remaining=1_000_000-total;if(remaining<=0){output.truncated=true;return;}const text=chunk.slice(0,remaining);output[target]+=text;total+=text.length;if(text.length<chunk.length)output.truncated=true;};
    child.stdout.setEncoding('utf8').on('data',(chunk:string)=>collect('stdout',chunk));
    child.stderr.setEncoding('utf8').on('data',(chunk:string)=>collect('stderr',chunk));
    child.stdin.on('error',()=>{});child.stdin.end(job.stdin??'');
    const finish=()=>{if(finished)return;finished=true;clearTimeout(timer);resolve();};
    child.once('error',()=>{output.exitCode=127;output.stderr='The command could not be started.';finish();});
    child.once('close',code=>{output.exitCode=code;finish();});
    const timer=setTimeout(()=>{output.timedOut=true;try{if(child.pid)process.kill(-child.pid,'SIGKILL');}catch{}setTimeout(finish,2000).unref();},job.timeoutSeconds*1000);
  });
  await writeFile(join(directory,'result.tmp'),JSON.stringify(output),{mode:0o600});
  await rename(join(directory,'result.tmp'),join(directory,'result.json'));
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href && process.argv[2]) await runAgent(process.argv[2]);
