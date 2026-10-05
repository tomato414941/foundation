import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import type { Resources } from './resources.js';
import type { HttpExecution } from './http-execution.js';
import type { Environments } from './environments.js';
import type { Inputs } from './inputs.js';
import type { Vault } from './vault.js';
import { iso } from './database.js';
import { Run, RunInput } from '../shared/contracts.js';
import type { NewRun, JsonValue, RunView } from '../shared/contracts.js';
import { redact } from '../shared/values.js';
import { fail, failure, required } from './errors.js';

interface RunRow {id:string;owner_id:string;actor_id:string;resource_id:string|null;kind:'http'|'command'|'function';state:RunView['state'];private_input:string;result:JsonValue|null;error:string|null;created_at:Date;started_at:Date|null;finished_at:Date|null;lease_token:string|null}
interface StoredRun {actor:Actor;input:NewRun}
export class Runs {
  private running=new Map<string,AbortController>();
  constructor(readonly resources:Resources,readonly http:HttpExecution,readonly environments:Environments,readonly inputs:Inputs,readonly vault:Vault) {}
  private view(row:RunRow) {return Run.parse({id:row.id,ownerId:row.owner_id,actorId:row.actor_id,resourceId:row.resource_id,kind:row.kind,state:row.state,result:row.result,error:row.error,createdAt:iso(row.created_at),startedAt:row.started_at?iso(row.started_at):null,finishedAt:row.finished_at?iso(row.finished_at):null});}
  async create(actor:Actor,ownerId:string,input:NewRun) {
    await this.resources.authorization.requirePrincipal(actor,ownerId,'execute');
    let resourceId:string|null=null;
    if(input.kind==='http')await this.http.validate(actor,input.request);
    else {
      resourceId=input.kind==='command'?input.environmentId:input.functionId;
      const resource=await this.resources.get(resourceId);
      if(resource.kind!==(input.kind==='command'?'environment':'function'))fail(400,'wrong_kind','Choose the correct item to run.');
      await this.resources.authorization.requireResource(actor,resource,'execute');
      if(input.kind==='command'&&resource.data.state!=='running')fail(409,'environment_unavailable','Wait for the environment to start.');
    }
    const id=randomUUID();
    const runActor:Actor={id:actor.id,...(actor.credentialId?{credentialId:actor.credentialId}:{}),...(actor.sessionId?{sessionId:actor.sessionId}:{})};
    const row=await this.resources.db.transaction(async connection=>{
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE',[ownerId]);
      const active=await this.resources.db.one<{count:string}>("SELECT count(*) FROM runs WHERE owner_id=$1 AND state IN ('queued','running')",[ownerId],connection);
      if(Number(active?.count)>=20)fail(429,'run_limit','Wait for an existing run to finish.');
      if(input.kind==='command') {
        await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE',[resourceId]);
        const busy=await this.resources.db.one("SELECT 1 FROM runs WHERE resource_id=$1 AND state IN ('queued','running')",[resourceId],connection);
        if(busy)fail(409,'environment_busy','Wait for the current command to finish.');
      }
      const row=required(await this.resources.db.one<RunRow>("INSERT INTO runs(id,owner_id,actor_id,resource_id,kind,state,private_input) VALUES($1,$2,$3,$4,$5,'queued',$6) RETURNING *",[id,ownerId,actor.id,resourceId,input.kind,await this.vault.encrypt({actor:runActor,input},'run:'+id)],connection));
      await this.resources.audit.record(ownerId,actor.id,'run.create',id,{kind:input.kind},connection);return row;
    });
    return this.view(row);
  }
  async get(actor:Actor,id:string) {const row=required(await this.resources.db.one<RunRow>('SELECT * FROM runs WHERE id=$1',[id]));await this.resources.authorization.requirePrincipal(actor,row.owner_id,'read');return this.view(row);}
  async list(actor:Actor,ownerId:string,limit=100,after?:string) {
    await this.resources.authorization.requirePrincipal(actor,ownerId,'read');
    const rows=await this.resources.db.all<RunRow>('SELECT * FROM runs WHERE owner_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3',[ownerId,after??null,limit+1]);
    return {items:rows.slice(0,limit).map(row=>this.view(row)),next:rows.length>limit?rows[limit-1]!.id:null};
  }
  async cancel(actor:Actor,id:string) {
    const row=required(await this.resources.db.one<RunRow>('SELECT * FROM runs WHERE id=$1',[id]));await this.resources.authorization.requirePrincipal(actor,row.owner_id,'execute');
    await this.resources.db.pool.query("UPDATE runs SET state='cancelled',finished_at=now(),private_input='',lease_until=NULL WHERE id=$1 AND state IN ('queued','running')",[id]);
    this.running.get(id)?.abort();
    if(row.kind==='command'&&row.resource_id)await this.environments.requestStop(row.resource_id);
    return this.get(actor,id);
  }
  async recover() {
    const rows=await this.resources.db.all<{resource_id:string|null;kind:string}>("UPDATE runs SET state='failed',error='The server interrupted this run. Check the destination before trying again.',finished_at=now(),private_input='',lease_until=NULL WHERE state='running' AND lease_until<now() RETURNING resource_id,kind");
    for(const row of rows)if(row.kind==='command'&&row.resource_id)await this.environments.requestStop(row.resource_id);
  }
  async tick() {
    const lease=randomUUID();
    const row=await this.resources.db.one<RunRow>(`UPDATE runs SET state='running',started_at=now(),lease_until=now()+interval '1 minute',lease_token=$1 WHERE id=(SELECT id FROM runs WHERE state='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *`,[lease]);
    if(!row)return false;
    const controller=new AbortController();this.running.set(row.id,controller);
    const heartbeat=setInterval(()=>{void (async()=>{
      const saved=await this.resources.db.one<{state:string}>('UPDATE runs SET lease_until=now()+interval \'1 minute\' WHERE id=$1 AND lease_token=$2 AND state=\'running\' RETURNING state',[row.id,lease]);
      if(!saved)controller.abort();
    })().catch(()=>controller.abort());},10_000);heartbeat.unref();
    try {
      const stored=await this.vault.decrypt<StoredRun>(row.private_input,'run:'+row.id),input=RunInput.parse(stored.input),actor=stored.actor;
      await this.resources.authorization.requirePrincipal(actor,row.owner_id,'execute');
      controller.signal.throwIfAborted();
      let result:JsonValue;
      if(input.kind==='http')result=await this.http.request(actor,row.owner_id,input.request,input.save,controller.signal);
      else if(input.kind==='function')result=await this.http.invoke(actor,await this.resources.get(input.functionId),input.arguments,controller.signal);
      else {
        const values=await this.inputs.process(actor,input.inputs);
        const command=await this.environments.execute(actor,input.environmentId,{command:input.command,timeoutSeconds:input.timeoutSeconds,...(input.stdin!==undefined?{stdin:input.stdin}:{}),environment:values.environment,files:values.files},controller.signal);
        result={...command,stdout:redact(command.stdout,values.sensitive),stderr:redact(command.stderr,values.sensitive)};
      }
      await this.resources.db.pool.query("UPDATE runs SET state='succeeded',result=$3,finished_at=now(),lease_until=NULL,private_input='' WHERE id=$1 AND lease_token=$2 AND state='running'",[row.id,lease,JSON.stringify(result)]);
    } catch(error) {
      const message=controller.signal.aborted?'The run was cancelled.':failure(error).message;
      await this.resources.db.pool.query("UPDATE runs SET state=$3,error=$4,finished_at=now(),lease_until=NULL,private_input='' WHERE id=$1 AND lease_token=$2 AND state='running'",[row.id,lease,controller.signal.aborted?'cancelled':'failed',message]);
    } finally {clearInterval(heartbeat);this.running.delete(row.id);}
    return true;
  }
  async shutdown() {for(const controller of this.running.values())controller.abort();}
}
