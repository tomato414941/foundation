import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import type { Resources } from './resources.js';
import type { Services } from './services.js';
import type { InjectionInput, SourceReference, JsonValue } from '../shared/contracts.js';
import { atPointer, textValue } from '../shared/values.js';
import { decode, encode } from '../shared/encryption.js';
import { fail } from './errors.js';
import { PublicKey } from '../shared/contracts.js';

export interface ProcessInputs { environment:Record<string,string>;files:Record<string,string>;sensitive:string[] }
export class Inputs {
  constructor(readonly resources:Resources,readonly services:Services) { services.resolve=(actor,source)=>this.text(actor,source); }
  resolver(actor:Actor) {
    const connections=new Map<string,Promise<Record<string,string>>>();
    return async (source:SourceReference):Promise<Uint8Array>=>{
      const row=await this.resources.get(source.id);
      if(row.kind!==source.kind) fail(400,'wrong_kind','Choose a secret or connection.');
      await this.resources.authorization.requireResource(actor,row,'use');
      if(source.kind==='secret') {
        await this.resources.authorization.requireResource({id:this.resources.identity.id},row,'use');
        try { return await this.resources.identity.open(row.sealed,'resource:'+row.id); } catch { fail(409,'encryption_access','Allow Foundation to use this secret before using it in tools.'); }
      }
      if(!connections.has(row.id)) connections.set(row.id,this.services.outputs(actor,row));
      const outputs=await connections.get(row.id)!;
      if(!Object.hasOwn(outputs,source.output)) fail(400,'output_not_found','Choose an available connection output.');
      return encode(outputs[source.output]!);
    };
  }
  async text(actor:Actor,source:SourceReference) { return this.utf8(await this.resolver(actor)(source)); }
  utf8(bytes:Uint8Array) { try {return new TextDecoder('utf-8',{fatal:true}).decode(bytes);} catch {fail(400,'binary_value','Use a file to pass binary content.');} }
  async process(actor:Actor,inputs:InjectionInput[]):Promise<ProcessInputs> {
    const environment:Record<string,string>={},files:Record<string,string>={},sensitive:string[]=[],resolve=this.resolver(actor),names=new Set<string>();
    for(const input of inputs) {
      if(names.has(input.name)||/^(FOUNDATION_|LD_|DYLD_)|^(NODE_OPTIONS|BASH_ENV|ENV|PYTHONSTARTUP|GIT_CONFIG_COUNT|GIT_CONFIG_SYSTEM)$/u.test(input.name)) fail(400,'invalid_variable','Use a unique, unreserved environment variable name.');
      names.add(input.name);
      let value=await resolve(input.source);
      if(input.format==='json') {
        try { value=encode(textValue(atPointer(JSON.parse(this.utf8(value)),input.pointer ?? ''))); } catch {fail(400,'invalid_pointer','Choose a text value in the JSON content.');}
      }
      if(input.format==='file') files[input.name]=Buffer.from(value).toString('base64');
      else { const text=this.utf8(value); if(text.includes('\0')) fail(400,'binary_value','Use a file to pass binary content.'); environment[input.name]=text; }
      sensitive.push(Buffer.from(value).toString('utf8'),Buffer.from(value).toString('base64'));
    }
    return {environment,files,sensitive};
  }
  async deliver(actor:Actor,inputs:InjectionInput[]) {
    const principal=await this.resources.principals.get(actor.id);
    const credential=actor.credentialId?await this.resources.db.one<{data:{publicKey?:unknown}}>("SELECT data FROM credentials WHERE id=$1 AND principal_id=$2 AND kind='key'",[actor.credentialId,actor.id]):null;
    const publicKey=credential?.data.publicKey?PublicKey.parse(credential.data.publicKey):principal.public_key;
    if(!publicKey) fail(409,'encryption_key_required','Register an encryption key to receive process inputs.');
    const result=await this.process(actor,inputs),id=randomUUID(),context='injection:'+id;
    const sealed=await this.resources.identity.seal(encode(JSON.stringify({environment:result.environment,files:result.files})),[{id:actor.id,publicKey}],context);
    await this.resources.audit.record(actor.id,actor.id,'inputs.deliver',null,{resources:inputs.map(input=>input.source.id)});
    return {id,context,sealed};
  }
  async keep(actor:Actor,ownerId:string,name:string,bytes:Uint8Array) {
    if(bytes.length>1_000_000) fail(413,'body_limit','The content is too large to keep as a secret.');
    const previous=await this.resources.find(ownerId,'secret',name);
    if(previous) await this.resources.authorization.requireResource(actor,previous,'update');
    else if(!await this.resources.authorization.canCreate(actor,ownerId,'secret')) fail(403,'forbidden','You cannot keep secrets for this principal.');
    const id=previous?.id ?? randomUUID(),recipients=await this.resources.recipients(ownerId);
    if(!recipients.length) fail(409,'encryption_key_required','Add an encryption key before keeping secrets.');
    if(!recipients.some(item=>item.id===this.resources.identity.id)) recipients.push({id:this.resources.identity.id,name:'Foundation',publicKey:this.resources.identity.publicKey});
    const sealed=await this.resources.identity.seal(bytes,recipients,'resource:'+id);
    if(previous) {
      const updated=await this.resources.updateSecret(actor,previous,sealed,bytes.length);
      await this.resources.db.pool.query("INSERT INTO grants(resource_id,principal_id,actions) VALUES($1,$2,ARRAY['use']) ON CONFLICT(resource_id,principal_id) DO UPDATE SET actions=ARRAY['use']",[id,this.resources.identity.id]);
      return updated;
    }
    return this.resources.createSecret(actor,ownerId,{kind:'secret',id,name,sealed,bytes:bytes.length,allowUse:true});
  }
}
