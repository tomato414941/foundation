import { Template } from '@fedify/uri-template';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Inputs } from './inputs.js';
import type { Transport } from './transport.js';
import { publicUrl } from './transport.js';
import { FunctionDefinition, HttpRequest } from '../shared/contracts.js';
import type { FunctionSpec, HttpRequestInput, JsonValue } from '../shared/contracts.js';
import { atPointer, setPointer, pointerParts, redact } from '../shared/values.js';
import { fail } from './errors.js';
import { encode } from '../shared/encryption.js';

export class HttpExecution {
  constructor(readonly resources:Resources,readonly inputs:Inputs,readonly transport:Transport,readonly origin:string) {}
  references(spec:HttpRequestInput):string[] { return spec.bindings.flatMap(binding=>binding.parts.flatMap(part=>typeof part==='string'?[]:[part.id])); }
  async validate(actor:Actor,spec:HttpRequestInput) {
    publicUrl(spec.url,this.origin);
    if([spec.body,spec.json,spec.form].filter(value=>value!==undefined).length>1) fail(400,'multiple_bodies','Choose one request body format.');
    for(const binding of spec.bindings) {
      let parts:string[];
      try {parts=pointerParts(binding.pointer);} catch {fail(400,'invalid_binding','Choose a field in the headers or body.');}
      if(!parts.length || !['headers','body','json','form'].includes(parts[0]!) || parts[0]==='body'&&parts.length!==1 || ['headers','form'].includes(parts[0]!)&&parts.length!==2) fail(400,'invalid_binding','Choose a field in the headers or body.');
      for(const part of binding.parts) if(typeof part!=='string') {
        const row=await this.resources.get(part.id);
        if(row.kind!==part.kind) fail(400,'wrong_kind','Choose a secret or connection.');
        await this.resources.authorization.requireResource(actor,row,'use');
      }
    }
  }
  async request(actor:Actor,ownerId:string,input:HttpRequestInput,save:Record<string,string>={},signal?:AbortSignal):Promise<JsonValue> {
    const spec=structuredClone(input); await this.validate(actor,spec);
    const sensitive:string[]=[],resolve=this.inputs.resolver(actor);
    for(const binding of spec.bindings) {
      let value='';
      for(const part of binding.parts) {
        if(typeof part==='string') value+=part;
        else {const text=this.inputs.utf8(await resolve(part));sensitive.push(text);value+=text;}
      }
      try {setPointer(spec,binding.pointer,value);} catch {fail(400,'invalid_binding','The binding target was not found in the request.');}
    }
    let body=spec.body;
    if(spec.json!==undefined) {body=JSON.stringify(spec.json);spec.headers['content-type']='application/json';}
    if(spec.form!==undefined) {body=new URLSearchParams(spec.form).toString();spec.headers['content-type']='application/x-www-form-urlencoded';}
    const response=await this.transport.send({url:spec.url,method:spec.method,headers:spec.headers,...(body!==undefined?{body}:{}),...(signal?{signal}:{})});
    const text=Buffer.from(response.body).toString('utf8'),saved:Record<string,string>={};
    if(Object.keys(save).length) {
      if(response.status>=400) fail(502,'service_response','The service returned an unsuccessful response.');
      let json:unknown;
      for(const [pointer,name] of Object.entries(save)) {
        let bytes=response.body;
        if(pointer!=='') {
          try {json ??= JSON.parse(text);const selected=atPointer(json,pointer);if(selected===undefined) throw new Error();bytes=encode(typeof selected==='string'?selected:JSON.stringify(selected));} catch {fail(400,'invalid_pointer','The selected response value was not found.');}
        }
        const row=await this.inputs.keep(actor,ownerId,name,bytes);saved[name]=row.id;
      }
    }
    const headers=Object.fromEntries(Object.entries(response.headers).map(([key,value])=>[key,redact(value,sensitive)]));
    return {status:response.status,headers,...(Object.keys(save).length?{saved}:{body:redact(text,sensitive)})};
  }
  async validateFunction(actor:Actor,definition:FunctionSpec) {
    const spec=FunctionDefinition.parse(definition),names=new Set<string>();
    for(const parameter of spec.parameters) {if(names.has(parameter.name)) fail(400,'duplicate_parameter','Use unique parameter names.');names.add(parameter.name);}
    const url=new URL(spec.request.url.replace(/\{[^}]+\}/g,'placeholder'));
    if(url.host.includes('placeholder')) fail(400,'variable_origin','The function must have a fixed destination host.');
    const filled=this.arguments(spec,Object.fromEntries(spec.parameters.map(parameter=>[parameter.name,'example'])));
    await this.validate(actor,filled);
    return spec;
  }
  async create(actor:Actor,ownerId:string,name:string,definition:FunctionSpec) {
    if(!await this.resources.authorization.canCreate(actor,ownerId,'function')) fail(403,'forbidden','You cannot create functions for this principal.');
    const spec=await this.validateFunction(actor,definition);
    // The owner provides the authority each invocation uses. Validate its sources before publishing.
    await this.validate({id:ownerId},this.arguments(spec,Object.fromEntries(spec.parameters.map(parameter=>[parameter.name,'example']))));
    return this.resources.db.transaction(connection=>this.resources.insert(ownerId,'function',name,spec as unknown as Record<string,JsonValue>,{references:this.references(spec.request)},connection));
  }
  arguments(spec:FunctionSpec,args:Record<string,string>):HttpRequestInput {
    const values:Record<string,string>={};
    if(Object.keys(args).some(name=>!spec.parameters.some(parameter=>parameter.name===name))) fail(400,'unknown_argument','Use the parameters this function declares.');
    for(const parameter of spec.parameters) {
      const value=args[parameter.name] ?? parameter.default ?? '';
      if(parameter.required&&!value) fail(400,'missing_argument','Complete the required function parameters.');
      if(value.length>8192) fail(400,'argument_limit','The function argument is too long.');
      values[parameter.name]=value;
    }
    const substitute=(value:JsonValue):JsonValue=>{
      if(typeof value==='string') return value.replace(/\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/g,(_match,name:string)=>{if(!Object.hasOwn(values,name)) fail(400,'unknown_argument','Declare every function parameter.');return values[name]!;});
      if(Array.isArray(value)) return value.map(substitute);
      if(value&&typeof value==='object') return Object.fromEntries(Object.entries(value).map(([key,child])=>[key,substitute(child)]));
      return value;
    };
    let url:string;
    try { url=new Template(spec.request.url).expand(values); } catch {fail(400,'invalid_template','Check the function URL template.');}
    const result=HttpRequest.parse({...substitute(spec.request as unknown as JsonValue) as Record<string,JsonValue>,url,bindings:spec.request.bindings});
    const fixed=new URL(spec.request.url.replace(/\{[^}]+\}/g,'placeholder'));
    if(new URL(url).origin!==fixed.origin) fail(400,'variable_origin','The function must have a fixed destination host.');
    return result;
  }
  async invoke(actor:Actor,row:ResourceRow,args:Record<string,string>,signal?:AbortSignal) {
    if(row.kind!=='function') fail(400,'wrong_kind','This item is not a function.');
    await this.resources.authorization.requireResource(actor,row,'execute');
    const spec=FunctionDefinition.parse(row.data);
    return this.request({id:row.owner_id},row.owner_id,this.arguments(spec,args),spec.save,signal);
  }
}
