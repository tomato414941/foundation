import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,readFile,writeFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { MemoryPayments,MemoryObjects,MemoryRunner } from './fakes.js';
import { EnvironmentInput,RunInput } from '../shared/contracts.js';

test('実行環境を起動し、一時的な認証情報を停止時に失効させて使用量を記録する',async t=>{
  const f=await fixture(),payments=new MemoryPayments(),runner=new MemoryRunner(),c=await createContext(f.config,{db:f.db,mailer:f.mailer,payments,runner});t.after(()=>f.close());const owner=await f.person();
  await f.db.pool.query("INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active')",[owner.actor.id,'customer-'+owner.actor.id]);
  const row=await c.environments.create(owner.actor,owner.actor.id,EnvironmentInput.parse({identityId:owner.actor.id,lifetime:{maxSeconds:120,idleSeconds:60}}));
  assert.equal(row.data.state,'starting');await c.environments.tick();assert.equal((await c.resources.get(row.id)).data.state,'running');
  const environment=runner.machines.get(row.id)!.environment;assert.equal((await c.authentication.authenticate(environment.FOUNDATION_TOKEN))?.id,owner.actor.id);
  const run=await c.runs.create(owner.actor,owner.actor.id,RunInput.parse({kind:'command',environmentId:row.id,command:['node','--version']}));await c.runs.tick();assert.equal((await c.runs.get(owner.actor,run.id)).state,'succeeded');
  await c.environments.stop(owner.actor,await c.resources.get(row.id));assert.equal(await c.authentication.authenticate(environment.FOUNDATION_TOKEN),null);
  await c.environments.tick();assert.equal((await c.resources.get(row.id)).data.state,'stopped');assert.equal(runner.machines.size,0);
  const usage=await c.billing.usage(owner.actor.id);assert.ok(usage.computeSeconds>=1);await c.billing.report();await c.billing.report();assert.equal(payments.events.length,1);
});

test('ファイルを更新し、同時編集と保存容量の超過を拒否して現在の内容を保持する',async t=>{
  const f=await fixture(),storage=new MemoryObjects(),c=await createContext(f.config,{db:f.db,mailer:f.mailer,payments:new MemoryPayments(),storage});t.after(()=>f.close());const owner=await f.person();
  await f.db.pool.query("INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active')",[owner.actor.id,'customer-'+owner.actor.id]);
  await c.billing.limits(owner.actor,owner.actor.id,10,3600);
  const first=await c.objects.upload(owner.actor,owner.actor.id,'note.txt',Buffer.from('one'),'text/plain');
  const updated=await c.objects.upload(owner.actor,owner.actor.id,'note.txt',Buffer.from('two'),'text/plain',first);
  await assert.rejects(()=>c.objects.upload(owner.actor,owner.actor.id,'note.txt',Buffer.from('old'),'text/plain',first),{code:'changed'});
  assert.equal(Buffer.from(await c.objects.content(owner.actor,updated)).toString(),'two');
  await assert.rejects(()=>c.objects.upload(owner.actor,owner.actor.id,'large.txt',Buffer.from('more than ten bytes'),'text/plain'),{code:'storage_limit'});
  await c.objects.remove(owner.actor,updated);assert.equal(storage.files.size,0);
});

test('ワーカーが実行を一度だけ取得し、再起動で中断した処理を終了として記録する',async t=>{
  const f=await fixture(),c=await createContext(f.config,{db:f.db,mailer:f.mailer,transport:{async send(){return {status:200,headers:{},body:Buffer.from('result')};}}});t.after(()=>f.close());const owner=await f.person();
  const run=await c.runs.create(owner.actor,owner.actor.id,RunInput.parse({kind:'http',request:{url:'https://api.example.com'}}));
  assert.deepEqual((await Promise.all([c.runs.tick(),c.runs.tick()])).sort(),[false,true]);assert.equal((await c.runs.get(owner.actor,run.id)).state,'succeeded');
  const interrupted=await c.runs.create(owner.actor,owner.actor.id,RunInput.parse({kind:'http',request:{url:'https://api.example.com'}}));
  await f.db.pool.query("UPDATE runs SET state='running',lease_until=now()-interval '1 minute' WHERE id=$1",[interrupted.id]);await c.runs.recover();assert.equal((await c.runs.get(owner.actor,interrupted.id)).state,'failed');
});

test('実行用プログラムが環境変数とファイルと標準入力を渡し、終了結果を記録する',async t=>{
  const directory=await mkdtemp(join(tmpdir(),'foundation-agent-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  await writeFile(join(directory,'input.json'),JSON.stringify({command:[process.execPath,'-e',"const fs=require('node:fs');process.stdout.write(process.env.VALUE+'|'+fs.readFileSync(process.env.DATA_FILE)+'|'+fs.readFileSync(0));"],stdin:'input',timeoutSeconds:10,environment:{VALUE:'value'},files:{DATA_FILE:Buffer.from('file').toString('base64')}}));
  await promisify(execFile)(process.execPath,['server/runner-agent.ts',directory],{cwd:process.cwd()});
  const result=JSON.parse(await readFile(join(directory,'result.json'),'utf8'));assert.equal(result.exitCode,0);assert.equal(result.stdout,'value|file|input');
});
