import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import * as C from '../shared/contracts.js';

export async function routesRequests(app:ApiApp,context:Context,cookieOptions:{httpOnly:boolean;secure:boolean;sameSite:'lax';path:string}) {
  const {requests,integrations}=context;
  app.get('/api/requests',{schema:{querystring:C.PageQuery,response:{200:C.listOf(C.ApprovalRequest)}}},request=>requests.list(actor(request),request.query.limit,request.query.after));
  app.post('/api/requests',{schema:{body:C.RequestInput,response:{201:C.ApprovalRequest}}},async(request,reply)=>reply.code(201).send(await requests.create(actor(request),request.body)));
  app.get('/api/requests/:id',{schema:{params:C.IdParams,response:{200:C.ApprovalRequest}}},request=>requests.get(request.actor,request.params.id));
  app.post('/api/requests/:id/approve',{schema:{params:C.IdParams,body:z.object({values:z.array(z.record(z.string(),C.Json)).max(8).default([]),code:z.string().max(20).optional()}).strict(),response:{200:C.ApprovalRequest}}},request=>requests.approve(actor(request),request.params.id,request.browser,request.body.values,request.body.code));
  app.post('/api/requests/:id/decline',{schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:C.ApprovalRequest}}},request=>requests.decline(actor(request),request.params.id));
  app.post('/api/requests/:id/cancel',{schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:C.ApprovalRequest}}},request=>requests.cancel(actor(request),request.params.id));
  app.post('/api/requests/:id/links',{schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:z.object({url:z.url(),expiresAt:C.Time})}}},request=>requests.link(actor(request),request.params.id));
  app.post('/api/requests/:id/redeem',{config:{rateLimit:{max:30,timeWindow:'1 hour'}},schema:{params:C.IdParams,body:z.object({token:z.string().max(200)}).strict(),response:{200:C.Ok}}},async(request,reply)=>{const session=await requests.redeem(request.params.id,request.body.token);reply.setCookie('foundation_request',session.token,{...cookieOptions,expires:new Date(session.expiresAt)});return {ok:true as const};});
  app.get('/api/principals/:id/settings',{schema:{params:C.IdParams,response:{200:C.Settings}}},request=>integrations.get(actor(request),request.params.id));
  app.put('/api/principals/:id/settings',{schema:{params:C.IdParams,body:C.Settings,response:{200:z.object({settings:C.Settings,webhookSecret:z.string().optional()})}}},request=>integrations.set(actor(request),request.params.id,request.body));
  app.post('/api/principals/:id/settings/rotate',{schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:z.object({webhookSecret:z.string()})}}},request=>integrations.rotate(actor(request),request.params.id));
}
