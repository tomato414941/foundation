import { z } from 'zod';
import { Id, Time } from './contracts.js';

const Text = z.string().refine(value => !value.includes('\0'), 'Use text without null bytes.');
export const WorkingDirectory = Text.max(4096).startsWith('/');
export const ProcessInput = z.object({
  command: z.array(Text.max(8192)).min(1).max(100).refine(value => Boolean(value[0]), 'Specify a program.'),
  workingDirectory: WorkingDirectory.optional(),
  environment: z.record(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/), Text.max(65536))
    .refine(value => Object.keys(value).length <= 128 && JSON.stringify(value).length <= 1_000_000,
      'Use at most 128 environment variables and 1 MB of environment data.').default({}),
  stdin: z.string().max(1_000_000).default(''),
  timeoutSeconds: z.number().int().min(1).max(3600).default(60),
}).strict();
export const CreateProcess = ProcessInput.extend({ id: Id.optional() });
export const ProcessState = z.enum(['queued', 'running', 'succeeded', 'failed', 'cancelled', 'uncertain']);
export const ProcessResult = z.object({
  exitCode: z.number().int().nullable(), signal: z.string().max(32).nullable(),
  stdout: z.string().max(1_000_000), stderr: z.string().max(1_000_000),
  timedOut: z.boolean(), truncated: z.boolean(),
}).strict();
export const ProcessCompletion = z.object({
  state: ProcessState.exclude(['queued', 'running']),
  result: ProcessResult.nullable(), error: z.string().max(100).nullable(),
}).strict();
export const ProcessView = ProcessInput.extend({
  id: Id, environmentId: Id, ownerId: Id, actorId: Id, workingDirectory: WorkingDirectory,
  state: ProcessState, result: ProcessResult.nullable(), error: z.string().nullable(),
  createdAt: Time, startedAt: Time.nullable(), finishedAt: Time.nullable(),
}).strict();
export const CreatedProcess = ProcessView.pick({ id: true, environmentId: true, ownerId: true, actorId: true,
  state: true, createdAt: true }).strict();
export const ProcessRegistration = z.object({ workingDirectory: WorkingDirectory }).strict();
export const ClaimedProcess = z.object({ lease: Id, process: ProcessView }).strict().nullable();
export type ProcessRequest = z.infer<typeof ProcessInput>;
export type ProcessInfo = z.infer<typeof ProcessView>;
export type Completion = z.infer<typeof ProcessCompletion>;
