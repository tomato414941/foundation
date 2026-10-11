import { redirect } from 'react-router';
import type { Route } from './+types/run';
import { Task } from '../../../shared/runtime-protocol';
import { api, signedIn } from '../api';

export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  const run = await api('/runtime/runs/' + params.id, { signal: request.signal }, Task);
  return redirect('/executions/' + (run.intent.operationContext?.id ?? run.id));
}
export default function RunLink() { return null; }
