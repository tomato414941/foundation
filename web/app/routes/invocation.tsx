import { redirect } from 'react-router';
import type { Route } from './+types/invocation';
export function clientLoader({ params }: Route.ClientLoaderArgs) { return redirect('/executions/' + params.id); }
export default function InvocationLink() { return null; }
