import { redirect } from 'react-router';
import type { Route } from './+types/service-return';
import { signedIn } from '../api';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const data = await signedIn(request);
  return redirect('/p/' + data.principal!.id + '/services' + new URL(request.url).search);
}
export default function ServiceReturn() {
  return null;
}
