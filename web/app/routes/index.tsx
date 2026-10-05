import { redirect } from 'react-router';
import { session } from '../api';
export async function clientLoader() { const data = await session(); return redirect(data.requestId ? '/requests/' + data.requestId : data.principal ? '/p/' + data.principal.id : '/signin'); }
export default function Index() { return null; }
