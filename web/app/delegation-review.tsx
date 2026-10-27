import { z } from 'zod';
import { useTranslation } from 'react-i18next';
import { Id, Principal, RelationInput } from '../../shared/contracts';
import type { ExecutionView } from '../../shared/executions';
import { api, ApiFailure } from './api';

const NamedPrincipal = Principal.pick({ id: true, name: true });
type NamedPrincipal = z.infer<typeof NamedPrincipal>;
const Participant = z.union([Id, z.literal('$approver'), z.literal('$requester')]);
const Delegation = RelationInput.extend({ subjectId: Participant, objectId: Participant, relation: z.literal('delegate') });
type ReviewPrincipal = NamedPrincipal | null;
export interface DelegationReviewData { subject: ReviewPrincipal; object: ReviewPrincipal; }

export async function loadDelegationReviews(operations: ExecutionView['operations'], {
  approver, requester, principals, inspect, signal,
}: {
  approver: NamedPrincipal | null; requester: NamedPrincipal; principals: NamedPrincipal[]; inspect: boolean; signal: AbortSignal;
}) {
  const known = new Map(principals.map(principal => [principal.id, principal]));
  known.set(requester.id, requester);
  if (approver) known.set(approver.id, approver);
  const pending = new Map<string, Promise<NamedPrincipal>>();
  const resolve = async (id: z.infer<typeof Participant>): Promise<ReviewPrincipal> => {
    if (id === '$approver') return approver;
    if (id === '$requester') return requester;
    const principal = known.get(id);
    if (principal) return principal;
    if (!inspect) return { id, name: id };
    if (!pending.has(id)) pending.set(id, api('/identities/' + id, { signal }, NamedPrincipal).catch(error => {
      if (error instanceof ApiFailure && [403, 404].includes(error.status)) return { id, name: id };
      throw error;
    }));
    return pending.get(id)!;
  };
  return Promise.all(operations.map(async operation => {
    if (operation.name !== 'relation.draw' || operation.inputs.length) return null;
    const input = Delegation.safeParse(operation.input);
    if (!input.success) return null;
    const [subject, object] = await Promise.all([resolve(input.data.subjectId), resolve(input.data.objectId)]);
    return { subject, object } satisfies DelegationReviewData;
  }));
}

export function DelegationReview({ review }: { review: DelegationReviewData }) {
  const { t } = useTranslation();
  return <div className="flex flex-col gap-4">
    <p className="font-medium leading-relaxed wrap-anywhere">{t('delegationReview', {
      subject: review.subject?.name ?? t('approvingPrincipal'), object: review.object?.name ?? t('approvingPrincipal'),
    })}</p>
    <ul className="list-disc space-y-1.5 pl-5 text-sm leading-relaxed">
      <li>{t('delegationResources')}</li>
      <li>{t('delegationSecrets')}</li>
    </ul>
    <p className="text-xs leading-relaxed text-muted-foreground">{t('delegationManagementExcluded')}</p>
  </div>;
}
