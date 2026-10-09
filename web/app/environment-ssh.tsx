import { Form } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { EnvironmentView } from '../../shared/contracts';
import { SSHView, sshCommand } from '../../shared/ssh';
import { Copy, Detail, Panel } from './components';
import { TextareaField } from './form-fields';
import { Button } from './components/ui/button';

export function EnvironmentSSH({ item, canUpdate, busy, saved }: {
  item: EnvironmentView; canUpdate: boolean; busy: boolean; saved: boolean;
}) {
  const { t } = useTranslation();
  if (!item.data.ssh) return null;
  const value = item.data.ssh;
  const state = !['starting', 'running'].includes(item.data.state) || item.data.deletion ? 'stopped'
    : item.data.state === 'starting' ? 'starting'
    : value.appliedRevision !== value.revision || !value.hostKey ? 'configuring'
    : value.authorizedKeys.length ? 'ready' : 'disabled';
  const ssh = SSHView.parse({ ...value, state });
  return <Panel title="SSH">
    {state !== 'ready' && <p aria-live="polite" className="text-sm leading-relaxed text-muted-foreground">{t('ssh.' + state)}</p>}
    {state !== 'stopped' && <>
      <div className="flex min-w-0 items-center gap-2 rounded-md border border-border bg-muted/30 px-3 py-2">
        <code className="min-w-0 flex-1 break-all font-mono text-sm">{sshCommand(ssh)}</code>
        <Copy value={sshCommand(ssh)} />
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground">{t('sshWorkspaceHelp')}</p>
    </>}
    {value.fingerprint && <>
      <Detail label={t('sshHostFingerprint')}>
        <span className="break-all font-mono text-xs">{value.fingerprint}</span>
        <Copy value={value.fingerprint} />
      </Detail>
      <p className="text-xs leading-relaxed text-muted-foreground">{t('sshFingerprintHelp')}</p>
    </>}
    {canUpdate && state !== 'stopped' && <Form method="post" className="grid min-w-0 gap-4">
      <input type="hidden" name="intent" value="ssh" />
      <input type="hidden" name="sshRevision" value={value.revision} />
      <TextareaField key={value.revision} name="sshKeys" label={t('sshAuthorizedKeys')}
        defaultValue={value.authorizedKeys.join('\n')} hint={t('sshKeysHelp')}
        rows={3} spellCheck={false} autoCapitalize="off" autoCorrect="off" className="font-mono text-xs" />
      <p className="text-xs leading-relaxed text-muted-foreground">{t('sshAccessHelp')}</p>
      <Button type="submit" variant="outline" loading={busy} className="w-fit">{t('save')}</Button>
      {saved && !busy && <p aria-live="polite" className="text-sm text-emerald-400">{t('sshKeysSaved')}</p>}
    </Form>}
  </Panel>;
}
