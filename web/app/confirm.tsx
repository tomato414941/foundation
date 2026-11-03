import { useState, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { browserSupportsWebAuthn, startAuthentication } from '@simplewebauthn/browser';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
import { ConfirmationView, decryptionContext, signConfirmation } from '../../shared/confirmations';
import { decode, open } from '../../shared/encryption';
import type { ConfirmationNeeded, ConfirmationProof } from '../../shared/confirmations';
import { api, ApiFailure, errorCode, session } from './api';
import { getIdentity, unlockedKeys } from './keys';
import i18n from './i18n';
import { ErrorNotice } from './components';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './components/ui/dialog';

type Method = 'passkey' | 'email';
type Answer = { method: Method } | { code: string } | null;
type Asking = { change: string; methods: Method[]; email: string | null; error: string | null; answer(value: Answer): void };
let asking: Asking | null = null;
const listeners = new Set<() => void>();
function ask(value: Omit<Asking, 'answer'>) {
  return new Promise<Answer>(resolve => {
    asking = { ...value, answer: answer => { asking = null; for (const listener of listeners) listener(); resolve(answer); } };
    for (const listener of listeners) listener();
  });
}

// Confirms a change through the API with what this browser can use: the keys it holds without asking, or else the
// passkey or email code the person chooses, switching between them until one works or they cancel. Returns the
// confirmation's ID.
export async function confirmChange(needed: ConfirmationNeeded) {
  const view = await api('/confirmations', { method: 'POST', body: { operation: needed.operation } }, ConfirmationView);
  const path = '/confirmations/' + view.id, change = 'change.' + needed.operation.action;
  const prove = (proof: ConfirmationProof) => api(path + '/proof', { method: 'POST', body: proof }, ConfirmationView);
  const principalId = (await session()).principal?.id;
  const identity = principalId ? await getIdentity(principalId) : null;
  if (view.methods.includes('signature') && identity && identity.binding.id === view.challenge.bindingId) {
    await prove({ method: 'signature', signature: await signConfirmation(view, identity.keys.signing) });
    return view.id;
  }
  const opened = principalId ? unlockedKeys(principalId) : null;
  if (view.methods.includes('decryption') && view.sealed && opened) {
    const secret = decode(await open(view.sealed, opened.encryption, view.id, decryptionContext(view.id)));
    await prove({ method: 'decryption', secret });
    return view.id;
  }
  const methods = view.methods.filter((method): method is Method =>
    method === 'email' || (method === 'passkey' && browserSupportsWebAuthn()));
  if (!methods.length) throw new ApiFailure('confirmation_unavailable');
  let method: Method | null = methods.length === 1 ? methods[0]! : null, email: string | null = null, error: string | null = null;
  for (;;) {
    if (!method) {
      const answer = await ask({ change, methods, email: null, error });
      error = null;
      if (!answer || !('method' in answer)) throw new ApiFailure('confirmation_cancelled');
      method = answer.method;
    }
    if (method === 'passkey') {
      try {
        const { options } = await api<{ options: PublicKeyCredentialRequestOptionsJSON }>(path + '/passkey', { method: 'POST', body: {} });
        let credential;
        try { credential = await startAuthentication({ optionsJSON: options }); }
        catch { throw new ApiFailure('passkey_cancelled'); }
        await prove({ method: 'passkey', credential: JSON.parse(JSON.stringify(credential)) });
        return view.id;
      } catch (failure) {
        if (methods.length === 1) throw failure;
        error = errorCode(failure);
      }
    } else {
      try {
        email ??= (await api<{ email: string }>(path + '/email', {
          method: 'POST', body: { locale: i18n.language === 'en' ? 'en' : 'ja' },
        })).email;
        const answer = await ask({ change, methods, email, error });
        // What went wrong is shown once, in the dialog that asks again.
        error = null;
        if (!answer) throw new ApiFailure('confirmation_cancelled');
        if ('method' in answer) { method = answer.method; continue; }
        await prove({ method: 'email', code: answer.code });
        return view.id;
      } catch (failure) {
        const code = errorCode(failure);
        if (code === 'invalid_proof') { error = 'confirmation_code_wrong'; continue; }
        if (code === 'confirmation_cancelled' || methods.length === 1) throw failure;
        error = code;
      }
    }
    method = null;
  }
}

// Where the person chooses how to confirm a change and enters the code sent by email.
export function ConfirmationPrompt() {
  const { t } = useTranslation();
  const current = useSyncExternalStore(listener => { listeners.add(listener); return () => listeners.delete(listener); },
    () => asking, () => null);
  const [code, setCode] = useState('');
  const answer = (value: Answer) => { setCode(''); current?.answer(value); };
  const others = current?.methods.filter(method => !(current.email && method === 'email')) ?? [];
  return <Dialog open={!!current} onOpenChange={open => { if (!open) answer(null); }}>
    <DialogContent>
      <form className="space-y-5" onSubmit={event => { event.preventDefault(); if (current?.email && code.trim()) answer({ code: code.trim() }); }}>
        <DialogHeader>
          <DialogTitle>{t('confirmationTitle')}</DialogTitle>
          <DialogDescription>
            {current?.email ? t('confirmationEmailBody', { change: t(current.change), email: current.email })
              : t('confirmationChooseBody', { change: t(current?.change ?? '') })}
          </DialogDescription>
        </DialogHeader>
        {current?.email && <Input aria-label={t('confirmationCode')} autoComplete="one-time-code" autoFocus value={code}
          onChange={event => setCode(event.target.value)} />}
        <ErrorNotice error={current?.error} />
        <DialogFooter className="flex-wrap">
          <Button type="button" variant="outline" onClick={() => answer(null)}>{t('cancel')}</Button>
          {others.map(method => <Button key={method} type="button" variant={current?.email ? 'outline' : 'default'}
            onClick={() => answer({ method })}>{t(method === 'passkey' ? 'confirmWithPasskey' : 'confirmWithEmail')}</Button>)}
          {current?.email && <Button type="submit" disabled={!code.trim()}>{t('confirmationSubmit')}</Button>}
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>;
}
