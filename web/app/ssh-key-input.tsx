import { useId, useRef, useState } from 'react';
import { FileUp, Plus, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { SSHPublicKey, SSHSettings } from '../../shared/ssh';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';

export type SSHKeyEntry = { id: string; value: string };

export function SSHKeyInput({ value, onChange, reading, onReadingChange }: {
  value: SSHKeyEntry[];
  onChange: (keys: SSHKeyEntry[]) => void;
  reading: boolean;
  onReadingChange: (reading: boolean) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const fileInput = useRef<HTMLInputElement>(null);
  const [fileError, setFileError] = useState(false);
  const invalid = value.map(key => Boolean(key.value.trim()) && !SSHPublicKey.safeParse(key.value).success);
  const hasError = fileError || invalid.some(Boolean);

  async function importFiles(files: File[]) {
    if (!files.length) return;
    onReadingChange(true);
    setFileError(false);
    try {
      const imported = await Promise.all(files.map(async file => {
        if (file.size > 32768) throw new Error('Public key file is too large.');
        return SSHPublicKey.parse(await file.text());
      }));
      const existing = new Set(value.map(key => key.value.trim()).filter(Boolean));
      const additions = imported.filter(key => {
        if (existing.has(key)) return false;
        existing.add(key);
        return true;
      }).map(key => ({ id: crypto.randomUUID(), value: key }));
      SSHSettings.parse({ authorizedKeys: [...existing] });
      onChange([...value.filter(key => key.value.trim()), ...additions]);
    } catch {
      setFileError(true);
    } finally {
      onReadingChange(false);
    }
  }

  return <div className="grid min-w-0 gap-4">
    <input type="hidden" name="sshKeys" value={value.map(key => key.value.trim()).filter(Boolean).join('\n')} />
    {value.length > 0 && <ul className="grid gap-4">
      {value.map((key, index) => {
        const label = t('sshKeyNumber', { number: index + 1 });
        return <li key={key.id} className="grid min-w-0 gap-2">
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor={id + '-' + key.id}>{label}</Label>
            <Button variant="ghost" size="icon-sm" disabled={reading}
              aria-label={t('sshRemoveKey', { number: index + 1 })}
              onClick={() => { setFileError(false); onChange(value.filter(item => item.id !== key.id)); }}>
              <X aria-hidden="true" />
            </Button>
          </div>
          <Input id={id + '-' + key.id} value={key.value} maxLength={8192} disabled={reading}
            ref={input => { input?.setCustomValidity(invalid[index] ? t('errors.invalid_ssh_key') : ''); }}
            aria-invalid={invalid[index] || undefined} aria-describedby={invalid[index] ? id + '-error' : undefined}
            spellCheck={false} autoCapitalize="off" autoCorrect="off" className="h-10 font-mono text-xs"
            onChange={event => {
              setFileError(false);
              onChange(value.map(item => item.id === key.id ? { ...item, value: event.target.value } : item));
            }}
            onKeyDown={event => { if (event.key === 'Enter') event.preventDefault(); }} />
        </li>;
      })}
    </ul>}
    {hasError && <p id={id + '-error'} role="alert" className="text-sm text-destructive">{t('errors.invalid_ssh_key')}</p>}
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={reading || value.length >= 32}
        onClick={() => {
          setFileError(false);
          onChange([...value, { id: crypto.randomUUID(), value: '' }]);
        }}>
        <Plus aria-hidden="true" />{t('sshAddKey')}
      </Button>
      <Button variant="ghost" loading={reading} onClick={() => fileInput.current?.click()}>
        <FileUp aria-hidden="true" />{t('sshImportKeys')}
      </Button>
      <input ref={fileInput} type="file" accept=".pub" multiple className="hidden"
        aria-label={t('sshImportKeys')} disabled={reading}
        onChange={event => {
          const files = Array.from(event.currentTarget.files ?? []);
          event.currentTarget.value = '';
          void importFiles(files);
        }} />
    </div>
  </div>;
}
