import { SSHSettings } from '../../shared/ssh';
import { ApiFailure, formText } from './api';

export function sshSettings(form: FormData) {
  const result = SSHSettings.safeParse({ authorizedKeys: formText(form, 'sshKeys').split(/\r?\n/).map(key => key.trim()).filter(Boolean) });
  if (!result.success) throw new ApiFailure('invalid_ssh_key');
  return result.data;
}
