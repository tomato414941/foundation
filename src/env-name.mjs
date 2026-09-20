// A delivered key is exposed to the child process under a variable name. The
// name must never override how the process itself starts.
const RESERVED = new Set(['PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'PWD', 'OLDPWD', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'TERM', 'HOSTNAME', 'IFS', 'PS1', 'PS4', 'ENV', 'BASH_ENV', 'CDPATH', 'EDITOR', 'VISUAL',
  'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'PERL5OPT', 'PERL5LIB', 'RUBYOPT', 'RUBYLIB', 'JAVA_TOOL_OPTIONS', 'GOFLAGS', 'GOPATH', 'GEM_PATH', 'GEM_HOME']);
const SYSTEM_PREFIX = /^(FOUNDATION_|LD_|DYLD_|LC_|XDG_|GIT_|SSH_)/;
// Names that built-in providers already own; a runtime-declared key may not borrow them.
const PROVIDER_PREFIX = /^(GOOGLE_OAUTH_|GMAIL_|OPENROUTER_|EXPO_)/;

export function validEnvName(value) {
  return typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(value) && !RESERVED.has(value) && !SYSTEM_PREFIX.test(value);
}
export function validRequestedEnvName(value) {
  return validEnvName(value) && !PROVIDER_PREFIX.test(value);
}
