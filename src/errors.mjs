export class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message);
    this.status = status;
    this.code = code;
    if (extra) this.extra = extra;
  }
}

export function fail(status, code, message, extra) {
  throw new HttpError(status, code, message, extra);
}

export function nameValue(value, label = '名前') {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 80 || /[\x00-\x1f]/.test(value)) {
    fail(400, 'invalid_name', `${label}は1〜80文字で入力してください。`);
  }
  return value.trim();
}
