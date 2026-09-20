import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { SupabaseAuth } from '../src/auth.mjs';
import { json, USER_A } from './helpers.mjs';

const user = { id: USER_A, email: 'owner@example.test', is_anonymous: false };
const session = { access_token: 'test-supabase-jwt', refresh_token: 'test-supabase-refresh', expires_in: 3600, token_type: 'bearer', user };
const setup = (fetcher) => new SupabaseAuth({ url: 'https://example.supabase.co', key: 'sb_publishable_test_only', fetcher });

test('Official Supabase SDK sends a signup-capable default magic link and exchanges its browser-bound PKCE code', async () => {
  const calls = [];
  const auth = setup(async (url, options) => {
    calls.push({ url: String(url), options });
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal);
    return json(new URL(url).pathname.endsWith('/otp') ? {} : String(url).endsWith('/user') ? user : session);
  });
  const storage = new Map();
  const redirectUri = 'https://foundation.example.test/auth/callback';
  await auth.sendLink(user.email, redirectUri, storage);
  assert.equal(new URL(calls[0].url).pathname, '/auth/v1/otp');
  assert.equal(new URL(calls[0].url).searchParams.get('redirect_to'), redirectUri);
  assert.equal(JSON.parse(calls[0].options.body).create_user, true);
  assert.equal(JSON.parse(calls[0].options.body).email, user.email);
  assert.equal(JSON.parse(calls[0].options.body).code_challenge_method, 's256');
  const result = await auth.exchangeLink('test-auth-code', storage);
  assert.equal(result.user.id, USER_A);
  assert.equal(result.refresh_token, session.refresh_token);
  assert.ok(result.expires_at > Date.now());
  assert.match(calls[1].url, /token\?grant_type=pkce$/);
  const exchanged = JSON.parse(calls[1].options.body);
  assert.equal(exchanged.auth_code, 'test-auth-code');
  assert.equal(createHash('sha256').update(exchanged.code_verifier).digest('base64url'), JSON.parse(calls[0].options.body).code_challenge);
  assert.ok(![...storage.values()].some(value => value.includes(session.refresh_token)));
  assert.equal(calls.some(call => 'password' in JSON.parse(call.options.body || '{}')), false);
  assert.deepEqual(await auth.user(result.access_token), { id: USER_A, email: user.email });
  assert.equal(calls.at(-1).options.headers.Authorization, 'Bearer test-supabase-jwt');
  await auth.refresh(result.refresh_token);
  assert.match(calls.at(-1).url, /grant_type=refresh_token/);
});

test('Logout explicitly revokes only this Supabase session, never all devices', async () => {
  let last;
  const auth = setup(async (url, options) => { last = { url: String(url), options }; return new Response(null, { status: 204 }); });
  await auth.logout('test-jwt');
  assert.match(last.url, /logout\?scope=local/);
  assert.equal(last.options.headers.Authorization, 'Bearer test-jwt');
});

test('Supabase errors and forged credentials never become local login identities', async () => {
  const auth = setup(async () => json({ code: 'invalid_credentials', msg: 'secret-token-in-upstream-error' }, 400));
  await assert.rejects(auth.exchangeLink('invalid-auth-code', new Map()), (error) => error.status === 401 && !error.message.includes('secret-token'));
  await assert.rejects(auth.sendLink('test@example.test', 'https://foundation.example.test/auth/callback', new Map()), (error) => error.status === 503 && !error.message.includes('secret-token'));
  const forged = setup(async () => json({ ...user, is_anonymous: true }));
  await assert.rejects(forged.user('forged'), { status: 401 });
});

test('Missing or privileged configuration fails closed, not back to owner key', async () => {
  const absent = new SupabaseAuth();
  assert.equal(absent.enabled, false);
  await assert.rejects(absent.sendLink('a@example.test', 'https://foundation.example.test/auth/callback', new Map()), { status: 503 });
  await assert.rejects(absent.exchangeLink('test-auth-code', new Map()), { status: 503 });
  assert.throws(() => new SupabaseAuth({ url: 'https://app.supabase.co' }));
  assert.throws(() => new SupabaseAuth({ url: 'https://app.supabase.co', key: 'sb_secret_test' }));
  assert.throws(() => new SupabaseAuth({ url: 'http://remote.example.test', key: 'anon' }));
  const elevated = 'header.' + Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url') + '.signature';
  assert.throws(() => new SupabaseAuth({ url: 'https://app.supabase.co', key: elevated }));
});

test('Email delivery must be enabled separately and cannot send while unavailable', async () => {
  let requests = 0;
  const auth = new SupabaseAuth({ url: 'https://example.supabase.co', key: 'sb_publishable_test_only', emailEnabled: false, fetcher: async () => { requests++; return json(user); } });
  assert.equal(auth.enabled, true);
  assert.equal(auth.emailEnabled, false);
  await assert.rejects(auth.sendLink(user.email, 'https://foundation.example.test/auth/callback', new Map()), { status: 503, code: 'email_unavailable' });
  assert.equal(requests, 0);
  assert.deepEqual(await auth.user('existing-session'), { id: USER_A, email: user.email });
});
