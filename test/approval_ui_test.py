import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['管理キー', '実装', '開発者', '設計意図', 'refresh_token', 'client_secret', 'fdn_', 'google-access-']:
        assert phrase not in text, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'fdn_session' not in page.evaluate('document.cookie')


with tempfile.TemporaryDirectory(prefix='foundation-approval-cli-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert 'fdn_' not in result.stdout and 'google-access-' not in result.stdout
        return json.loads(result.stdout)

    request = cli('connect', '--name', 'dev-us のAI', '--purpose', '届いたメールを確認する')['request']
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1050})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='ログイン', exact=True)).to_be_visible()
    expect(page.get_by_text('接続依頼の確認', exact=True)).to_be_visible()
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    callback = context.new_page()
    callback.goto(args.base + '/auth/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    expect(callback.get_by_role('heading', name='利用を許可しますか？', exact=True)).to_be_visible()
    assert callback.url == request['verification_uri']
    callback.close()
    page.bring_to_front()
    page.evaluate('window.dispatchEvent(new Event("focus"))')
    expect(page.get_by_role('heading', name='利用を許可しますか？', exact=True)).to_be_visible()
    expect(page.get_by_text(request['confirmation_code'], exact=True)).to_be_visible()
    expect(page.get_by_role('button', name='利用を許可', exact=True)).to_be_disabled()
    review(page)
    page.screenshot(path=str(shots / 'request-before-connection.png'), full_page=True)
    authorization = {'deny': True}

    def consent(route):
        query = parse_qs(urlparse(route.request.url).query)
        assert query['code_challenge_method'] == ['S256']
        params = {'state': query['state'][0]}
        metadata = 'gmail.metadata' in query['scope'][0]
        params.update({'error': 'access_denied'} if authorization['deny'] else {'code': 'headers-metadata' if metadata else 'personal-readonly'})
        route.fulfill(status=302, headers={'location': query['redirect_uri'][0] + '?' + urlencode(params)}, body='')

    page.route('https://accounts.google.com/o/oauth2/v2/auth?*', consent)
    page.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_text('接続をキャンセルしました。', exact=True)).to_be_visible()
    assert page.url == request['verification_uri']
    assert cli('status')['request']['status'] == 'pending'
    authorization['deny'] = False
    page.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_role('radio', name='Gmail personal@example.test', exact=True)).to_be_visible()
    assert page.url == request['verification_uri']
    assert cli('status')['request']['status'] == 'pending'
    expect(page.get_by_role('button', name='利用を許可', exact=True)).to_be_disabled()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width in [1280, 390]:
            page.screenshot(path=str(shots / ('request-desktop.png' if width == 1280 else 'request-mobile.png')), full_page=True)
    page.get_by_role('checkbox', name='会話の確認コードと一致しています', exact=True).check()
    page.get_by_role('button', name='利用を許可', exact=True).click()
    expect(page.get_by_role('heading', name='利用を許可しました', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'request-approved.png'), full_page=True)
    approved = cli('status')['request']
    assert approved['status'] == 'approved'
    assert cli('accounts')['accounts'][0]['id'] == approved['account']['id']
    command = subprocess.run(['node', 'src/runtime.mjs', 'exec', approved['account']['id'], '--', 'node', '-e', 'if(!process.env.GOOGLE_OAUTH_ACCESS_TOKEN || process.env.FOUNDATION_ACCESS_TOKEN!==process.env.GOOGLE_OAUTH_ACCESS_TOKEN)process.exit(2);console.log("ready")'], env=env, capture_output=True, text=True, timeout=15)
    assert command.returncode == 0 and command.stdout.strip() == 'ready', command.stderr

    page.goto(args.base, wait_until='networkidle')
    runtime = page.locator('.agent-row').filter(has_text='dev-us のAI')
    runtime.get_by_role('button', name='利用を停止', exact=True).click()
    page.get_by_role('dialog').get_by_role('button', name='利用を停止', exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    assert cli('status')['request']['status'] == 'revoked'
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='利用許可は停止されています', exact=True)).to_be_visible()

    request = cli('connect', '--name', 'dev-us のAI')['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('radio')).to_have_count(1)
    page.get_by_role('button', name='許可しない', exact=True).click()
    expect(page.get_by_role('heading', name='利用を許可しませんでした', exact=True)).to_be_visible()
    assert cli('status')['request']['status'] == 'denied'

    request = cli('connect', '--mode', 'metadata')['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('radio')).to_have_count(0)
    page.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_role('radio', name='Gmail headers@example.test', exact=True)).to_be_visible()
    expect(page.get_by_text('本文・添付ファイルは対象外', exact=True)).to_be_visible()
    review(page)
    cli('cancel')
    page.reload(wait_until='networkidle')
    expect(page.get_by_role('heading', name='依頼は取り消されました', exact=True)).to_be_visible()

    request = cli('connect', '--name', '<img src=x onerror="window.xss=1">', '--purpose', '長い用途' * 50)['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    assert page.locator('.approval-card img').count() == 0
    assert page.evaluate('window.xss === undefined')
    for width in [320, 390, 1280]:
        page.set_viewport_size({'width': width, 'height': 950})
        review(page)
    cli('cancel')
    page.goto(args.base + '/connect/' + 'A' * 43, wait_until='networkidle')
    expect(page.get_by_role('heading', name='依頼を確認できません', exact=True)).to_be_visible()
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Approval flow passed: CLI bootstrap, email-link return, Google consent/cancellation, explicit approval, CLI resume, native credentials, revocation, denial, metadata-only access, cancellation, invalid link, mobile, XSS and visible copy.')
