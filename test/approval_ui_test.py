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
    for phrase in ['実装', '開発者', '設計意図', 'refresh_token', 'client_secret', 'fdn_', 'google-access-']:
        assert phrase not in text, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'fdn_session' not in page.evaluate('document.cookie')


with tempfile.TemporaryDirectory(prefix='foundation-approval-cli-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, success=True):
        result = subprocess.run(['node', 'cli/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == success, ' '.join(command) + ': ' + result.stderr + result.stdout
        assert 'fdn_' not in result.stdout and 'google-access-' not in result.stdout
        return json.loads(result.stdout.split('\n\nKey file')[0]) if success else None

    # 1. A new key asks only to be approved. The owner types the code; nothing is registered here.
    request = cli('connect', '--name', 'dev-us のAI')['request']
    assert '/requests/' in request['verification_uri'] and request['confirmation_code']
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1050})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='ログイン', exact=True)).to_be_visible()
    expect(page.get_by_text('依頼の確認', exact=True)).to_be_visible()
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    callback = context.new_page()
    callback.goto(args.base + '/login/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    expect(callback.get_by_role('heading', name='このアクセスキーを承認しますか？', exact=True)).to_be_visible()
    assert callback.url == request['verification_uri']
    callback.close()
    page.bring_to_front()
    page.evaluate('window.dispatchEvent(new Event("focus"))')
    expect(page.get_by_role('heading', name='このアクセスキーを承認しますか？', exact=True)).to_be_visible()
    expect(page.get_by_text(request['confirmation_code'], exact=True)).to_have_count(0)
    assert request['confirmation_code'] not in page.content()
    expect(page.get_by_role('button', name='Googleで接続', exact=True)).to_have_count(0)
    expect(page.get_by_role('button', name='承認する', exact=True)).to_be_disabled()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width in [1280, 390]:
            page.screenshot(path=str(shots / ('request-desktop.png' if width == 1280 else 'request-mobile.png')), full_page=True)
    page.get_by_label('確認コード', exact=True).fill('0000-0000')
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('alert')).to_contain_text('確認コードを入力してください')
    assert cli('api', 'GET', '/v1/principals/me')['acts_for'] == []
    page.get_by_label('確認コード', exact=True).fill(request['confirmation_code'].lower())
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()
    expect(page.get_by_role('link', name='アクセスキー', exact=True)).to_have_attribute('href', '/principals')
    page.get_by_role('link', name='アクセスキー', exact=True).click()
    expect(page).to_have_url(args.base + '/principals')
    expect(page.get_by_role('heading', name='アクセスキー', exact=True)).to_be_visible()
    review(page)
    assert cli('api', 'GET', '/v1/holdings?kind=secret')['holdings'] == []

    # 2. The approved key asks for a registration, on its own link and without a code.
    request = cli('api', 'POST', '/v1/requests', '--json', json.dumps({'kind': 'connect', 'input': {'connector': 'gmail.readonly'}, 'purpose': '届いたメールを確認する'}))['request']
    assert request['kind'] == 'connect' and 'confirmation_code' not in request
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='Googleで接続', exact=True)).to_be_visible()
    expect(page.locator('.approval-facts')).to_contain_text('メールの読み取り')
    expect(page.get_by_label('確認コード', exact=True)).to_have_count(0)
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
    expect(page.get_by_text('登録をキャンセルしました。', exact=True)).to_be_visible()
    assert page.url == request['verification_uri']
    assert cli('api', 'GET', '/v1/holdings?kind=secret')['holdings'] == []
    authorization['deny'] = False
    page.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_role('heading', name='接続しました', exact=True)).to_be_visible()
    expect(page.get_by_text('personal@example.test', exact=False)).to_be_visible()
    expect(page.get_by_role('link', name='接続', exact=True)).to_have_attribute('href', '/connections')
    page.get_by_role('link', name='接続', exact=True).click()
    expect(page).to_have_url(args.base + '/connections')
    expect(page.get_by_role('heading', name='接続', exact=True)).to_be_visible()
    page.goto(request['verification_uri'], wait_until='networkidle')
    review(page)
    page.screenshot(path=str(shots / 'request-approved.png'), full_page=True)
    connection = cli('api', 'GET', '/v1/requests/' + request['id'])['request']['result']['connection_id']
    saved = cli('api', 'POST', '/v1/functions/connection.credentials', '--json', json.dumps({'connection_id': connection, 'save': {'GOOGLE_OAUTH_ACCESS_TOKEN': 'mail token'}}))
    assert saved['saved'][0]['name'] == 'mail token'
    command = subprocess.run(['node', 'cli/runtime.mjs', 'exec', 'GOOGLE_OAUTH_ACCESS_TOKEN=mail token', '--', 'node', '-e', 'if(!process.env.GOOGLE_OAUTH_ACCESS_TOKEN)process.exit(2);console.log("ready")'], env=env, capture_output=True, text=True, timeout=15)
    assert command.returncode == 0 and command.stdout.strip() == 'ready', command.stderr

    # 3. Revoking the key stops it; its open registration link says so.
    pending = cli('api', 'POST', '/v1/requests', '--json', json.dumps({'kind': 'connect', 'input': {'connector': 'gmail.metadata'}, 'purpose': '件名を確認する'}))['request']
    page.goto(args.base + '/principals', wait_until='networkidle')
    runtime = page.locator('.agent-row').filter(has_text='dev-us のAI')
    runtime.get_by_role('button', name='失効', exact=True).click()
    page.get_by_role('dialog').get_by_role('button', name='失効させる', exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    cli('api', 'GET', '/v1/holdings?kind=secret', success=False)
    page.goto(pending['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='依頼は取り消されました', exact=True)).to_be_visible()

    # 4. The same key file is now unknown again: it may ask to be approved, and the owner may refuse.
    request = cli('connect', '--name', 'dev-us のAI')['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='このアクセスキーを承認しますか？', exact=True)).to_be_visible()
    page.get_by_role('button', name='承認しない', exact=True).click()
    expect(page.get_by_role('heading', name='承認しませんでした', exact=True)).to_be_visible()
    assert cli('api', 'GET', '/v1/principals/me')['acts_for'] == []

    # 5. Approved again, the key asks for a metadata-only Gmail credential: another kind, its own registration.
    request = cli('connect', '--name', 'dev-us のAI')['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    page.get_by_label('確認コード', exact=True).fill(request['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()
    request = cli('api', 'POST', '/v1/requests', '--json', json.dumps({'kind': 'connect', 'input': {'connector': 'gmail.metadata'}, 'purpose': '件名を確認する'}))['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.locator('.approval-facts')).to_contain_text('件名・差出人などの読み取り')
    page.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_role('heading', name='接続しました', exact=True)).to_be_visible()
    expect(page.get_by_text('headers@example.test', exact=False)).to_be_visible()
    review(page)
    request = cli('api', 'POST', '/v1/requests', '--json', json.dumps({'kind': 'connect', 'input': {'connector': 'gmail.readonly'}, 'purpose': '確認'}))['request']
    cli('api', 'DELETE', '/v1/requests/' + request['id'])
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='依頼は取り消されました', exact=True)).to_be_visible()

    request = cli('api', 'POST', '/v1/requests', '--json', json.dumps({'kind': 'connect', 'input': {'connector': 'gmail.readonly'}, 'purpose': '<img src=x onerror="window.xss=1">' + '長い用途' * 50}))['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    assert page.locator('.approval-card img').count() == 0
    assert page.evaluate('window.xss === undefined')
    for width in [320, 390, 1280]:
        page.set_viewport_size({'width': width, 'height': 950})
        review(page)
    cli('api', 'DELETE', '/v1/requests/' + request['id'])
    page.goto(args.base + '/requests/' + 'A' * 43, wait_until='networkidle')
    expect(page.get_by_role('heading', name='依頼を確認できません', exact=True)).to_be_visible()
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Approval flow passed: key approval with code, then separate registration, Google consent/cancellation, native credentials, revocation, refusal, metadata-only credential, cancellation, invalid link, mobile, XSS and visible copy.')
