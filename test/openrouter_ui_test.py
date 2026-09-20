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
    for phrase in ['管理者キー', '実装', '開発者', '設計意図', 'refresh_token', 'client_secret', 'sk-or-v1-', 'fdn_']:
        assert phrase not in text, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'fdn_session' not in page.evaluate('document.cookie')


with tempfile.TemporaryDirectory(prefix='foundation-openrouter-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, success=True):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == success, result.stderr
        assert 'sk-or-v1-' not in result.stdout + result.stderr and 'fdn_' not in result.stdout
        return json.loads(result.stdout) if success else None

    request = cli('connect', '--name', 'dev-us のAI', '--purpose', '接続したキーの情報を確認。モデルは実行しません。')['request']
    assert request['provider'] == 'openrouter' and request['mode'] == 'api-key'
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1050})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(request['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/auth/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    expect(page.get_by_role('heading', name='利用を許可しますか？', exact=True)).to_be_visible()
    assert page.url == request['verification_uri']
    expect(page.get_by_text('OpenRouterへのアクセス', exact=True)).to_be_visible()
    expect(page.get_by_text('APIキーの利用', exact=False)).to_be_visible()
    expect(page.get_by_text('利用上限と有効期限はOpenRouter側の設定が適用されます。', exact=False)).to_be_visible()
    expect(page.get_by_role('button', name='利用を許可', exact=True)).to_be_disabled()
    review(page)
    authorization = {'deny': True, 'code': 'personal'}

    def consent(route):
        query = parse_qs(urlparse(route.request.url).query)
        assert query['code_challenge_method'] == ['S256']
        assert 'client_secret' not in query and 'code_verifier' not in query
        callback = query['callback_url'][0]
        assert parse_qs(urlparse(callback).query)['state']
        params = {'error': 'access_denied'} if authorization['deny'] else {'code': authorization['code']}
        route.fulfill(status=302, headers={'location': callback + '&' + urlencode(params)}, body='')

    page.route('https://openrouter.ai/auth?*', consent)
    page.get_by_role('button', name='OpenRouterで接続', exact=True).click()
    expect(page.get_by_text('接続をキャンセルしました。', exact=True)).to_be_visible()
    cli('accounts', success=False)
    authorization['deny'] = False
    page.get_by_role('button', name='OpenRouterで接続', exact=True).click()
    expect(page.get_by_role('radio')).to_have_count(1)
    expect(page.get_by_text('期限の指定なし', exact=True)).to_be_visible()
    expect(page.get_by_text('$0.00 · リセットなし', exact=True)).to_be_visible()
    cli('accounts', success=False)
    cli('accounts', success=False)
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('approval-desktop.png' if width == 1280 else 'approval-mobile.png')), full_page=True)
    expect(page.get_by_text(request['confirmation_code'], exact=True)).to_have_count(0)
    page.get_by_label('確認コード', exact=True).fill(request['confirmation_code'])
    page.get_by_role('button', name='利用を許可', exact=True).click()
    expect(page.get_by_role('heading', name='利用を許可しました', exact=True)).to_be_visible()
    account = cli('accounts')['accounts'][0]
    assert account['authentication']['type'] == 'api_key_bearer'
    command = subprocess.run(['node', 'src/runtime.mjs', 'exec', account['id'], '--', 'node', '-e', 'if(!process.env.OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY!==process.env.FOUNDATION_ACCESS_TOKEN || process.env.FOUNDATION_TOKEN_EXPIRES_AT!=="")process.exit(2);console.log("ready")'], env=env, capture_output=True, text=True, timeout=15)
    assert command.returncode == 0 and command.stdout.strip() == 'ready', command.stderr

    page.goto(args.base, wait_until='networkidle')
    section = page.locator('[aria-labelledby="openrouter-title"]')
    assert 'Gmail' not in section.inner_text() and 'メール' not in section.inner_text()
    expect(section.get_by_role('button', name='再接続', exact=True)).to_have_count(0)
    section.get_by_role('button', name='接続を確認', exact=True).click()
    expect(page.get_by_text('OpenRouterに接続できました。', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('connections-desktop.png' if width == 1280 else 'connections-mobile.png')), full_page=True)

    runtime = page.locator('.agent-row').filter(has_text='dev-us のAI')
    runtime.get_by_role('button', name='失効', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text('有効期限が未指定または不明の認証情報', exact=False)).to_be_visible()
    review(page)
    dialog.get_by_role('button', name='失効させる', exact=True).click()
    expect(dialog).not_to_be_visible()
    cli('accounts', success=False)

    section.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_text('受け渡し済みのAPIキーは、この操作では無効になりません。', exact=False)).to_be_visible()
    expect(dialog.get_by_role('link', name='OpenRouterでキーを削除する', exact=False)).to_have_attribute('href', account['management_url'])
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).to_be_visible()
    dialog.get_by_role('checkbox', name='キーの無効化はOpenRouterで行うことを確認しました', exact=True).check()
    review(page)
    page.screenshot(path=str(shots / 'disconnect-mobile.png'), full_page=True)
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(section.get_by_role('heading', name='OpenRouterを接続しましょう', exact=True)).to_be_visible()

    # Root management uses the same provider-driven flow, with no Gmail-only copy.
    section.get_by_role('button', name='OpenRouterを接続', exact=True).click()
    expect(dialog.get_by_label('表示名', exact=True)).to_have_value('OpenRouter')
    review(page)
    authorization['code'] = 'second'
    dialog.get_by_label('表示名', exact=True).fill('<img src=x onerror="window.xss=1">')
    dialog.get_by_role('button', name='OpenRouterで接続', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    assert 'Gmailを接続しました。' not in page.locator('body').inner_text()
    assert section.locator('img').count() == 0 and page.evaluate('window.xss === undefined')
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('OpenRouter browser flow passed: login, PKCE return/cancellation, explicit approval, budget/expiry/cost copy, CLI resume, native credential injection, runtime revocation, manual key deletion notice, root connection, mobile, XSS. No paid API calls.')
