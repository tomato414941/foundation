import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
token = 'cfut_' + 'fixturetoken' * 4
account_id = '1234567890abcdef1234567890abcdef'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['管理者キー', '実装', '開発者', '設計意図', '作業報告', 'refresh_token', 'fdn_', token]:
        assert phrase not in text, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'fdn_session' not in page.evaluate('document.cookie')


with tempfile.TemporaryDirectory(prefix='foundation-cloudflare-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, success=True):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=20)
        assert (result.returncode == 0) == success, result.stderr
        assert token not in result.stdout + result.stderr and 'fdn_' not in result.stdout
        return json.loads(result.stdout) if success else None

    approval = cli('connect', '--name', 'dev-us のAI')['request']
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1050})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(approval['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/auth/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    # The key is approved first, on its own screen; the registration comes as a separate request.
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()
    request = cli('connect', '--adapter', 'cloudflare.api-token', '--purpose', 'R2のバケット一覧を確認。変更やデータ転送は行いません。')['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='Cloudflareのトークンを登録', exact=True)).to_be_visible()
    expect(page.get_by_text('dev-us のAIの依頼', exact=True)).to_be_visible()
    expect(page.get_by_label('確認コード', exact=True)).to_have_count(0)
    review(page)

    dialog = page.get_by_role('dialog')
    register = page.locator('.register-body')
    field = register.get_by_label('APIトークン', exact=True)
    account_field = register.get_by_label('アカウントID', exact=True)
    expect(field).to_have_attribute('type', 'password')
    expect(field).to_have_attribute('autocomplete', 'off')
    expect(page.get_by_text('Global API Key と R2 の S3互換キーは不可', exact=False)).to_be_visible()
    context.route('https://dash.cloudflare.com/profile/api-tokens', lambda route: route.fulfill(status=200, content_type='text/html', body='<h1>Cloudflare token settings fixture</h1>'))
    link = register.get_by_role('link', name='CloudflareのAPIトークン管理ページを開く', exact=False)
    expect(link).to_have_attribute('rel', 'noopener noreferrer')
    with page.expect_popup() as popup_event:
        link.click()
    popup = popup_event.value
    popup.wait_for_load_state()
    assert popup.url == 'https://dash.cloudflare.com/profile/api-tokens'
    assert popup.evaluate('window.opener === null')
    popup.close()

    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        assert register.evaluate('(el) => el.scrollWidth <= el.clientWidth')
        if width != 320:
            page.screenshot(path=str(shots / ('token-desktop.png' if width == 1280 else 'token-mobile.png')), full_page=True)

    # Both fields must be valid, and failed verification never keeps the secret.
    account_field.fill('invalid')
    assert not account_field.evaluate('(el) => el.checkValidity()')
    account_field.fill(account_id)
    field.fill('invalid-token-with-valid-syntax')
    register.get_by_role('button', name='登録する', exact=True).click()
    expect(register.get_by_role('alert')).to_contain_text('トークンが無効か')
    expect(field).to_have_value('')
    expect(account_field).to_have_value(account_id)
    review(page)
    assert cli('credentials')['credentials'] == []
    cli('wait', success=False)

    # A valid token with an inaccessible account is a reported fact, not a hard gate; the result shows it.
    account_field.fill('f' * 32)
    field.fill(token)
    register.get_by_role('button', name='登録する', exact=True).click()
    expect(page.get_by_role('heading', name='登録しました', exact=True)).to_be_visible()
    expect(page.get_by_text('R2の一覧を取得できませんでした。', exact=False)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('verification-desktop.png' if width == 1280 else 'verification-mobile.png')), full_page=True)

    # To correct the account ID the owner removes that credential and registers again through a new request.
    wrong = cli('credentials')['credentials'][0]
    page.goto(args.base, wait_until='networkidle')
    page.locator('[aria-labelledby="cloudflare-title"]').get_by_role('button', name='登録を解除', exact=True).click()
    dialog.get_by_role('checkbox', name='キーの無効化はCloudflareで行うことを確認しました', exact=True).check()
    dialog.get_by_role('button', name='登録を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert [item['id'] for item in cli('credentials')['credentials']] == []
    request = cli('connect', '--adapter', 'cloudflare.api-token', '--purpose', 'R2のバケット一覧を確認。')['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    account_field.fill(account_id)
    field.fill(token)
    with page.expect_response(lambda response: '/api/adapters/cloudflare.api-token/connect' in response.url) as response_event:
        register.get_by_role('button', name='登録する', exact=True).click()
    assert token not in response_event.value.text()
    expect(page.get_by_role('heading', name='登録しました', exact=True)).to_be_visible()
    page.get_by_text('検証結果', exact=True).click()
    expect(page.get_by_text('R2のバケット一覧を取得できました。', exact=False)).to_be_visible()
    review(page)
    account = cli('credentials')['credentials'][0]
    assert account['cloudflare_account_id'] == account_id
    assert account['variables'] == ['CLOUDFLARE_API_TOKEN']
    result = subprocess.run(['node', 'src/runtime.mjs', 'exec', account['id'], '--', 'node', '-e',
        'if(!process.env.CLOUDFLARE_API_TOKEN?.startsWith("cfut_") || process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2); console.log("ready")'],
        env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0 and result.stdout.strip() == 'ready', result.stderr
    assert token not in result.stdout + result.stderr

    page.goto(args.base, wait_until='networkidle')
    section = page.locator('[aria-labelledby="cloudflare-title"]')
    section.get_by_role('button', name='検証する', exact=True).click()
    expect(page.get_by_text('Cloudflareで検証できました。', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('connections-desktop.png' if width == 1280 else 'connections-mobile.png')), full_page=True)

    section.get_by_role('button', name='登録を解除', exact=True).click()
    expect(dialog.get_by_role('link', name='Cloudflareでキーを削除する', exact=False)).to_have_attribute('href', 'https://dash.cloudflare.com/profile/api-tokens')
    expect(dialog.get_by_text('受け渡し済みのAPIキーは、この操作では無効になりません。', exact=False)).to_be_visible()
    dialog.get_by_role('checkbox', name='キーの無効化はCloudflareで行うことを確認しました', exact=True).check()
    review(page)
    dialog.get_by_role('button', name='登録を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert cli('credentials')['credentials'] == []

    # Root imports use the same small form and do not restore revoked grants.
    # The dashboard registers through the dialog.
    section.get_by_role('button', name='Cloudflareを登録', exact=True).click()
    field = dialog.get_by_label('APIトークン', exact=True)
    account_field = dialog.get_by_label('アカウントID', exact=True)
    field.fill(token)
    dialog.get_by_role('button', name='閉じる', exact=True).click()
    section.get_by_role('button', name='Cloudflareを登録', exact=True).click()
    expect(field).to_have_value('')
    expect(account_field).to_have_value('')
    account_field.fill(account_id)
    field.fill(token)
    dialog.get_by_role('button', name='登録する', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert len(cli('credentials')['credentials']) == 1, 'the approved key uses a connection the owner registers later'
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Cloudflare browser flow passed: key approval first, registration as its own request, verification shown on the result, R2 failure nonblocking, correction by registering again, native credential delivery, secret clearing and mobile copy review. All Cloudflare calls mocked.')
