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
token = hashlib.sha256(b'expo-fixture:personal').hexdigest()


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['管理者キー', '実装', '開発者', '設計意図', 'refresh_token', 'session_secret', 'fdn_', token]:
        assert phrase not in text, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'fdn_session' not in page.evaluate('document.cookie')


with tempfile.TemporaryDirectory(prefix='foundation-expo-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, success=True):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
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
    # The key is approved first; the registration is a separate request with no code.
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()
    request = cli('connect', '--adapter', 'expo.token', '--purpose', 'Expoのアカウントを確認。ビルドは実行しません。')['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='Expoのトークンを登録', exact=True)).to_be_visible()
    expect(page.get_by_role('button', name='承認する', exact=True)).to_have_count(0)
    review(page)
    dialog = page.get_by_role('dialog')
    register = page.locator('.register-body')
    field = register.get_by_label('アクセストークン', exact=True)
    expect(field).to_have_attribute('type', 'password')
    expect(field).to_have_attribute('autocomplete', 'off')
    expect(register.get_by_text('すべてのアカウント・組織', exact=False)).to_have_count(0)
    expect(page.get_by_text(request['purpose'], exact=True)).to_be_visible()
    expect(register.get_by_label('用途 任意', exact=True)).to_have_count(0)

    # Verify the external login is an isolated official-site tab, never a
    # Foundation password form or an iframe. No real account is used.
    context.route('https://expo.dev/settings/access-tokens', lambda route: route.fulfill(status=200, content_type='text/html', body='<h1>Official token settings fixture</h1>'))
    link = register.get_by_role('link', name='Expoのアクセストークン管理ページを開く', exact=False)
    expect(link).to_have_attribute('rel', 'noopener noreferrer')
    with page.expect_popup() as popup_event:
        link.click()
    popup = popup_event.value
    popup.wait_for_load_state()
    assert popup.url == 'https://expo.dev/settings/access-tokens'
    assert popup.evaluate('window.opener === null')
    popup.close()
    assert page.url == request['verification_uri']

    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        assert register.evaluate('(el) => el.scrollWidth <= el.clientWidth')
        if width != 320:
            page.screenshot(path=str(shots / ('token-desktop.png' if width == 1280 else 'token-mobile.png')), full_page=True)

    field.fill('syntactically-valid-but-revoked')
    register.get_by_role('button', name='登録する', exact=True).click()
    expect(register.get_by_role('alert')).to_contain_text('トークンが無効か')
    expect(field).to_have_value('')
    assert cli('credentials')['credentials'] == []
    review(page)
    field.fill(token)
    with page.expect_response(lambda response: '/api/adapters/expo.token/connect' in response.url) as response_event:
        register.get_by_role('button', name='登録する', exact=True).click()
    assert token not in response_event.value.text()
    expect(page.get_by_role('heading', name='登録しました', exact=True)).to_be_visible()
    review(page)
    assert cli('credentials')['credentials'][0]['adapter'] == 'expo.token'
    account = cli('credentials')['credentials'][0]
    command = subprocess.run(['node', 'src/runtime.mjs', 'exec', account['id'], '--', 'node', '-e', 'if(!process.env.EXPO_TOKEN || process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("ready")'], env=env, capture_output=True, text=True, timeout=15)
    assert command.returncode == 0 and command.stdout.strip() == 'ready', command.stderr
    assert token not in command.stdout + command.stderr

    page.goto(args.base, wait_until='networkidle')
    section = page.locator('[aria-labelledby="expo-title"]')
    assert 'Gmail' not in section.inner_text() and 'OpenRouter' not in section.inner_text()
    section.get_by_role('button', name='検証する', exact=True).click()
    expect(page.get_by_text('Expoで検証できました。', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('connections-desktop.png' if width == 1280 else 'connections-mobile.png')), full_page=True)

    section.get_by_role('button', name='登録を解除', exact=True).click()
    assert 'OpenRouter' not in dialog.inner_text() and 'Google' not in dialog.inner_text()
    expect(dialog.get_by_role('link', name='Expoでキーを削除する', exact=False)).to_have_attribute('href', 'https://expo.dev/settings/access-tokens')
    dialog.get_by_role('button', name='登録を解除', exact=True).click()
    expect(dialog).to_be_visible()
    dialog.get_by_role('checkbox', name='キーの無効化はExpoで行うことを確認しました', exact=True).check()
    review(page)
    dialog.get_by_role('button', name='登録を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert cli('credentials')['credentials'] == []

    # The dashboard registers through the dialog.
    section.get_by_role('button', name='Expoを登録', exact=True).click()
    field = dialog.get_by_label('アクセストークン', exact=True)
    field.fill(token)
    dialog.get_by_role('button', name='閉じる', exact=True).click()
    section.get_by_role('button', name='Expoを登録', exact=True).click()
    expect(field).to_have_value('')
    field.fill(token)
    dialog.get_by_role('button', name='登録する', exact=True).click()
    expect(dialog).not_to_be_visible()
    section.get_by_role('button', name='編集', exact=True).click()
    dialog.get_by_label('表示名', exact=True).fill('<img src=x onerror="window.xss=1">')
    dialog.get_by_role('button', name='保存', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(section.get_by_role('heading', name='<img src=x onerror="window.xss=1">', exact=True)).to_be_visible()
    assert section.locator('img').count() == 0 and page.evaluate('window.xss === undefined')
    assert len(cli('credentials')['credentials']) == 1, 'the approved key uses a connection the owner registers later'
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Expo browser flow passed: login, official-site handoff, masked/cleared token field, explicit approval, CLI injection, disconnect warning, no auto-grants, root import, mobile and XSS. All provider calls mocked; no builds or paid operations.')
