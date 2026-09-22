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
PASSWORD = 'fixture-password-do-not-use'
OTP = '123456'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    copy = page.locator('body').inner_text()
    for phrase in ['管理者キー', '実装', '開発者', '設計意図', 'session_secret', 'sessionSecret', 'fdn_', PASSWORD, 'fixture-session-', '接続完了を伝えて']:
        assert phrase not in copy, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'fdn_session' not in page.evaluate('document.cookie')
    assert not page.locator('iframe').count()


with tempfile.TemporaryDirectory(prefix='foundation-expo-login-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, success=True):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == success, result.stderr
        assert PASSWORD not in result.stdout + result.stderr and 'fdn_' not in result.stdout and 'fixture-session-' not in result.stdout
        return json.loads(result.stdout) if success else None

    def request():
        return cli('connect', '--adapter', 'expo.login', '--name', 'dev-us のAI', '--purpose', 'Expoのアカウントを確認します。ビルド・公開は行いません。')['request']

    row = request()
    assert row['permission']['id'] == 'session'
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 800})
    page = context.new_page()
    errors, logs = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('console', lambda message: logs.append(message.text))
    page.goto(row['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/auth/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    expect(page.get_by_role('heading', name='Expoにログイン', exact=True)).to_be_visible()
    expect(page.get_by_text(row['confirmation_code'], exact=True)).to_have_count(0)
    code = page.get_by_label('確認コード', exact=True)
    expect(code).to_be_visible()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(page.get_by_role('button', name='承認する', exact=True)).to_have_count(0)
    expect(page.get_by_text('トークンを登録', exact=False)).to_have_count(0)
    username, password = page.get_by_label('Expoのメールアドレスまたはユーザー名', exact=True), page.get_by_label('パスワード', exact=True)
    submit = page.get_by_role('button', name='ログインして承認', exact=True)
    expect(password).to_have_attribute('type', 'password')
    expect(password).to_have_attribute('autocomplete', 'off')
    expect(page.get_by_text('入力内容はFoundationを経由してExpoへ送信します。', exact=False)).to_be_visible()
    expect(page.get_by_text('課金を伴う操作も含みます。', exact=False)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 844})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('login-desktop.png' if width == 1280 else 'login-mobile.png')), full_page=True)
    code.fill(row['confirmation_code'])
    username.fill('otp-user')
    password.fill('fixture-wrong-password')
    submit.click()
    expect(page.get_by_role('alert')).to_contain_text('Expoにログインできませんでした')
    expect(password).to_have_value('')
    expect(code).to_have_value(row['confirmation_code'])
    cli('accounts', success=False)

    # The runtime learns nothing until approval; it just tries accounts.
    try:
        username.fill('otp-user')
        password.fill(PASSWORD)
        with page.expect_response(lambda response: response.url.endswith('/api/adapters/expo.login/connect')) as reply:
            submit.click()
        assert reply.value.status == 202 and PASSWORD not in reply.value.text()
        otp = page.get_by_label('認証コード', exact=True)
        expect(otp).to_be_visible()
        expect(password).to_have_value('')
        expect(password).to_be_disabled()
        cli('accounts', success=False)
        for width in [1280, 390, 320]:
            page.set_viewport_size({'width': width, 'height': 844})
            review(page)
            if width != 320:
                page.screenshot(path=str(shots / ('mfa-desktop.png' if width == 1280 else 'mfa-mobile.png')), full_page=True)
        otp.fill('000000')
        page.get_by_role('button', name='確認して承認', exact=True).click()
        expect(page.get_by_role('alert')).to_contain_text('Expoにログインできませんでした')
        expect(otp).to_have_value('')
        expect(otp).to_be_visible()
        otp.fill(OTP)
        with page.expect_response(lambda response: response.url.endswith('/api/adapters/expo.login/connect')) as reply:
            page.get_by_role('button', name='確認して承認', exact=True).click()
        assert reply.value.status == 200 and PASSWORD not in reply.value.text() and 'fixture-session-' not in reply.value.text()
        expect(page.get_by_role('heading', name='登録しました', exact=True)).to_be_visible()
        expect(page.get_by_text('この画面は閉じて構いません。', exact=False)).to_be_visible()
        expect(password).to_have_count(0)
        listed = subprocess.run(['node', 'src/runtime.mjs', 'accounts'], env=env, capture_output=True, text=True, timeout=15)
        assert listed.returncode == 0, listed.stderr
        assert PASSWORD not in listed.stdout + listed.stderr and 'fixture-session-' not in listed.stdout + listed.stderr
    finally:
        pass
    account = cli('accounts')['accounts'][0]
    assert account['credential_type'] == 'expo_session'
    review(page)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.screenshot(path=str(shots / 'approved-mobile.png'), full_page=True)

    # The approved key already uses the connected account; a further request only offers another login, with no code.
    row = request()
    page.goto(row['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='Expoにログイン', exact=True)).to_be_visible()
    expect(page.get_by_label('確認コード', exact=True)).to_have_count(0)
    assert len(cli('accounts')['accounts']) == 1
    submit = page.get_by_role('button', name='ログインして接続', exact=True)
    username.fill('otp-other')
    password.fill(PASSWORD)
    page.reload(wait_until='networkidle')
    expect(password).to_have_value('')
    username.fill('otp-other')
    password.fill(PASSWORD)
    submit.click()
    expect(page.get_by_label('認証コード', exact=True)).to_be_visible()
    page.get_by_role('button', name='ログイン情報を入力し直す', exact=True).click()
    expect(password).to_have_value('')
    expect(password).to_be_enabled()
    expect(username).to_have_value('')
    expect(page.get_by_label('認証コード', exact=True)).not_to_be_visible()
    page.clock.install()
    username.fill('otp-other')
    password.fill(PASSWORD)
    submit.click()
    expect(page.get_by_label('認証コード', exact=True)).to_be_visible()
    page.clock.fast_forward(300_001)
    expect(password).to_be_visible()
    expect(password).to_have_value('')
    expect(page.get_by_role('alert')).to_contain_text('時間が経過しました')
    username.fill('unused-user')
    password.fill(PASSWORD)
    page.get_by_role('button', name='登録しない', exact=True).click()
    expect(page.get_by_role('heading', name='利用を許可しませんでした', exact=True)).to_be_visible()
    expect(password).to_have_count(0)
    review(page)

    # Root connection is optional and never silently grants the runtime.
    page.goto(args.base, wait_until='networkidle')
    section = page.locator('[aria-labelledby="expo-title"]')
    section.get_by_role('button', name='接続を確認', exact=True).click()
    expect(page.get_by_text('Expoに接続できました。', exact=True)).to_be_visible()
    section.get_by_role('button', name='Expoを接続', exact=True).click()
    dialog = page.get_by_role('dialog')
    username.fill('fixture-user')
    password.fill(PASSWORD)
    dialog.get_by_role('button', name='閉じる', exact=True).click()
    section.get_by_role('button', name='Expoを接続', exact=True).click()
    expect(password).to_have_value('')
    username.fill('fixture-user')
    password.fill(PASSWORD)
    dialog.get_by_role('button', name='ログインして接続', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert len(cli('accounts')['accounts']) == 2, 'the approved key uses a connection the owner adds later'
    section.locator('.account-item').filter(has_text='otp-user').click()
    section.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_role('link', name='Expoでキーを削除する', exact=False)).to_have_count(0)
    expect(dialog.get_by_text('Expoのプロジェクトやデータは削除しません。', exact=False)).to_be_visible()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert len(cli('accounts')['accounts']) == 1, 'the other connection stays usable'
    review(page)
    page.goto(args.base + '/connect/' + 'Z' * 43, wait_until='networkidle')
    expect(page.get_by_role('heading', name='依頼を確認できません', exact=True)).to_be_visible()
    expect(password).to_have_count(0)
    review(page)
    assert not errors, errors
    assert PASSWORD not in '\n'.join(logs) and 'fixture-session-' not in '\n'.join(logs)
    context.close()
    browser.close()
    print('Expo login browser flow passed: combined login/approval, MFA/retry, private fields cleared, timeout, existing accounts, runtime wait, root isolation, revocation, expiry and responsive copy. Expo and email calls were mocked; no real credentials or paid operations.')
