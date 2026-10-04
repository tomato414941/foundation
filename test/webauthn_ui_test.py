import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import urlencode, urlparse
from playwright.sync_api import sync_playwright, expect
from ui_flows import open_menu

# Passkeys in the browser, with Chromium's virtual authenticator standing in for the device: added from the account
# page, used to sign in, and removed - which ends the session it proved. WebAuthn needs a hostname, so the fixture
# server is reached as localhost.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
base = args.base.replace('127.0.0.1', 'localhost')
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
email = 'passkey@example.test'
token = base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['credential', 'WebAuthn', '実装', '設計意図']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 390, 'height': 844})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    device = context.new_cdp_session(page)
    device.send('WebAuthn.enable')
    device.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
                                                                 'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True, 'hasPrf': True}})

    # Signed in by email first, the account page offers to add a passkey.
    page.goto(base + '/account', wait_until='networkidle')
    expect(page.get_by_role('button', name='パスキーでサインイン', exact=True)).to_be_visible()
    page.screenshot(path=str(shots / 'signin-390.png'), full_page=True)
    review(page)
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(base + '/signin/confirm?' + urlencode({'return_to': '/account'}) + '#' + urlencode({'token': token, 'email': email}), wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(base + '/account')
    section = page.get_by_role('region', name='パスキー')
    page.get_by_role('button', name='パスキーを追加').click()
    dialog = page.get_by_role('dialog')
    dialog.get_by_label('名前', exact=True).fill('テスト端末')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(page.get_by_text('パスキーを追加しました。このパスキーは、この端末にしか保存されていません。', exact=True)).to_be_visible()
    expect(section.get_by_role('heading', name='テスト端末', exact=True)).to_be_visible()
    page.screenshot(path=str(shots / 'account-390.png'), full_page=True)
    review(page)

    # Signing out and back in with the passkey alone, back to the page left.
    open_menu(page)
    page.get_by_role('button', name='サインアウト', exact=True).click()
    page.get_by_role('button', name='パスキーでサインイン', exact=True).click()
    expect(page.get_by_role('heading', name='アカウント', exact=True)).to_be_visible()
    assert urlparse(page.url).path == '/account', 'back where signing out left off: ' + page.url

    # Removing the passkey that proved this session ends it.
    page.goto(base + '/account', wait_until='networkidle')
    page.get_by_role('region', name='パスキー').get_by_role('button', name='削除', exact=True).click()
    page.get_by_role('dialog').get_by_role('button', name='削除する', exact=True).click()
    expect(page.get_by_role('heading', name='サインイン', exact=True)).to_be_visible()

    # Someone new starts with a passkey alone, in a browser of their own.
    newcomer = browser.new_context(locale='ja-JP', viewport={'width': 390, 'height': 844})
    fresh = newcomer.new_page()
    fresh.on('pageerror', lambda error: errors.append(str(error)))
    other = newcomer.new_cdp_session(fresh)
    other.send('WebAuthn.enable')
    other.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
                                                                'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True, 'hasPrf': True}})
    fresh.goto(base, wait_until='networkidle')
    fresh.screenshot(path=str(shots / 'start-390.png'), full_page=True)
    review(fresh)
    # One press: nothing is asked.
    fresh.get_by_role('button', name='パスキーで始める', exact=True).click()
    started = fresh.get_by_role('dialog')
    expect(started.get_by_text('このパスキーは、この端末にしか保存されていません。', exact=True)).to_be_visible()
    started.get_by_role('button', name='続ける', exact=True).click()
    expect(fresh.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()
    import re
    assert re.fullmatch(r"[A-Z][A-Za-z' ]+ [A-Z][A-Za-z' ]+", newcomer.request.get(base + '/v1/principals/me').json()['principal']['name']), 'named by a role at a star'
    # A name is given on the account page, when wanted.
    fresh.goto(base + '/account', wait_until='networkidle')
    fresh.get_by_role('button', name='名前を変更', exact=True).click()
    fresh.get_by_role('dialog').get_by_label('名前', exact=True).fill('はじめての人')
    fresh.get_by_role('dialog').get_by_role('button', name='保存', exact=True).click()
    expect(fresh.get_by_role('region', name='名前').get_by_text('はじめての人', exact=True)).to_be_visible()
    review(fresh)
    assert newcomer.request.get(base + '/v1/principals/me').json()['principal']['name'] == 'はじめての人'
    # A passkey is added to a subprincipal the same way as to oneself: made here, listed among its credentials.
    fresh.goto(base + '/principals', wait_until='networkidle')
    fresh.get_by_role('button', name='作成', exact=True).click()
    box = fresh.get_by_role('dialog')
    box.get_by_label('名前', exact=True).fill('分けた置き場所')
    box.get_by_role('button', name='作成', exact=True).click()
    expect(box.get_by_role('heading', name='分けた置き場所', exact=True)).to_be_visible()
    box.get_by_role('button', name='追加', exact=True).click()
    box.get_by_role('button', name='パスキー', exact=True).click()
    box.locator('form button[type=submit]').click()
    expect(box.locator('.detail-row').filter(has_text='クレデンシャル')).to_contain_text('パスキー')
    review(fresh)
    # Switching shows what the subprincipal holds: a secret placed there is opened there, and is not one's own.
    box.get_by_role('button', name='切り替え', exact=True).click()
    fresh.wait_for_url(base + '/services')
    expect(fresh.get_by_text('分けた置き場所 を表示中', exact=True)).to_be_visible()
    open_menu(fresh)
    fresh.get_by_role('navigation').get_by_role('link', name='シークレット', exact=True).click()
    expect(fresh.get_by_text('分けた置き場所 を表示中', exact=True)).to_be_visible()
    fresh.get_by_role('button', name='追加', exact=True).click()
    box.get_by_label('名前', exact=True).fill('分けた鍵')
    box.get_by_label('値', exact=True).fill('only-there')
    box.locator('form button[type=submit]').click()
    expect(fresh.get_by_role('heading', name='分けた鍵', exact=True)).to_be_visible()
    review(fresh)
    fresh.screenshot(path=str(shots / 'switched.png'), full_page=True)
    held = newcomer.request.get(base + '/v1/principals/me/resources?kind=secret').json()['resources']
    assert [item['name'] for item in held] == [], held
    fresh.get_by_role('button', name='自分に戻る', exact=True).click()
    expect(fresh.get_by_text('分けた置き場所 を表示中', exact=True)).to_have_count(0)
    # Not among one's own; having placed it there, one may still use it, and it is listed as shared.
    expect(fresh.get_by_role('region', name='シークレット', exact=True).get_by_role('heading', name='分けた鍵', exact=True)).to_have_count(0)
    expect(fresh.get_by_role('region', name='共有アイテム', exact=True).get_by_role('heading', name='分けた鍵', exact=True)).to_be_visible()
    assert not errors, errors
    browser.close()
    print('パスキー: アカウントでの追加・パスキーだけでのサインイン・削除によるセッションの終了・パスキーだけで始めることと、スマートフォンの表示を確認しました。')
