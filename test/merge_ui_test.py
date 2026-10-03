import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect
from ui_flows import virtual_authenticator, unlock, hand_to_foundation, plain, injected

# An account begun with a passkey, then made one with the email account from the account page: its secret, its
# passkey and its key come over, opened here with that passkey.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
base = args.base.replace('127.0.0.1', 'localhost')
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
email = 'keeper@example.test'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '設計意図', 'fdn_', 'merge']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 390, 'height': 844})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    virtual_authenticator(context, page)

    # The other account: begun with a passkey, with a secret Foundation may use.
    page.goto(base, wait_until='networkidle')
    page.get_by_role('button', name='パスキーで始める', exact=True).click()
    page.get_by_role('dialog').get_by_role('button', name='続ける', exact=True).click()
    expect(page.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()
    other = context.request.get(base + '/v1/overview').json()
    unlock(page, base)
    hand_to_foundation(page)
    page.get_by_role('button', name='追加', exact=True).click()
    dialog = page.get_by_role('dialog')
    dialog.get_by_label('名前', exact=True).fill('their secret')
    dialog.get_by_label('値', exact=True).fill('their-value')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(page.get_by_role('article', name='their secret', exact=True)).to_be_visible()

    # This account: signed in by email, in the same browser.
    page.get_by_role('link', name='アカウント', exact=True).click()
    page.get_by_role('button', name='サインアウト', exact=True).click()
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(base + '/signin/confirm?' + urlencode({'return_to': '/account'}) + '#' + urlencode({'token': base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode(), 'email': email}), wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(base + '/account')
    mine = context.request.get(base + '/v1/overview').json()
    assert mine['user']['id'] != other['user']['id']
    review(page)
    page.screenshot(path=str(shots / 'account-390.png'), full_page=True)
    page.get_by_role('region', name='アカウントを統合する').get_by_role('button', name='統合する', exact=True).click()
    dialog = page.get_by_role('dialog')
    # First which way, then the other account by its ID and its passkey, then what will happen.
    expect(dialog.get_by_role('radio', name='別のアカウントをこのアカウントに取り込む')).to_be_checked()
    expect(dialog.get_by_role('radio', name='このアカウントを別のアカウントに取り込む')).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'merge-direction-390.png'), full_page=True)
    dialog.get_by_role('button', name='次へ', exact=True).click()
    dialog.get_by_label('相手のアカウントの ID', exact=True).fill(other['user']['id'])
    review(page)
    dialog.get_by_role('button', name='パスキーで確認する', exact=True).click()
    expect(dialog.get_by_text(other['principal']['name'] + ' の持ち物・パスキー・メールアドレスがこのアカウントのものになり、' + other['principal']['name'] + ' はなくなります。', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'merge-390.png'), full_page=True)
    dialog.get_by_role('button', name='統合する', exact=True).click()
    expect(dialog).not_to_be_visible()
    passkeys = context.request.get(base + '/v1/webauthn-credentials').json()['webauthn_credentials']
    assert len(passkeys) == 1, passkeys
    expect(page.get_by_role('region', name='パスキー').get_by_role('heading', name=passkeys[0]['name'], exact=True)).to_be_visible()
    assert [row['name'] for row in context.request.get(base + '/v1/resources?kind=secret').json()['resources']] == ['their secret']
    assert context.request.get(base + '/v1/principals/' + other['user']['id'] + '/public-key').status == 404, 'the other ended'

    # Its secret opens here, with the key made for this account from that passkey; and the passkey signs this account in.
    unlock(page, base)
    row = page.get_by_role('article', name='their secret', exact=True)
    expect(row.get_by_role('button', name='値を表示', exact=True)).to_be_enabled()
    row.get_by_role('button', name='値を表示', exact=True).click()
    expect(row.locator('.kept-document')).to_have_text('their-value')
    page.get_by_role('link', name='アカウント', exact=True).click()
    page.get_by_role('button', name='サインアウト', exact=True).click()
    page.get_by_role('button', name='パスキーでサインイン', exact=True).click()
    expect(page.get_by_role('heading', name='アカウント', exact=True)).to_be_visible()
    assert context.request.get(base + '/v1/overview').json()['user']['id'] == mine['user']['id']
    assert not errors, errors
    browser.close()
    print('アカウントを統合する: パスキーで始めた相手の秘密・パスキーがこちらのものになり、その鍵で開け、そのパスキーでこちらにサインインできることを確認しました。')
