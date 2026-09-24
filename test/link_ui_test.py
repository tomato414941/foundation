import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
SECRET = 'npm_link-ui-fixture-value'


def call(path, token, method='GET', data=None):
    request = urllib.request.Request(args.base + path, method=method, data=None if data is None else json.dumps(data).encode(),
                                     headers={'authorization': 'Bearer ' + token, **({'content-type': 'application/json'} if data is not None else {})})
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '開発者', '設計意図', 'fdn_', 'fdni_', SECRET]:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    # The owner of Foundation registers the product once.
    owner = browser.new_context().new_page()
    owner.goto(args.base + '/', wait_until='networkidle')
    owner.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    owner.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(owner.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    owner.goto(args.base + '/auth/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    owner.set_viewport_size({'width': 1280, 'height': 1000})
    # The registration lives on its own page, reached through the account, not the home.
    owner.get_by_role('link', name='アカウント', exact=True).click()
    owner.wait_for_url('**/account')
    owner.get_by_role('link', name='アプリの登録', exact=True).click()
    owner.wait_for_url('**/developers')
    expect(owner.get_by_role('heading', name='アプリ', exact=True)).to_be_visible()
    owner.get_by_role('button', name='アプリを登録').click()
    dialog = owner.get_by_role('dialog')
    dialog.get_by_label('名前', exact=True).fill('ai-simplicity')
    dialog.get_by_label('戻り先のURL', exact=True).fill('https://simplicity.example.test/foundation')
    dialog.get_by_label('リンクが使えないときの戻り先（省略可）', exact=True).fill('https://simplicity.example.test/foundation/again')
    dialog.get_by_role('button', name='アプリキーを発行').click()
    expect(dialog.get_by_role('heading', name='ai-simplicity のアプリキー', exact=True)).to_be_visible()
    product = dialog.get_by_label('アプリキー', exact=True).input_value()
    assert product.startswith('fdni_')
    dialog.locator('button.primary', has_text='閉じる').click()
    section = owner.locator('[aria-labelledby="integration-title"]')
    expect(section.get_by_role('heading', name='ai-simplicity', exact=True)).to_be_visible()
    expect(section.get_by_text('simplicity.example.test · 利用者 0 人', exact=True)).to_be_visible()
    review(owner)
    owner.screenshot(path=str(shots / 'integrations.png'), full_page=True)

    # The product makes its user's account and key; the user's AI asks for something to keep.
    call('/v1/integration/accounts/user-1', product, 'PUT', {})
    key = call('/v1/integration/accounts/user-1/keys', product, 'POST', {'name': 'ai-simplicity'})['key']['token']
    asked = call('/v1/requests', key, 'POST', {'store': {'name': 'npm-token', 'label': 'npm のアクセストークン', 'site': 'https://www.npmjs.com/'},
                                             'purpose': 'パッケージの公開に使います。', 'steps': ['npmjs.com でアクセストークンを作ります。', '表示されたトークンをここに貼ります。']})['request']
    link = call('/v1/integration/links', product, 'POST', {'request_id': asked['id']})['url']

    # The user, who has never signed up for Foundation, opens the link the product handed them.
    context = browser.new_context(viewport={'width': 1280, 'height': 1000})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(link, wait_until='networkidle')
    expect(page.get_by_role('heading', name='npm のアクセストークンを預ける', exact=True)).to_be_visible()
    assert '#' not in page.url, 'the link is taken out of the address bar once spent'
    expect(page.get_by_role('button', name='ログアウト')).to_have_count(0)
    expect(page.get_by_text('パッケージの公開に使います。', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'link-request.png'), full_page=True)
    page.get_by_label('保存名', exact=True).fill('npm-api-token')
    page.get_by_label('npm のアクセストークン', exact=True).fill(SECRET)
    page.get_by_role('button', name='登録する').click()
    expect(page.get_by_role('heading', name='登録しました', exact=True)).to_be_visible()
    expect(page.get_by_role('main').get_by_role('link')).to_have_text(['ai-simplicityに戻る'])
    returned = page.get_by_role('link', name='ai-simplicityに戻る').get_attribute('href')
    assert returned == 'https://simplicity.example.test/foundation?foundation_request=' + asked['id'] + '&foundation_status=done', returned
    review(page)
    page.screenshot(path=str(shots / 'link-done.png'), full_page=True)
    assert call('/v1/requests/' + asked['id'], key)['request']['result']['names'] == ['npm-api-token']
    delivered = call('/v1/deliver', key, 'POST', {'names': [{'name': 'npm-api-token', 'as': 'NPM_TOKEN'}]})
    assert delivered['delivery']['environment']['NPM_TOKEN'] == SECRET

    # The same link opened again reaches nothing.
    again = browser.new_context().new_page()
    again.goto(link, wait_until='networkidle')
    expect(again.get_by_role('heading', name='npm のアクセストークンを預ける', exact=True)).to_have_count(0)
    expect(again.get_by_role('button', name='ログアウト')).to_have_count(0)
    assert again.get_by_role('link', name='ai-simplicityに戻る').get_attribute('href') == 'https://simplicity.example.test/foundation/again?foundation_request=' + asked['id']
    review(again)
    again.screenshot(path=str(shots / 'link-spent.png'), full_page=True)
    assert not errors, errors
    browser.close()
print('Link flow passed: a product registered once, its user opened a single-use link with no Foundation login, kept one value for their own key, and the spent link reached nothing.')
