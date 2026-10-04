import argparse
import base64
import hashlib
import json
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from ui_flows import allow_foundation

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
    owner = browser.new_context(locale='ja-JP').new_page()
    owner.goto(args.base + '/', wait_until='networkidle')
    owner.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    owner.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(owner.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    owner.goto(args.base + '/signin/confirm#token=' + base64.urlsafe_b64encode(hashlib.sha256(b'owner@example.test').digest()).rstrip(b'=').decode() + '&email=owner%40example.test', wait_until='networkidle')
    owner.get_by_role('button', name='サインイン', exact=True).click()
    owner.wait_for_load_state('networkidle')
    owner.set_viewport_size({'width': 1280, 'height': 1000})
    # The registration lives on its own page, reached through the account, not the home.
    owner.get_by_role('link', name='アカウント', exact=True).click()
    owner.wait_for_url('**/account')
    expect(owner.get_by_role('heading', name='製品に組み込む', exact=True)).to_be_visible()
    owner.get_by_role('button', name='アプリを登録').click()
    dialog = owner.get_by_role('dialog')
    dialog.get_by_label('名前', exact=True).fill('ai-simplicity')
    dialog.get_by_label('戻り先のURL', exact=True).fill('https://simplicity.example.test/foundation')
    dialog.get_by_label('リンクが使えないときの戻り先（省略可）', exact=True).fill('https://simplicity.example.test/foundation/again')
    dialog.get_by_role('button', name='アプリキーを発行').click()
    expect(dialog.get_by_role('heading', name='ai-simplicity のアプリキー', exact=True)).to_be_visible()
    product = dialog.get_by_label('アプリキー', exact=True).input_value()
    assert product.startswith('fdn_')
    dialog.locator('button.primary', has_text='閉じる').click()
    owner.get_by_role('link', name='プリンシパル', exact=True).click()
    section = owner.get_by_role('region', name='プリンシパル', exact=True)
    expect(section.get_by_role('heading', name='ai-simplicity', exact=True)).to_be_visible()
    section.get_by_role('article').filter(has_text='ai-simplicity').get_by_role('button', name='詳細', exact=True).click()
    expect(dialog.get_by_text('クレデンシャル', exact=True)).to_be_visible()
    expect(dialog.locator('.credential-item')).to_have_count(1)
    dialog.get_by_role('button', name='閉じる', exact=True).click()
    review(owner)
    owner.screenshot(path=str(shots / 'integrations.png'), full_page=True)

    # The product makes its user's account and key; the user's AI asks for something to keep.
    user = call('/v1/principals', product, 'POST', {'alias': 'user-1'})['principal']
    key = call('/v1/principals/' + user['id'] + '/credentials', product, 'POST', {'kind': 'key'})['token']
    # What the user keeps is injected by Foundation's principal, which the user makes their agent.
    call('/v1/principals/agent/relations', key, 'POST', {'relation': 'agent', 'object_type': 'principal', 'object_id': call('/v1/principals/me', key)['principal']['id']})
    asked = call('/v1/requests', key, 'POST', {'operations': [{'method': 'PUT', 'path': '/v1/principals/me/resources?kind=secret&name=npm-api-token',
                                                                'inputs': [{'at': '', 'label': 'npm のアクセストークン', 'kind': 'sealed', 'site': 'https://www.npmjs.com/'}]}],
                                             'binding_message': 'パッケージの公開に使います。', 'steps': ['npmjs.com でアクセストークンを作ります。', '表示されたトークンをここに貼ります。']})['request']
    link = call('/v1/principals/' + user['id'] + '/links', product, 'POST', {'request_id': asked['id']})['url']

    # The user, who has never signed up for Foundation, opens the link the product handed them.
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 1000})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(link, wait_until='networkidle')
    expect(page.get_by_role('heading', name='シークレットを保存する', exact=True)).to_be_visible()
    assert '#' not in page.url, 'the link is taken out of the address bar once spent'
    expect(page.get_by_role('button', name='サインアウト')).to_have_count(0)
    expect(page.get_by_text('パッケージの公開に使います。', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'link-request.png'), full_page=True)
    page.get_by_label('npm のアクセストークン', exact=True).fill(SECRET)
    page.get_by_role('button', name='許可して実行する').click()
    expect(page.get_by_role('heading', name='依頼に応えました', exact=True)).to_be_visible()
    expect(page.get_by_role('main').get_by_role('link')).to_have_text(['ai-simplicityに戻る'])
    returned = page.get_by_role('link', name='ai-simplicityに戻る').get_attribute('href')
    assert returned == 'https://simplicity.example.test/foundation?foundation_request=' + asked['id'] + '&foundation_status=granted', returned
    review(page)
    page.screenshot(path=str(shots / 'link-done.png'), full_page=True)
    assert call('/v1/requests/' + asked['id'], key)['request']['results'][0]['body']['resource']['name'] == 'npm-api-token'
    delivered = call('/v1/principals/me/injections', key, 'POST', {'names': [{'name': 'npm-api-token', 'as': 'NPM_TOKEN'}]})
    assert delivered['injection']['environment']['NPM_TOKEN'] == SECRET

    # The same link opened again reaches nothing.
    again = browser.new_context(locale='ja-JP').new_page()
    again.goto(link, wait_until='networkidle')
    expect(again.get_by_role('heading', name='シークレットを保存する', exact=True)).to_have_count(0)
    expect(again.get_by_role('button', name='サインアウト')).to_have_count(0)
    assert again.get_by_role('link', name='ai-simplicityに戻る').get_attribute('href') == 'https://simplicity.example.test/foundation/again?foundation_request=' + asked['id']
    review(again)
    again.screenshot(path=str(shots / 'link-spent.png'), full_page=True)
    assert not errors, errors
    browser.close()
print('Link flow passed: a product registered once, its user opened a single-use link with no Foundation signin, kept one value for their own key, and the spent link reached nothing.')
