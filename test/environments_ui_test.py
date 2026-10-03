import argparse
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)

# The words a person reads on this page, and none of what only a developer would say.
def review(page):
    text = page.locator('body').inner_text()
    for phrase in ['runner', 'machine', 'environment', 'identity', 'Fly', '実装', 'fdn_']:
        assert phrase not in text, phrase
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 1000})
    caller = p.request.new_context(base_url=args.base, extra_http_headers={'origin': args.base})

    def call(method, path, data=None, token=None):
        result = caller.fetch(path, method=method, data=None if data is None else json.dumps(data),
                              headers={'content-type': 'application/json', **({'authorization': 'Bearer ' + token} if token else {})})
        assert result.ok, str(result.status) + ' ' + result.text()
        return result.json()

    actor = call('POST', '/v1/principals', {'kind': 'key', 'name': '作業用AI'})
    token = actor['token']
    asked = call('POST', '/v1/requests', {'authorization_details': [{'type': 'relation', 'relation': 'agent'}]}, token)['request']
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(asked['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    callback = args.base + '/signin/confirm?' + urlencode({'return_to': '/requests/' + asked['id']})
    page.goto(callback + '#token=' + base64.urlsafe_b64encode(hashlib.sha256(b'owner@example.test').digest()).rstrip(b'=').decode() + '&email=owner%40example.test', wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.get_by_label('確認コード', exact=True).fill(asked['user_code'])
    page.get_by_role('button', name='許可する', exact=True).click()
    expect(page.get_by_role('heading', name='アクセスを許可しました', exact=True)).to_be_visible()
    owner = call('GET', '/v1/principals/me', token=token)['acts_for'][0]

    # Nothing open yet: the page says so, with the month's computing.
    # A page of its own, beside the other things one holds, reached from the menu.
    page.goto(args.base + '/', wait_until='networkidle')
    page.locator('.page-nav').get_by_role('link', name='エンバイロメント', exact=True).click()
    expect(page).to_have_url(args.base + '/environments')
    expect(page.get_by_role('heading', name='エンバイロメント', exact=True)).to_be_visible()
    expect(page.get_by_text('開いているエンバイロメントはありません。', exact=True)).to_be_visible()
    expect(page.get_by_text('今月の計算時間', exact=False)).to_be_visible()

    # The AI opens two: one acting as the owner, one with no identity at all.
    as_owner = call('POST', '/v1/principals/' + owner + '/environments', {'name': 'ビルド', 'identity': owner}, token)['environment']
    call('POST', '/v1/principals/' + owner + '/environments', {'name': '調べもの'}, token)
    page.reload(wait_until='networkidle')
    building = page.locator('.access-row').filter(has_text='ビルド')
    expect(building.get_by_text('待機中 · あなたとして動作', exact=True)).to_be_visible()
    expect(page.locator('.access-row').filter(has_text='調べもの').get_by_text('待機中 · 権限なし', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / f'environments-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Closing one from the page.
    building.get_by_role('button', name='閉じる', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text('中のファイルは消え、このエンバイロメントに渡した鍵は使えなくなります。', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='エンバイロメントを閉じる', exact=True).click()
    expect(page.get_by_text('閉じました。', exact=True)).to_be_visible()
    expect(page.locator('.access-row').filter(has_text='ビルド')).to_have_count(0)
    gone = caller.get('/v1/environments/' + as_owner['id'], headers={'authorization': 'Bearer ' + token})
    assert gone.status == 404, 'closed from the page, it is gone'
    assert not errors, errors
    context.close()
    browser.close()
    print('Environments on the access page: listed with who they act as, the month\'s computing, closed from the page, desktop and mobile.')
