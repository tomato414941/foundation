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

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 1000})
    caller = p.request.new_context(base_url=args.base, extra_http_headers={'origin': args.base})

    def post(path, data, token=None):
        result = caller.post(path, data=json.dumps(data), headers={'content-type': 'application/json', **({'authorization': 'Bearer ' + token} if token else {})})
        assert result.ok, str(result.status)
        return result.json()

    actor = post('/v1/principals', {'kind': 'key', 'name': 'laptop の作業用AI'})
    token = actor['token']
    asked = post('/v1/requests', {'authorization_details': [{'type': 'relation', 'relation': 'agent'}], 'binding_message': '保存した認証情報を使って接続を確認します。'}, token)['request']
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
    expect(page.get_by_role('heading', name='アクセスを許可する', exact=True)).to_be_visible()
    expect(page.get_by_text('laptop の作業用AIの依頼', exact=True)).to_be_visible()
    expect(page.get_by_text('owner@example.test', exact=True)).to_be_visible()
    expect(page.get_by_text('保存した認証情報を使って接続を確認します。', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        expect(page.get_by_text('認証情報とオブジェクトの取得・追加・更新・削除', exact=True)).to_be_visible()
        expect(page.get_by_text('接続済みサービスの利用とファンクションの実行', exact=True)).to_be_visible()
        expect(page.get_by_text('接続の追加・解除、他の相手への権限付与、アカウント管理は含みません。', exact=True)).to_be_visible()
        expect(page.get_by_text('今後追加するものも含め、取り消すまで有効です。', exact=True)).to_be_visible()
        label_box = page.get_by_text('目的', exact=True).bounding_box()
        purpose_box = page.get_by_text('保存した認証情報を使って接続を確認します。', exact=True).bounding_box()
        permissions_box = page.get_by_text('権限', exact=True).bounding_box()
        assert purpose_box['y'] >= label_box['y'] + label_box['height'] + 3, 'purpose appears below its label'
        assert abs(purpose_box['x'] - label_box['x']) < 1, 'purpose aligns with its label'
        assert permissions_box['y'] >= purpose_box['y'] + purpose_box['height'], 'purpose appears before permissions'
        if width != 320:
            page.screenshot(path=str(shots / f'approval-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})
    page.get_by_label('確認コード', exact=True).fill(asked['user_code'])
    page.get_by_role('button', name='許可する', exact=True).click()
    expect(page.get_by_role('heading', name='アクセスを許可しました', exact=True)).to_be_visible()
    page.get_by_role('link', name='プリンシパル', exact=True).click()
    row = page.locator('.access-row').filter(has_text='laptop の作業用AI')
    expect(row).to_be_visible()
    row.get_by_role('button', name='詳細', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_role('heading', name='アクセスキー', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='名前を編集', exact=True).click()
    dialog.get_by_label('名前', exact=True).fill('laptop のアシスタント')
    dialog.get_by_role('button', name='保存', exact=True).click()
    expect(dialog.get_by_role('heading', name='laptop のアシスタント', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='キーを発行', exact=True).click()
    expect(dialog.get_by_label('アクセスキー', exact=True)).to_be_visible()
    second_token = dialog.get_by_label('アクセスキー', exact=True).input_value()
    dialog.get_by_role('button', name='完了', exact=True).click()
    expect(dialog.locator('.connection-list li')).to_have_count(2)
    me = caller.get('/v1/principals/me', headers={'authorization': 'Bearer ' + token}).json()
    owner = me['principal']['acts_for'][0]
    original_key = actor['credential']['id'][:8]
    dialog.locator('.connection-list li').filter(has_text=original_key).get_by_role('button', name='失効', exact=True).click()
    expect(dialog.get_by_text('このキーは使えなくなります。他のキーとアクセス許可は残ります。', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='失効させる', exact=True).click()
    expect(dialog.locator('.connection-list li')).to_have_count(1)
    assert caller.get('/v1/principals/me', headers={'authorization': 'Bearer ' + token}).status == 401
    assert caller.get('/v1/principals/' + owner + '/resources?kind=connection', headers={'authorization': 'Bearer ' + second_token}).status == 200
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        expect(dialog.get_by_role('button', name='失効', exact=True)).to_be_visible()
        if width != 320:
            page.screenshot(path=str(shots / f'details-{width}.png'), full_page=True)
    dialog.get_by_role('button', name='閉じる', exact=True).click()
    row = page.locator('.access-row').filter(has_text='laptop のアシスタント')
    for width in [1280, 1024, 900, 801, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        expect(row.get_by_role('button', name='取り消す', exact=True)).to_be_visible()
        if width in [1280, 390]:
            page.screenshot(path=str(shots / f'access-{width}.png'), full_page=True)
    row.get_by_role('button', name='取り消す', exact=True).click()
    dialog.get_by_role('button', name='許可を取り消す', exact=True).click()
    expect(row.get_by_text('全体へのアクセス許可なし', exact=True)).to_be_visible()
    own = caller.get('/v1/principals/me', headers={'authorization': 'Bearer ' + second_token})
    assert own.status == 200 and own.json()['principal']['id'] == actor['principal']['id']
    assert own.json()['principal']['acts_for'] == []
    assert caller.get('/v1/principals/' + owner + '/resources?kind=connection', headers={'authorization': 'Bearer ' + second_token}).status == 403
    row.get_by_role('button', name='詳細', exact=True).click()
    expect(dialog.get_by_text('全体へのアクセス許可なし', exact=True)).to_be_visible()
    expect(dialog.locator('.connection-list li')).to_have_count(1)
    assert not errors, errors
    caller.dispose()
    context.close()
    browser.close()
    print('Access UI passed: named approval, purpose, account, details, rename, individual key revocation, account access revocation and responsive layout.')
