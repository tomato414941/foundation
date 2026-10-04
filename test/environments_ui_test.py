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
    owner = call('GET', '/v1/principals/me', token=token)['principal']['acts_for'][0]

    # Nothing open yet: the page says so, with the month's computing.
    # A page of its own, beside the other things one holds, reached from the menu.
    page.goto(args.base + '/', wait_until='networkidle')
    page.locator('.page-nav').get_by_role('link', name='エンバイロメント', exact=True).click()
    expect(page).to_have_url(args.base + '/environments')
    expect(page.get_by_role('heading', name='エンバイロメント', exact=True)).to_be_visible()
    expect(page.get_by_text('リソースなし', exact=True)).to_be_visible()
    expect(page.get_by_text('今月の計算時間', exact=False)).to_be_visible()

    # 名前と自動停止時間を選び、詳細設定を開いて環境を作成する。
    page.get_by_role('button', name='作成', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_role('heading', name='エンバイロメントを作成', exact=True)).to_be_visible()
    expect(dialog.get_by_label('自動停止', exact=True)).to_have_value('60')
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 900})
        review(page)
        page.screenshot(path=str(shots / f'environment-create-{width}.png'), full_page=True)
    dialog.get_by_label('名前', exact=False).fill('ビルド')
    dialog.get_by_label('自動停止', exact=True).select_option('30')
    dialog.get_by_text('詳細設定', exact=True).click()
    expect(dialog.get_by_label('イメージ', exact=True)).to_have_value('default')
    dialog.get_by_label('イメージ', exact=True).select_option('custom')
    dialog.get_by_label('コンテナイメージ名', exact=True).fill('python:3.12-slim')
    dialog.get_by_label('サイズ', exact=True).select_option('medium')
    dialog.get_by_label('Foundationへのアクセス', exact=True).select_option(owner)
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        page.screenshot(path=str(shots / f'environment-create-options-{width}.png'), full_page=True)

    # 作成中は重複送信を防ぎ、失敗したときは入力を保って再試行する。
    pending = []
    endpoint = args.base + '/v1/principals/' + owner + '/environments'
    page.route(endpoint, lambda route: pending.append(route))
    dialog.get_by_role('button', name='作成', exact=True).click()
    expect(dialog.get_by_role('button', name='作成中…', exact=True)).to_be_disabled()
    expect(dialog.get_by_label('名前', exact=False)).to_be_disabled()
    page.keyboard.press('Enter')
    assert len(pending) == 1
    pending[0].fulfill(status=503, content_type='application/json', body=json.dumps({'error': {'code': 'runner_unavailable', 'message': '現在作成できません。もう一度お試しください。'}}))
    expect(dialog.get_by_role('alert')).to_have_text('現在作成できません。もう一度お試しください。')
    expect(dialog.get_by_label('名前', exact=False)).to_have_value('ビルド')
    expect(dialog.get_by_label('イメージ', exact=True)).to_have_value('custom')
    expect(dialog.get_by_label('コンテナイメージ名', exact=True)).to_have_value('python:3.12-slim')
    expect(dialog.get_by_label('自動停止', exact=True)).to_have_value('30')
    expect(dialog.get_by_role('button', name='作成', exact=True)).to_be_enabled()
    page.unroute(endpoint)
    dialog.get_by_role('button', name='作成', exact=True).click()
    expect(page.get_by_text('作成しました。', exact=True)).to_be_visible()
    as_owner = next(item for item in call('GET', '/v1/principals/' + owner + '/resources?kind=environment', token=token)['resources'] if item['name'] == 'ビルド')
    assert as_owner['identity'] == owner
    assert as_owner['image'] == 'python:3.12-slim'
    assert as_owner['size'] == 'medium'
    assert as_owner['lifetime']['max_seconds'] == 1800
    assert as_owner['lifetime']['idle_seconds'] == 1800

    # カスタムから標準へ戻すと、標準イメージ・権限なし・Small・1時間の設定で作成する。
    page.get_by_role('button', name='作成', exact=True).click()
    dialog.get_by_label('名前', exact=False).fill('調べもの')
    dialog.get_by_text('詳細設定', exact=True).click()
    dialog.get_by_label('イメージ', exact=True).select_option('custom')
    dialog.get_by_label('コンテナイメージ名', exact=True).fill('python:3.12-slim')
    dialog.get_by_label('イメージ', exact=True).select_option('default')
    dialog.get_by_role('button', name='作成', exact=True).click()
    expect(page.locator('.access-row').filter(has_text='調べもの')).to_be_visible()
    research = next(item for item in call('GET', '/v1/principals/' + owner + '/resources?kind=environment', token=token)['resources'] if item['name'] == '調べもの')
    assert research['identity'] is None
    assert research['image'] is None
    assert research['size'] == 'small'
    assert research['lifetime']['max_seconds'] == 3600
    assert research['lifetime']['idle_seconds'] == 3600
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
    gone = caller.get('/v1/resources/' + as_owner['id'], headers={'authorization': 'Bearer ' + token})
    assert gone.status == 404, 'closed from the page, it is gone'

    # 英語表示でも作成フォームを操作し、名前を省略して作成する。
    context.add_cookies([{'name': 'foundation_locale', 'value': 'en', 'url': args.base}])
    page.reload(wait_until='networkidle')
    page.get_by_role('button', name='Create', exact=True).click()
    expect(dialog.get_by_role('heading', name='Create environment', exact=True)).to_be_visible()
    expect(dialog.get_by_label('Stop automatically', exact=True)).to_have_value('60')
    dialog.get_by_text('Options', exact=True).click()
    expect(dialog.get_by_label('Image', exact=True)).to_have_value('default')
    expect(dialog.get_by_label('Foundation access', exact=True)).to_have_value('')
    page.screenshot(path=str(shots / 'environment-create-en.png'), full_page=True)
    dialog.get_by_role('button', name='Create', exact=True).click()
    expect(page.get_by_text('Environment created.', exact=True)).to_be_visible()
    expect(page.locator('.access-row').filter(has_text='エンバイロメント')).to_be_visible()
    assert not errors, errors
    context.close()
    browser.close()
    print('画面から環境を作成する。設定を反映し、失敗時は入力を保って再試行する。日本語・英語とデスクトップ・モバイルで表示し、環境を閉じる。')
