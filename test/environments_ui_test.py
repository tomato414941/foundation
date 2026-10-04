import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs
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
    page.on('console', lambda message: errors.append(message.text) if message.type == 'error' and 'Content Security Policy' in message.text else None)
    catalog_attempts = {'search': 0, 'tags': 0}
    delayed_searches = []
    def catalog(route):
        query = parse_qs(urlparse(route.request.url).query)
        needle = query.get('query', [''])[0]
        number = query.get('page', ['1'])[0]
        is_tags = urlparse(route.request.url).path.endswith('/tags')
        kind = 'tags' if is_tags else 'search'
        catalog_attempts[kind] += 1
        if catalog_attempts[kind] == 1:
            route.fulfill(status=503, json={'error': {'code': 'image_catalog_unavailable', 'message': 'Docker Hubに接続できません。しばらく待ってからお試しください。'}})
        elif is_tags:
            if query.get('repository', [''])[0] == 'example/python':
                route.fulfill(json={'tags': [{'name': '1.0'}], 'next': None, 'default_tag': None})
            elif needle == 'none':
                route.fulfill(json={'tags': [], 'next': None})
            else:
                tags = ['3.12-slim'] if number == '2' else ['3.12.7-slim'] if needle == '3.12' else ['3.13-slim']
                route.fulfill(json={'tags': [{'name': name} for name in tags], 'next': None if number == '2' else 2, **({'default_tag': 'latest'} if not needle else {})})
        elif needle == 'slow':
            delayed_searches.append(route)
        else:
            route.fulfill(json={'images': [{'name': 'python', 'description': 'Python programming language.', 'official': True}, {'name': 'example/python', 'description': 'Python tools.', 'official': False}], 'next': None})
    page.route('**/v1/environment-images**', catalog)
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
    expect(dialog.get_by_role('button', name='60 分後 自動停止', exact=True)).to_be_visible()
    for width in [1280]:
        page.set_viewport_size({'width': width, 'height': 900})
        review(page)
        page.wait_for_timeout(400)
        page.screenshot(path=str(shots / f'environment-create-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})
    dialog.get_by_label('名前', exact=False).fill('ビルド')
    dialog.get_by_role('button', name='60 分後 自動停止', exact=True).click()
    page.get_by_role('option', name='30 分後', exact=True).click()
    dialog.get_by_text('詳細設定', exact=True).click()
    expect(dialog.get_by_role('combobox', name='イメージ', exact=True)).to_have_value('標準イメージ')
    dialog.get_by_role('combobox', name='イメージ', exact=True).fill('python')
    expect(page.get_by_role('option', name='再試行', exact=True)).to_contain_text('Docker Hubに接続できません。しばらく待ってからお試しください。')
    page.get_by_role('option', name='再試行', exact=True).click()
    dialog.get_by_role('combobox', name='イメージ', exact=True).fill('python')
    expect(page.get_by_role('option', name='python', exact=True)).to_be_visible()
    expect(page.get_by_role('option', name='python', exact=True)).to_contain_text('公式')
    for width in [1280]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        page.wait_for_timeout(400)
        page.screenshot(path=str(shots / f'environment-image-search-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # 前の検索が遅れて届いても、今入力した名前の候補を選択する。
    dialog.get_by_role('combobox', name='イメージ', exact=True).fill('slow')
    page.wait_for_timeout(400)
    assert len(delayed_searches) == 1
    dialog.get_by_role('combobox', name='イメージ', exact=True).fill('python')
    expect(page.get_by_role('option', name='python', exact=True)).to_be_visible()
    delayed_searches[0].fulfill(json={'images': [{'name': 'old-result', 'description': 'Old search', 'official': False}], 'next': None})
    page.get_by_role('option', name='python', exact=True).click()
    expect(dialog.get_by_text('Docker Hubに接続できません。しばらく待ってからお試しください。', exact=True)).to_be_visible()
    dialog.get_by_role('combobox', name='バージョン・種類', exact=True).click()
    expect(dialog.get_by_role('combobox', name='バージョン・種類', exact=True)).to_have_value('既定（latest）')
    dialog.get_by_role('combobox', name='バージョン・種類', exact=True).fill('none')
    expect(page.get_by_role('option', name='該当するバージョンがありません。', exact=True)).to_be_visible()
    dialog.get_by_role('combobox', name='バージョン・種類', exact=True).fill('3.12')
    expect(page.get_by_role('option', name='3.12.7-slim', exact=True)).to_be_visible()
    expect(page.get_by_role('option', name='3.12-slim', exact=True)).to_be_visible()
    page.get_by_role('option', name='3.12-slim', exact=True).click()
    dialog.get_by_role('button', name='候補を表示 バージョン・種類', exact=True).click()
    dialog.get_by_role('combobox', name='バージョン・種類', exact=True).press('Escape')
    expect(dialog.get_by_role('combobox', name='バージョン・種類', exact=True)).to_have_value('3.12-slim')
    dialog.get_by_role('button', name='Small サイズ', exact=True).click()
    page.get_by_role('option', name='Medium', exact=True).click()
    dialog.get_by_role('button', name='許可しない Foundationへのアクセス', exact=True).click()
    page.get_by_role('option', name='自分の権限で許可', exact=True).click()
    for width in [1280]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        page.wait_for_timeout(400)
        page.screenshot(path=str(shots / f'environment-create-options-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

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
    expect(dialog.get_by_role('combobox', name='イメージ', exact=True)).to_have_value('python')
    expect(dialog.get_by_role('combobox', name='バージョン・種類', exact=True)).to_have_value('3.12-slim')
    expect(dialog.get_by_role('button', name='30 分後 自動停止', exact=True)).to_be_visible()
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
    dialog.get_by_role('combobox', name='イメージ', exact=True).fill('python:3.12-slim')
    page.get_by_role('option', name='「python:3.12-slim」を使用', exact=True).click()
    dialog.get_by_role('button', name='候補を表示 イメージ', exact=True).click()
    page.get_by_role('option', name='標準イメージ', exact=True).click()
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
    for width in [1280]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width != 320:
            page.wait_for_timeout(400)
            page.screenshot(path=str(shots / f'environments-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # イメージを選ぶと既定のバージョンを自動で使って作成する。
    page.get_by_role('button', name='作成', exact=True).click()
    dialog.get_by_label('名前', exact=False).fill('既定バージョン')
    dialog.get_by_text('詳細設定', exact=True).click()
    dialog.get_by_role('combobox', name='イメージ', exact=True).fill('example/python')
    page.get_by_role('option', name='example/python', exact=True).click()
    dialog.get_by_role('combobox', name='バージョン・種類', exact=True).click()
    page.get_by_role('option', name='1.0', exact=True).click()
    expect(dialog.get_by_role('combobox', name='バージョン・種類', exact=True)).to_have_value('1.0')
    dialog.get_by_role('combobox', name='イメージ', exact=True).fill('python')
    page.get_by_role('option', name='python', exact=True).click()
    expect(dialog.get_by_role('combobox', name='バージョン・種類', exact=True)).to_have_value('既定（latest）')
    dialog.get_by_role('button', name='作成', exact=True).click()
    expect(page.locator('.access-row').filter(has_text='既定バージョン')).to_be_visible()
    defaulted = next(item for item in call('GET', '/v1/principals/' + owner + '/resources?kind=environment', token=token)['resources'] if item['name'] == '既定バージョン')
    assert defaulted['image'] == 'python:latest'

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
    expect(dialog.get_by_role('button', name='After 60 minutes Stop automatically', exact=True)).to_be_visible()
    dialog.get_by_text('Options', exact=True).click()
    expect(dialog.get_by_role('combobox', name='Image', exact=True)).to_have_value('Default image')
    expect(dialog.get_by_role('button', name='Do not allow Foundation access', exact=True)).to_be_visible()
    dialog.get_by_role('combobox', name='Image', exact=True).fill('ghcr.io/example/tools:stable')
    expect(page.get_by_role('option', name='Use ghcr.io/example/tools:stable', exact=True)).to_be_visible()
    dialog.get_by_role('combobox', name='Image', exact=True).press('ArrowDown')
    dialog.get_by_role('combobox', name='Image', exact=True).press('Enter')
    page.wait_for_timeout(400)
    page.screenshot(path=str(shots / 'environment-create-en.png'), full_page=True)
    dialog.get_by_role('button', name='Create', exact=True).click()
    expect(page.get_by_text('Environment created.', exact=True)).to_be_visible()
    expect(page.locator('.access-row').filter(has_text='エンバイロメント')).to_be_visible()
    named = next(item for item in call('GET', '/v1/principals/' + owner + '/resources?kind=environment', token=token)['resources'] if item['name'] == 'エンバイロメント')
    assert named['image'] == 'ghcr.io/example/tools:stable'
    # 作成フォームを開いたまま履歴を戻ると移動先を操作でき、もう一度フォームを開ける。
    page.locator('.page-nav a[href="/services"]').click()
    page.locator('.page-nav a[href="/environments"]').click()
    page.get_by_role('button', name='Create', exact=True).click()
    dialog.get_by_label('Name', exact=False).fill('Unfinished')
    page.go_back()
    expect(page).to_have_url(args.base + '/services')
    page.locator('.page-nav a[href="/environments"]').click()
    page.get_by_role('button', name='Create', exact=True).click()
    expect(dialog.get_by_label('Name', exact=False)).to_have_value('')
    dialog.get_by_role('button', name='Cancel', exact=True).click()
    page.locator('.page-nav a[href="/services"]').click()
    expect(page).to_have_url(args.base + '/services')
    assert not errors, errors
    context.close()
    browser.close()
    print('画面から環境を作成する。設定を反映し、失敗時は入力を保って再試行する。日本語・英語で表示し、環境を閉じる。')
