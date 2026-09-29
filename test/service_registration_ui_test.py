import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots')
args = parser.parse_args()
shots = Path(args.screenshots) if args.screenshots else None
if shots:
    shots.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/services', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    fragment = urlencode({'email': 'owner@example.test', 'token_hash': hashlib.sha256(b'owner@example.test').hexdigest()})
    page.goto(args.base + '/login/confirm?return_to=%2Fservices#' + fragment, wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    page.wait_for_url(args.base + '/services')
    page.wait_for_load_state('networkidle')
    dialog = page.get_by_role('dialog')

    def api(path, method='GET', data=None, raw=None):
        headers = {'Origin': args.base}
        if raw is not None:
            headers['content-type'] = 'text/plain'
        response = context.request.fetch(args.base + path, method=method, data=raw if raw is not None else data, headers=headers)
        assert response.ok, response.text()
        return response.text() if raw is not None else response.json()

    def overview():
        return api('/v1/overview')

    def service(name):
        return next(item for item in overview()['services'] if item['name'] == name)

    def keep(name, value):
        query = urlencode({'kind': 'credential', 'name': name})
        response = context.request.put(args.base + '/v1/resources?' + query, data=value,
                                       headers={'Origin': args.base, 'content-type': 'text/plain'})
        assert response.ok, response.text()
        return response.json()['resource']

    def adopt(entry):
        page.goto(args.base + '/secrets', wait_until='networkidle')
        page.get_by_role('article', name=entry['name'], exact=True).get_by_role('button', name='サービスのトークンにする', exact=True).click()

    def review(label):
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), label
        text = page.locator('body').inner_text()
        for phrase in ['fixture-private-', '実装', '設計意図', 'auth_schemes']:
            assert phrase not in text, (label, phrase)
        small = page.evaluate("""() => [...document.querySelectorAll('label, button, input, p, h3')]
          .filter(el => el.checkVisibility() && parseFloat(getComputedStyle(el).fontSize) < 14)
          .map(el => el.textContent)""")
        assert not small, small
        if shots:
            page.screenshot(path=str(shots / (label + '.png')), full_page=True)

    # 名前だけで登録し、再読込後も未接続のサービスとして表示する。
    page.get_by_role('button', name='サービスを追加', exact=True).click()
    dialog.get_by_label('サービスを探す', exact=True).fill('社内ツール')
    dialog.get_by_role('button', name='一覧にないサービスを追加', exact=True).click()
    expect(dialog.get_by_label('サービス名', exact=True)).to_have_value('社内ツール')
    review('name-only')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    row = page.get_by_role('article', name='社内ツール', exact=True)
    expect(row.get_by_text('未接続', exact=True)).to_be_visible()
    page.reload(wait_until='networkidle')
    expect(row.get_by_text('未接続', exact=True)).to_be_visible()
    registered = service('社内ツール')
    assert registered['definition']['auth_schemes'] == {}
    row.get_by_role('button', name='接続を追加', exact=True).click()
    dialog.get_by_role('button', name='トークンを入力する').click()
    dialog.get_by_label('トークン', exact=True).fill('fixture-private-cancelled')
    page.keyboard.press('Escape')
    expect(dialog).not_to_be_visible()
    assert service('社内ツール')['definition']['auth_schemes'] == {}
    print('名前だけの登録を保持し、接続を途中で取り消すと未設定のままにする。')

    # 後からトークンを預ける。通信失敗後も入力を保ち、再試行して利用する。
    row.get_by_role('button', name='接続を追加', exact=True).click()
    dialog.get_by_role('button', name='トークンを入力する').click()
    dialog.get_by_label('トークン', exact=True).fill('fixture-private-manual')
    expect(dialog.get_by_text('接続先での有効性の確認は行いません。', exact=True)).to_be_visible()
    page.route('**/v1/credentials', lambda route: route.fulfill(status=503, json={'error': {'message': '再試行してください。'}}))
    dialog.get_by_role('button', name='預ける', exact=True).click()
    expect(dialog.get_by_role('alert')).to_have_text('再試行してください。')
    expect(dialog.get_by_label('トークン', exact=True)).to_have_value('fixture-private-manual')
    page.unroute('**/v1/credentials')
    dialog.get_by_role('button', name='預ける', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_text('トークン・未検証', exact=True)).to_be_visible()
    connected = next(item for item in overview()['credentials'] if item.get('service', {}).get('id') == registered['id'])
    assert api('/v1/injections', 'POST', {'names': [{'name': connected['id']}]})['injection']['environment'] == {'API_TOKEN': 'fixture-private-manual'}
    print('未検証であることを示し、通信失敗後に入力を保ってトークンを登録・利用する。')

    # シークレットの移行からサービスを登録し、キャンセル後も元の値を保つ。
    kept = keep('任意の名前/a', 'fixture-private-adopt')
    adopt(kept)
    search = dialog.get_by_label('サービスを探す', exact=True)
    search.fill('自作アプリ')
    expect(dialog.get_by_text('見つかりません。', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='一覧にないサービスを追加', exact=True).click()
    expect(dialog.get_by_label('サービス名', exact=True)).to_have_value('自作アプリ')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog.get_by_role('heading', name='自作アプリのトークンにする', exact=True)).to_be_visible()
    expect(dialog.get_by_text('任意の名前/a', exact=True)).to_be_visible()
    page.keyboard.press('Escape')
    expect(dialog).not_to_be_visible()
    assert service('自作アプリ')['definition']['auth_schemes'] == {}
    original = context.request.get(args.base + '/v1/resources/' + kept['id'] + '/content')
    assert original.text() == 'fixture-private-adopt'

    # 同名の新規登録は既存の接続設定を上書きせず、その場で再入力を受け付ける。
    adopt(kept)
    dialog.get_by_label('サービスを探す', exact=True).fill('社内ツール')
    dialog.get_by_role('button', name='一覧にないサービスを追加', exact=True).click()
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog.get_by_role('alert')).to_have_text('同じ名前のサービスがあります。一覧から選んでください。')
    expect(dialog.get_by_label('サービス名', exact=True)).to_have_value('社内ツール')
    assert service('社内ツール')['definition']['auth_schemes']['token']['injection'] == {'API_TOKEN': '{token}'}
    dialog.get_by_label('サービス名', exact=True).fill('追加のアプリ')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog.get_by_role('heading', name='追加のアプリのトークンにする', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='移す', exact=True).click()
    expect(dialog).not_to_be_visible()
    adopted = next(item for item in overview()['credentials'] if item['id'] == kept['id'])
    assert adopted['name'] == kept['name']
    assert adopted['service']['id'] == service('追加のアプリ')['id']
    assert api('/v1/injections', 'POST', {'names': [{'name': kept['id']}]})['injection']['environment'] == {'API_TOKEN': 'fixture-private-adopt'}
    print('移行中の新規登録・キャンセル・名前の競合に対応し、元のID・名前・値で移行する。')

    # 検索して既存の未接続サービスを選び、キーボードで移行を確定する。
    second = keep('別のシークレット', 'fixture-private-second')
    adopt(second)
    dialog.get_by_label('サービスを探す', exact=True).fill('自作')
    choice = dialog.get_by_role('button', name='自作アプリ', exact=True)
    expect(choice).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 900})
        review('search-' + str(width))
    choice.focus()
    page.keyboard.press('Enter')
    review('adopt-mobile')
    dialog.get_by_role('button', name='移す', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert next(item for item in overview()['credentials'] if item['id'] == second['id'])['service']['id'] == service('自作アプリ')['id']
    print('PCとスマートフォンでサービスを検索し、キーボードでも選択・移行する。')

    # OAuthだけのサービスも検索し、トークン方式を追加して元のOAuth設定を保つ。
    oauth = {'authorize': 'https://service.example/authorize', 'token': 'https://service.example/token',
             'scopes': {'base': []}, 'injection': {'OAUTH_ACCESS_TOKEN': '{access_token}'}}
    named = api('/v1/resources?kind=service&name=OAuth-only', 'PUT',
                {'version': 1, 'name': 'OAuth-only', 'auth_schemes': {'oauth': oauth}})['resource']
    third = keep('oauth-service-token', 'fixture-private-third')
    adopt(third)
    dialog.get_by_label('サービスを探す', exact=True).fill('oauth-only')
    dialog.get_by_role('button', name='OAuth-only', exact=True).click()
    dialog.get_by_role('button', name='移す', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert service('OAuth-only')['definition']['auth_schemes']['oauth'] == oauth
    assert service('OAuth-only')['definition']['auth_schemes']['token']['injection'] == {'API_TOKEN': '{token}'}

    # 複数の入力を持つトークン方式では、保存済みの値に追加情報だけを添える。
    fields = {'fields': [{'name': 'token', 'label': 'トークン', 'secret': True},
                         {'name': 'account', 'label': 'アカウントID', 'secret': False}],
              'identity': {'from': 'fields', 'id': 'account'},
              'injection': {'API_TOKEN': '{token}', 'ACCOUNT_ID': '{account}'}}
    api('/v1/resources?kind=service&name=Account-Service', 'PUT',
        {'version': 1, 'name': 'Account-Service', 'auth_schemes': {'token': fields}})
    fourth = keep('account-token', 'fixture-private-fourth')
    adopt(fourth)
    dialog.get_by_label('サービスを探す', exact=True).fill('account-service')
    dialog.get_by_role('button', name='Account-Service', exact=True).click()
    dialog.get_by_label('アカウントID', exact=True).fill('account-1')
    dialog.get_by_role('button', name='移す', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert api('/v1/injections', 'POST', {'names': [{'name': fourth['id']}]})['injection']['environment'] == {
        'API_TOKEN': 'fixture-private-fourth', 'ACCOUNT_ID': 'account-1'}
    print('OAuth設定を保持してトークン方式を加え、追加のアカウントIDが必要なサービスにも移行する。')

    # AIからの依頼でも、未検証であることを伝えてトークンを受け取る。
    actor = api('/v1/principals', 'POST', {'name': 'テストAI', 'actor': True, 'key': True})
    response = context.request.post(args.base + '/v1/requests?as=' + actor['principal']['acts_for'][0],
        data={'kind': 'connect', 'input': {'service': named['id'], 'auth_scheme': 'token'}, 'purpose': '接続を確認します。'},
        headers={'Origin': args.base, 'Authorization': 'Bearer ' + actor['token']})
    assert response.ok, response.text()
    page.goto(args.base + '/requests/' + response.json()['request']['id'], wait_until='networkidle')
    expect(page.get_by_text('接続先での有効性の確認は行いません。', exact=True)).to_be_visible()
    page.get_by_label('トークン', exact=True).fill('fixture-private-request')
    page.get_by_role('button', name='預ける', exact=True).click()
    expect(page.get_by_role('heading', name='接続しました', exact=True)).to_be_visible()
    print('AIからのトークン接続依頼でも検証の有無を示し、預かった結果を返す。')

    # 使っていない登録を明示確認のうえ削除する。
    page.set_viewport_size({'width': 1280, 'height': 900})
    page.goto(args.base + '/services', wait_until='networkidle')
    expect(page.get_by_text(kept['name'], exact=True)).to_be_visible()
    expect(page.get_by_text(second['name'], exact=True)).to_be_visible()
    page.get_by_role('button', name='サービスを追加', exact=True).click()
    dialog.get_by_label('サービスを探す', exact=True).fill('削除用')
    dialog.get_by_role('button', name='一覧にないサービスを追加', exact=True).click()
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    deleting = service('削除用')
    page.get_by_role('article', name='削除用', exact=True).get_by_role('button', name='削除', exact=True).click()
    expect(dialog.get_by_role('heading', name='削除用 を削除しますか？', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert context.request.get(args.base + '/v1/resources/' + deleting['id']).status == 404
    review('services-desktop')
    print('不要になった未接続サービスの登録を削除する。')
    assert not errors, errors
    browser.close()
