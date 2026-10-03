import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect
from ui_flows import allow_foundation, plain, virtual_authenticator, make_key, unlock, injected

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots')
args = parser.parse_args()
# Passkeys need a hostname.
args.base = args.base.replace('127.0.0.1', 'localhost')
shots = Path(args.screenshots) if args.screenshots else None
if shots:
    shots.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    virtual_authenticator(context, page)
    email = 'workspace-state@example.test'
    page.goto(args.base + '/secrets', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    fragment = urlencode({'email': email, 'token': base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()})
    page.goto(args.base + '/signin/confirm?return_to=%2Fsecrets#' + fragment, wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(args.base + '/secrets')
    page.wait_for_load_state('networkidle')
    allow_foundation(context.request, args.base)
    # Values are edited with the owner's key, from a passkey.
    make_key(page, args.base)

    def keep(kind, name, value='fixture-only'):
        result = context.request.put(args.base + '/v1/resources?' + urlencode({'kind': kind, 'name': name}),
                                     data=plain(value) if kind == 'secret' else value, headers={'Origin': args.base, 'content-type': 'application/json' if kind == 'secret' else 'text/plain'})
        assert result.ok, result.text()
        return result.json()['resource']

    def go(label):
        page.locator('.page-nav').get_by_role('link', name=label, exact=True).click()
        expect(page.get_by_role('heading', name=label, exact=True)).to_be_visible()

    def release(routes, pattern='**/v1/principals/me'):
        assert routes, '通信を待機する'
        for route in routes:
            route.continue_()
        page.unroute(pattern)
        page.wait_for_load_state('networkidle')

    keep('secret', 'name-draft')
    value_resource = keep('secret', 'value-draft')
    for name in ['root.txt', 'reports/one.txt', 'reports/sub/two.txt', '資料 #?/three.txt']:
        keep('object', name)
    unlock(page, args.base)

    # 名前と値を別々に編集中、フォーカスを外しても取得結果から入力を保護する。
    go('サービス')
    page.wait_for_load_state('networkidle')
    pending = []
    page.route('**/v1/principals/me', lambda route: pending.append(route))
    go('シークレット')
    name_row = page.get_by_role('article', name='name-draft', exact=True)
    name_row.get_by_role('button', name='名前を編集', exact=True).click()
    name_form = name_row.get_by_role('form', name='名前の変更')
    name_form.get_by_role('textbox', name='名前', exact=True).fill('saved-name')
    value_row = page.get_by_role('article', name='value-draft', exact=True)
    value_row.get_by_role('button', name='値を差し替える', exact=True).click()
    value_form = value_row.get_by_role('form', name='値の差し替え')
    value_form.get_by_role('textbox', name='値', exact=True).fill('unsaved-value')
    page.get_by_role('heading', name='シークレット', exact=True).click()
    keep('secret', 'arrived-while-editing')
    release(pending)
    expect(name_form.get_by_role('textbox', name='名前', exact=True)).to_have_value('saved-name')
    expect(value_form.get_by_role('textbox', name='値', exact=True)).to_have_value('unsaved-value')

    # 保存失敗後も再編集でき、別の編集を保存しても残りの下書きを維持する。
    page.route('**/v1/resources/*', lambda route: route.fulfill(status=503, json={'error': {'message': '保存を再試行してください。'}}) if route.request.method == 'PATCH' else route.continue_())
    name_form.get_by_role('button', name='保存', exact=True).click()
    expect(name_form.get_by_role('alert')).to_have_text('保存を再試行してください。')
    expect(name_form.get_by_role('textbox', name='名前', exact=True)).to_have_value('saved-name')
    page.unroute('**/v1/resources/*')
    name_form.get_by_role('button', name='保存', exact=True).click()
    expect(page.get_by_role('heading', name='saved-name', exact=True)).to_be_visible()
    expect(value_form.get_by_role('textbox', name='値', exact=True)).to_have_value('unsaved-value')
    keep('secret', 'arrived-after-refresh')
    value_form.get_by_role('button', name='キャンセル', exact=True).click()
    expect(page.get_by_role('heading', name='arrived-after-refresh', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='arrived-while-editing', exact=True)).to_be_visible()
    expect(value_row.get_by_role('button', name='値を差し替える', exact=True)).to_be_focused()
    print('フォーカス移動・保存失敗・他の編集の保存後も下書きを保ち、全編集終了後に最新情報を取得する。')

    # 値の読み込み中に背景更新が終わっても、そのまま編集して保存する。
    go('サービス')
    page.wait_for_load_state('networkidle')
    pending, content = [], []
    page.route('**/v1/principals/me', lambda route: pending.append(route))
    content_pattern = '**/v1/resources/' + value_resource['id'] + '/content'
    page.route(content_pattern, lambda route: content.append(route))
    go('シークレット')
    value_row.get_by_role('button', name='値を差し替える', exact=True).click()
    value_row.get_by_role('button', name='今の値を読み込む', exact=True).click()
    keep('secret', 'arrived-during-value-load')
    # Two reads wait: the revision the editor replaces, and the value asked for.
    for _ in range(100):
        if len(content) >= 2:
            break
        page.wait_for_timeout(100)
    release(pending)
    release(content, content_pattern)
    value_form.get_by_role('textbox', name='値', exact=True).fill('saved-value')
    page.get_by_role('heading', name='シークレット', exact=True).click()
    value_form.get_by_role('button', name='保存', exact=True).click()
    expect(page.get_by_role('heading', name='arrived-during-value-load', exact=True)).to_be_visible()
    expect(value_row.get_by_role('button', name='値を差し替える', exact=True)).to_be_focused()
    saved = injected(context.request, args.base, 'value-draft')
    assert saved.text() == 'saved-value'
    print('値の取得中から保存まで編集を継続する。')

    # JavaScriptの開始前から、サインイン済みの各画面はメニューのボタン・見出し・読み込み状態を表示する。
    reading = browser.new_context(locale='ja-JP', storage_state=context.storage_state(), java_script_enabled=False,
                                  viewport={'width': 390, 'height': 844})
    initial = reading.new_page()
    for path, title in [('/', 'Foundation'), ('/secrets', 'シークレット'), ('/objects?prefix=reports%2F', 'オブジェクト')]:
        initial.goto(args.base + path, wait_until='networkidle')
        expect(initial.get_by_role('heading', name=title, exact=True)).to_be_visible()
        expect(initial.get_by_role('button', name='メニュー', exact=True)).to_be_visible()
        expect(initial.get_by_role('status', name='読み込み中')).to_be_visible()
    if shots:
        initial.screenshot(path=str(shots / 'initial-mobile.png'), full_page=True)
    reading.close()
    print('サインイン済みの初回HTMLから画面の枠を表示する。')

    # 通信失敗と未認証を区別し、同じ場所で再試行する。
    page.route('**/v1/principals/me', lambda route: route.fulfill(status=503, json={'error': {'message': '一時的に取得できません。'}}))
    page.reload(wait_until='networkidle')
    expect(page.get_by_role('heading', name='シークレット', exact=True)).to_be_visible()
    expect(page.get_by_role('alert')).to_have_text('一時的に取得できません。')
    expect(page.get_by_role('button', name='再読み込み', exact=True)).to_be_enabled()
    if shots:
        page.screenshot(path=str(shots / 'communication-error.png'), full_page=True)
    page.unroute('**/v1/principals/me')
    page.get_by_role('button', name='再読み込み', exact=True).click()
    expect(page.get_by_role('heading', name='saved-name', exact=True)).to_be_visible()
    # 読み込み直した画面では、鍵を開き直してから値を差し替えるする。
    unlock(page, args.base)

    # キャッシュ済みの画面と編集中の値は、背景通信の失敗時にも操作を続けられる。
    go('サービス')
    page.wait_for_load_state('networkidle')
    pending = []
    page.route('**/v1/principals/me', lambda route: pending.append(route))
    go('シークレット')
    value_row.get_by_role('button', name='値を差し替える', exact=True).click()
    value_form.get_by_role('textbox', name='値', exact=True).fill('retained-after-error')
    for route in pending:
        route.fulfill(status=503, json={'error': {'message': '通信を再試行してください。'}})
    page.unroute('**/v1/principals/me')
    expect(page.locator('.page-error').get_by_role('alert')).to_have_text('通信を再試行してください。')
    expect(value_form.get_by_role('textbox', name='値', exact=True)).to_have_value('retained-after-error')
    page.get_by_role('button', name='再読み込み', exact=True).click()
    expect(value_form.get_by_role('textbox', name='値', exact=True)).to_have_value('retained-after-error')
    value_form.get_by_role('button', name='キャンセル', exact=True).click()
    page.wait_for_load_state('networkidle')
    print('通信失敗をその場で再試行し、取得済みデータと未保存入力を維持する。')

    go('オブジェクト')
    page.wait_for_load_state('networkidle')
    # キーボードで選択を続け、選択件数を反映する。
    box = page.get_by_role('checkbox', name='root.txt を選ぶ', exact=True)
    box.focus()
    page.keyboard.press('Space')
    expect(box).to_be_checked()
    expect(box).to_be_focused()
    expect(page.get_by_role('button', name='削除（1）', exact=True)).to_be_enabled()
    all_boxes = page.get_by_role('checkbox', name='この画面のものをすべて選ぶ', exact=True)
    assert all_boxes.evaluate('el => el.indeterminate')
    all_boxes.focus()
    page.keyboard.press('Space')
    expect(all_boxes).to_be_focused()
    expect(page.get_by_role('button', name='削除（4）', exact=True)).to_be_enabled()
    page.get_by_role('searchbox', name='絞り込む', exact=True).fill('root')
    expect(page.get_by_role('searchbox', name='絞り込む', exact=True)).to_be_focused()
    page.get_by_role('searchbox', name='絞り込む', exact=True).fill('')
    print('選択と絞り込みでフォーカスを維持する。')

    # 一覧の更新を待っている間に選んだ行も、通信完了後に選択とフォーカスを保つ。
    go('サービス')
    page.wait_for_load_state('networkidle')
    pending = []
    page.route('**/v1/principals/me/usage', lambda route: pending.append(route))
    go('オブジェクト')
    box.focus()
    page.keyboard.press('Space')
    keep('object', 'arrived-during-selection.txt')
    release(pending, '**/v1/principals/me/usage')
    expect(box).to_be_checked()
    expect(box).to_be_focused()
    expect(page.get_by_role('button', name='削除（1）', exact=True)).to_be_enabled()

    # オブジェクトの通信失敗時にも取得済みの一覧を利用し、再試行で追加分を取得する。
    go('サービス')
    page.wait_for_load_state('networkidle')
    page.route('**/v1/principals/me/usage', lambda route: route.fulfill(status=503, json={'error': {'message': '一時的に取得できません。'}}))
    go('オブジェクト')
    expect(page.locator('.page-error').get_by_role('alert')).to_have_text('一時的に取得できません。')
    expect(page.get_by_role('link', name='root.txt', exact=True)).to_be_visible()
    page.unroute('**/v1/principals/me/usage')
    page.get_by_role('button', name='再読み込み', exact=True).click()
    expect(page.get_by_role('link', name='arrived-during-selection.txt', exact=True)).to_be_visible()
    page.wait_for_load_state('networkidle')
    print('一覧の背景更新でも選択とフォーカスを保ち、通信失敗時は取得済みデータを表示する。')

    # フォルダ位置をURLで共有し、直接表示・再読込・戻る・進む・新しいタブで復元する。
    reports = args.base + '/objects?' + urlencode({'prefix': 'reports/'})
    page.get_by_role('link', name='reports', exact=True).click()
    expect(page).to_have_url(reports)
    expect(page.get_by_role('link', name='one.txt', exact=True)).to_be_visible()
    page.get_by_role('link', name='sub', exact=True).click()
    expect(page).to_have_url(args.base + '/objects?' + urlencode({'prefix': 'reports/sub/'}))
    page.reload(wait_until='networkidle')
    expect(page.get_by_role('link', name='two.txt', exact=True)).to_be_visible()
    page.go_back()
    expect(page).to_have_url(reports)
    expect(page.get_by_role('link', name='one.txt', exact=True)).to_be_visible()
    page.go_forward()
    expect(page.get_by_role('link', name='two.txt', exact=True)).to_be_visible()
    page.get_by_role('navigation', name='パス', exact=True).get_by_role('link', name='すべて', exact=True).click()
    with context.expect_page() as opened:
        page.get_by_role('link', name='資料 #?', exact=True).click(modifiers=['Control'])
    tab = opened.value
    tab.wait_for_load_state('networkidle')
    expect(tab).to_have_url(args.base + '/objects?' + urlencode({'prefix': '資料 #?/'}))
    expect(tab.get_by_role('link', name='three.txt', exact=True)).to_be_visible()
    tab.close()
    page.get_by_role('link', name='reports', exact=True).click()
    page.wait_for_load_state('networkidle')
    print('フォルダを通常のURLとリンクで扱う。')

    # 追加ボタンをキーボードで操作し、今のフォルダにファイルを保存する。
    button = page.get_by_role('button', name='追加', exact=True)
    button.focus()
    with page.expect_file_chooser() as selected:
        page.keyboard.press('Enter')
    selected.value.set_files({'name': 'keyboard.txt', 'mimeType': 'text/plain', 'buffer': b'keyboard-fixture'})
    expect(page.get_by_role('link', name='keyboard.txt', exact=True)).to_be_visible()
    found = context.request.get(args.base + '/v1/resources?' + urlencode({'kind': 'object', 'name': 'reports/keyboard.txt'}))
    assert found.ok
    for choice in ['キャンセル', '置き換える']:
        with page.expect_file_chooser() as selected:
            button.click()
        selected.value.set_files({'name': 'keyboard.txt', 'mimeType': 'text/plain', 'buffer': b'replacement-fixture'})
        page.get_by_role('dialog').get_by_role('button', name=choice, exact=True).click()
        expect(button).to_be_enabled()
    resource = found.json()['resource']
    expect(page.get_by_role('link', name='keyboard.txt', exact=True)).to_be_visible()
    assert context.request.get(args.base + '/v1/resources/' + resource['id'] + '/content').body() == b'replacement-fixture'
    print('キーボードからファイルを追加し、置き換えの取り消しと再試行を行う。')

    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), '画面幅に収める'
        print(f'表示文言 ({width}px): ' + page.get_by_role('main').inner_text().replace('\n', ' / '))
        if shots:
            page.screenshot(path=str(shots / f'objects-{width}.png'), full_page=True)
    context.clear_cookies()
    page.reload(wait_until='networkidle')
    expect(page.get_by_role('heading', name='サインイン', exact=True)).to_be_visible()
    expect(page.get_by_label('メールアドレス', exact=True)).to_be_enabled()
    # フォルダを開く途中にサインインしても、同じ場所へ戻る。
    signin_email = 'folder-return@example.test'
    page.get_by_label('メールアドレス', exact=True).fill(signin_email)
    with page.expect_request(lambda request: request.method == 'POST' and request.url.endswith('/v1/session')) as sent:
        page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    assert sent.value.post_data_json['return_to'] == '/objects?prefix=reports%2F'
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    fragment = urlencode({'email': signin_email, 'token': base64.urlsafe_b64encode(hashlib.sha256(signin_email.encode()).digest()).rstrip(b'=').decode()})
    page.goto(args.base + '/signin/confirm?' + urlencode({'return_to': '/objects?prefix=reports%2F'}) + '#' + fragment, wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    expect(page).to_have_url(reports)
    expect(page.get_by_role('navigation', name='パス', exact=True).get_by_text('reports', exact=True)).to_be_visible()

    # サインインの設定取得に失敗した場合も、再試行してフォームへ進む。
    context.clear_cookies()
    page.route('**/v1/session', lambda route: route.fulfill(status=503, json={'error': {'message': '接続できませんでした。'}}))
    page.reload(wait_until='networkidle')
    expect(page.get_by_role('alert')).to_have_text('接続できませんでした。')
    page.unroute('**/v1/session')
    page.get_by_role('button', name='再読み込み', exact=True).click()
    expect(page.get_by_label('メールアドレス', exact=True)).to_be_enabled()
    assert not errors, errors
    context.close()
    browser.close()
