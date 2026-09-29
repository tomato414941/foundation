import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
parser.add_argument('--engine', choices=['chromium', 'webkit'], default='chromium')
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = getattr(p, args.engine).launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 900}, reduced_motion='reduce')
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    email = 'navigation@example.test'
    page.goto(args.base + '/secrets', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    fragment = urlencode({'email': email, 'token_hash': hashlib.sha256(email.encode()).hexdigest()})
    page.goto(args.base + '/login/confirm?return_to=%2Fsecrets#' + fragment, wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    page.wait_for_url(args.base + '/secrets')
    page.wait_for_load_state('networkidle')
    created = context.request.put(args.base + '/v1/resources?kind=object&name=navigation.txt',
                                  data='fixture-only', headers={'Origin': args.base, 'content-type': 'text/plain'})
    assert created.ok, created.status

    def go(label):
        page.get_by_role('navigation').get_by_role('link', name=label, exact=True).click()
        expect(page.get_by_role('heading', name=label, exact=True)).to_be_visible()

    def current(label):
        expect(page.get_by_role('heading', name=label, exact=True)).to_be_visible()
        expect(page.get_by_role('navigation').get_by_role('link', name=label, exact=True)).to_have_attribute('aria-current', 'page')
        expect(page).to_have_title(label + ' · Foundation')

    # 通信の完了を待っている間も、移動先とメニューを表示して操作を受け付ける。
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 900})
        go('シークレット')
        page.wait_for_load_state('networkidle')
        before = page.get_by_role('navigation').bounding_box()
        pending = []
        page.route('**/v1/overview', lambda route: pending.append(route))
        go('サービス')
        current('サービス')
        expect(page.get_by_role('main')).to_be_focused()
        assert page.get_by_role('navigation').bounding_box() == before, 'メニューの位置と大きさを保って切り替える'
        page.get_by_role('button', name='サービスを追加', exact=True).click()
        field = page.get_by_label('サービスを探す', exact=True)
        field.fill('Slack')
        if width == 1280:
            created = context.request.put(args.base + '/v1/resources?kind=secret&name=background-example',
                                          data='fixture-only', headers={'Origin': args.base, 'content-type': 'text/plain'})
            assert created.ok, created.status
        assert pending, '最新情報の確認を進める'
        for route in pending:
            route.continue_()
        page.unroute('**/v1/overview')
        page.wait_for_load_state('networkidle')
        expect(field).to_have_value('Slack')
        expect(field).to_be_focused()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), '画面幅に収める'
        if width != 320:
            page.screenshot(path=str(shots / f'navigation-{args.engine}-{width}.png'), full_page=True)
        field.fill('')
        page.get_by_role('dialog').get_by_role('button', name='閉じる', exact=True).click()
    print('通信待ちでも移動先を表示し、メニューの位置と入力中の内容を保つ。')

    page.set_viewport_size({'width': 1280, 'height': 900})
    # 必要な部分を読み込み表示にし、取得後に一覧へ切り替える。
    pending = []
    page.route('**/v1/usage', lambda route: pending.append(route))
    go('オブジェクト')
    expect(page.get_by_role('status', name='読み込み中')).to_be_visible()
    expect(page.get_by_role('navigation')).to_be_visible()
    page.screenshot(path=str(shots / f'loading-{args.engine}.png'), full_page=True)
    assert pending
    for route in pending:
        route.continue_()
    page.unroute('**/v1/usage')
    expect(page.get_by_role('table')).to_be_visible()
    page.wait_for_load_state('networkidle')
    print('オブジェクトの取得中も見出しとメニューを表示し、取得後に一覧を表示する。')

    # 移動が重なったときは、最後に選んだ画面を表示する。
    pending = []
    page.route('**/v1/overview', lambda route: pending.append(route))
    for label in ['サービス', 'アクセス管理', 'ファンクション']:
        go(label)
        current(label)
    for route in reversed(pending):
        route.continue_()
    page.unroute('**/v1/overview')
    page.wait_for_load_state('networkidle')
    current('ファンクション')
    print('連続して移動しても、最後に選んだ画面を表示する。')

    # 戻る・進む、キーボード操作、ページ内の行き先を扱う。
    page.go_back()
    current('アクセス管理')
    page.go_forward()
    current('ファンクション')
    page.get_by_role('link', name='アカウント', exact=True).click()
    expect(page.get_by_role('heading', name='アカウント', exact=True)).to_be_visible()
    page.get_by_role('link', name='アプリの登録', exact=True).click()
    expect(page).to_have_url(args.base + '/principals#apps')
    expect(page.locator('#apps')).to_be_in_viewport()
    page.go_back()
    expect(page.get_by_role('heading', name='アカウント', exact=True)).to_be_visible()
    page.go_forward()
    expect(page.locator('#apps')).to_be_in_viewport()
    page.reload(wait_until='networkidle')
    expect(page).to_have_url(args.base + '/principals#apps')
    expect(page.locator('#apps')).to_be_in_viewport()
    link = page.get_by_role('navigation').get_by_role('link', name='シークレット', exact=True)
    link.focus()
    page.keyboard.press('Enter')
    current('シークレット')
    print('戻る・進むとキーボード操作を扱い、直接開いたページ内の行き先も表示する。')

    # 別のタブからも、URLに対応する画面を利用する。
    with context.expect_page() as opened:
        page.get_by_role('navigation').get_by_role('link', name='サービス', exact=True).click(modifiers=['Control'])
    tab = opened.value
    tab.wait_for_load_state('networkidle')
    expect(tab).to_have_url(args.base + '/services')
    expect(tab.get_by_role('button', name='サービスを追加', exact=True)).to_be_enabled()
    tab.close()
    page.bring_to_front()
    print('新しいタブでも通常のリンクとして接続画面を開く。')

    # ほかのクライアントで追加された情報を、移動時に取り込む。
    created = context.request.put(args.base + '/v1/resources?kind=secret&name=navigation-example',
                                  data='fixture-only', headers={'Origin': args.base, 'content-type': 'text/plain'})
    assert created.ok, created.status
    go('サービス')
    go('シークレット')
    expect(page.get_by_role('heading', name='navigation-example', exact=True)).to_be_visible()
    page.get_by_role('article', name='navigation-example', exact=True).get_by_role('button', name='名前を編集', exact=True).click()
    editor = page.get_by_role('form', name='名前の変更')
    editor.get_by_role('textbox', name='名前', exact=True).fill('renamed-example')
    editor.get_by_role('button', name='保存', exact=True).click()
    expect(page.get_by_role('heading', name='renamed-example', exact=True)).to_be_visible()
    go('サービス')
    go('シークレット')
    expect(page.get_by_role('heading', name='renamed-example', exact=True)).to_be_visible()
    print('最新の情報を取り込み、移動後も認証情報を編集する。')

    # 取得に失敗した場合は、その場所からやり直す。
    page.goto(args.base + '/secrets', wait_until='networkidle')
    page.route('**/v1/usage', lambda route: route.fulfill(status=503, json={'error': {'message': '一時的に取得できません。'}}))
    go('オブジェクト')
    retry = page.get_by_role('button', name='再読み込み', exact=True)
    expect(retry).to_be_enabled()
    page.unroute('**/v1/usage')
    retry.click()
    expect(page.get_by_role('table')).to_be_visible()
    print('取得の失敗を表示し、再読み込みで一覧を表示する。')

    # ガイドなどの通常のページへ移動し、戻って引き続き利用する。
    page.get_by_role('link', name='Foundation ホーム', exact=True).click()
    expect(page.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()
    page.wait_for_load_state('networkidle')
    page.goto(args.base + '/start', wait_until='networkidle')
    expect(page.locator('body')).to_contain_text('foundation connect')
    page.go_back(wait_until='networkidle')
    expect(page.get_by_role('main').get_by_role('link', name='シークレット', exact=False)).to_be_visible()

    # セッションが切れていたらログインへ案内する。
    context.clear_cookies()
    go('サービス')
    expect(page.get_by_role('heading', name='ログイン', exact=True)).to_be_visible()
    expect(page.get_by_label('メールアドレス', exact=True)).to_be_enabled()
    page.go_back(wait_until='networkidle')
    expect(page.get_by_role('heading', name='ログイン', exact=True)).to_be_visible()
    print('セッションの終了を確認してログインへ案内する。')
    assert not errors, errors
    context.close()
    browser.close()
