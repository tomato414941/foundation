import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from playwright.sync_api import sync_playwright, expect

# A service Foundation does not know, against the fixture server (which answers for service.example): the owner describes
# the service and where it is, adds an OAuth app for it, and connecting goes through that app. The service's consent
# screen is answered here; its token endpoint is the fixture's fake.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots')
args = parser.parse_args()
shots = Path(args.screenshots) if args.screenshots else None
if shots:
    shots.mkdir(parents=True, exist_ok=True)


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    small = page.evaluate("""() => [...document.querySelectorAll('p, label, button, small, dt, dd, input, textarea, summary, h3')]
      .filter(el => el.getBoundingClientRect().width && el.checkVisibility() && parseFloat(getComputedStyle(el).fontSize) < 14)
      .map(el => el.tagName + ': ' + el.textContent.slice(0, 30))""")
    assert not small, small
    text = page.locator('body').inner_text()
    for phrase in ['notes-secret', 'refresh-', 'access-personal', 'client_secret', '実装', '設計意図']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(locale='ja-JP', viewport={'width': 1280, 'height': 1000})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/services', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/signin/confirm?return_to=%2Fservices#token=' + base64.urlsafe_b64encode(hashlib.sha256(b'owner@example.test').digest()).rstrip(b'=').decode() + '&email=owner%40example.test', wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(args.base + '/services')
    page.wait_for_load_state('networkidle')
    dialog = page.get_by_role('dialog')

    # 名前だけで登録したサービスに、後からOAuthの接続先を設定する。
    page.get_by_role('button', name='サービスを追加', exact=True).click()
    dialog.get_by_role('button', name='一覧にないサービスを追加', exact=True).click()
    dialog.get_by_label('サービス名', exact=True).fill('Notes')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    registered = page.get_by_role('article', name='Notes', exact=True)
    expect(registered.get_by_text('未接続', exact=True)).to_be_visible()
    registered.get_by_role('button', name='接続を追加', exact=True).click()
    dialog.get_by_label('認可エンドポイントのURL', exact=True).fill('https://service.example/oauth/authorize')
    dialog.get_by_label('トークンエンドポイントのURL', exact=True).fill('http://service.example/oauth/token')
    dialog.get_by_label('利用者情報のURL（任意）', exact=True).fill('https://service.example/api/me')
    dialog.get_by_label('取り消しのURL（任意）', exact=True).fill('https://service.example/oauth/revoke')
    dialog.get_by_role('button', name='次へ').click()
    expect(dialog.locator('.form-error')).to_contain_text('サービスの定義を確認してください')
    dialog.get_by_label('トークンエンドポイントのURL', exact=True).fill('https://service.example/oauth/token')
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'define-service.png'), full_page=True)
    dialog.get_by_role('button', name='次へ').click()

    # Then its app, whose redirect URL is the same for every service.
    expect(dialog.get_by_role('heading', name='OAuthアプリを追加', exact=True)).to_be_visible()
    expect(dialog.get_by_text(args.base + '/oauth/callback')).to_be_visible()
    dialog.get_by_label('名前', exact=True).fill('Notes')
    dialog.get_by_label('クライアントID', exact=True).fill('notes-client')
    dialog.get_by_label('クライアントシークレット', exact=True).fill('notes-secret')
    dialog.get_by_role('button', name='追加', exact=True).click()

    # Connecting asks for the owner's scopes through that app, and the service says who authorized.
    asked = {}

    def consent(route):
        values = parse_qs(urlparse(route.request.url).query)
        asked.update({key: values[key][0] for key in ['client_id', 'scope', 'code_challenge_method']})
        query = {'state': values['state'][0], 'code': 'personal'}
        route.fulfill(status=302, headers={'location': values['redirect_uri'][0] + '?' + urlencode(query)}, body='')

    page.route('https://service.example/oauth/authorize?*', consent)
    expect(dialog.get_by_role('heading', name='Notesに接続', exact=True)).to_be_visible()
    dialog.get_by_label('許可する権限（1行に1つ）', exact=True).fill('notes.read')
    review(page)
    dialog.get_by_role('button', name='Notesの画面へ', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    assert asked == {'client_id': 'notes-client', 'scope': 'notes.read', 'code_challenge_method': 'S256'}, asked
    page.goto(args.base + '/services', wait_until='networkidle')
    connections = page.locator('[aria-label="サービス"]')
    expect(connections.get_by_role('heading', name='Notes', exact=True)).to_be_visible()
    expect(connections.get_by_text('personal@service.example', exact=True)).to_be_visible()
    expect(connections.get_by_text('OAuthアプリ：Notes', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots and width != 320:
            page.screenshot(path=str(shots / ('generic-desktop.png' if width == 1280 else 'generic-mobile.png')), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Disconnecting can take the grant back, because the service's definition says where.
    connections.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_label('Notes側の許可も取り消す')).to_be_checked()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(registered.get_by_text('未接続', exact=True)).to_be_visible()
    assert not errors, errors
    browser.close()
    print('一覧にないサービス: 定義・アプリの追加・権限を選んだ接続・取り消し付きの解除と、PC・スマートフォンの表示を確認しました。')
