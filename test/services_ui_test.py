import argparse
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from playwright.sync_api import sync_playwright, expect

# The services Foundation knows by name, against the fixture server with FOUNDATION_TEST_SERVICES=1, where Foundation
# has no app for any of them: they wait, searchable, among the other services; choosing one starts with registering
# the owner's own app, asking for what that service needs (kintone: its domain); then it is ready to connect.
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
    for phrase in ['kintone-secret', 'client_secret', '実装', '設計意図']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1280, 'height': 1000})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/connections', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/login/confirm?return_to=%2Fconnections#token_hash=' + hashlib.sha256(b'owner@example.test').hexdigest() + '&email=owner%40example.test', wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    page.wait_for_url(args.base + '/connections')
    page.wait_for_load_state('networkidle')
    dialog = page.get_by_role('dialog')
    connect = page.locator('[aria-labelledby="connect-title"]')

    # The other services, searchable; a search that finds none says what else can be done.
    connect.locator('summary').click()
    search = connect.get_by_label('サービスを探す', exact=True)
    expect(connect.get_by_role('button', name='Microsoft 365', exact=True)).to_be_visible()
    search.fill('zzz')
    expect(connect.get_by_text('見つかりません。OAuth 2.0に対応したサービスなら、OAuthアプリを追加して接続できます。', exact=True)).to_be_visible()
    search.fill('kin')
    expect(connect.get_by_role('button', name='Notion', exact=True)).to_be_hidden()
    for width in [1280, 390]:
        page.set_viewport_size({'width': width, 'height': 1000})
        search.fill('')
        review(page)
        if shots:
            page.screenshot(path=str(shots / f'services-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Choosing kintone starts with its app, which names the owner's kintone domain.
    search.fill('kin')
    connect.get_by_role('button', name='kintone', exact=True).click()
    expect(dialog.get_by_label('接続先', exact=True)).to_have_value('kintone.oauth')
    dialog.get_by_label('名前', exact=True).fill('社内kintone')
    dialog.get_by_label('kintoneのドメイン', exact=True).fill('example')
    dialog.get_by_label('クライアントID', exact=True).fill('kintone-client')
    dialog.get_by_label('クライアントシークレット', exact=True).fill('kintone-secret')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog.get_by_text('kintoneのドメインを確認してください。', exact=True)).to_be_visible()
    dialog.get_by_label('kintoneのドメイン', exact=True).fill('example.cybozu.com')
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'kintone-app.png'), full_page=True)
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()

    # Now kintone is ready, and connecting goes to that domain's consent screen.
    asked = {}

    def consent(route):
        url = urlparse(route.request.url)
        asked.update({'host': url.hostname, 'client_id': parse_qs(url.query)['client_id'][0]})
        route.fulfill(status=200, body='consent')

    page.route('https://example.cybozu.com/oauth2/authorization?*', consent)
    expect(connect.get_by_role('heading', name='kintone', exact=True)).to_be_visible()
    connect.get_by_role('button', name='kintoneで接続', exact=True).click()
    dialog.get_by_label('許可する権限（1行に1つ）', exact=True).fill('k:app_record:read')
    dialog.get_by_role('button', name='kintoneで接続', exact=True).click()
    page.wait_for_url('https://example.cybozu.com/**')
    assert asked == {'host': 'example.cybozu.com', 'client_id': 'kintone-client'}, asked
    assert not errors, errors
    browser.close()
    print('サービス一覧: ほかのサービスの検索・該当なしの案内・ドメインが要るアプリの登録・登録後の接続開始と、PC・スマートフォンの表示を確認しました。')
