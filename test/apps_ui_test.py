import argparse
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from ui_flows import start_connect
from playwright.sync_api import sync_playwright, expect

# OAuth apps on the connections page, against the fixture server with FOUNDATION_TEST_CLOUDFLARE=1: adding one,
# connecting through it, changing its secret, removing it (which stops its connection), and registering one from an
# AI's request. No real service is reached: the consent screen is answered here.
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
    for phrase in ['work-app-secret', 'rotated-secret', 'mail-app-secret', 'client_secret', '実装', '設計意図']:
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
    apps = page.locator('#oauth-apps')
    # OAuth apps are folded away until they are needed.
    apps.locator('summary').click()
    expect(apps.get_by_text('Foundationのアプリ', exact=True).first).to_be_visible()

    # Adding an app: the service, a name, its client ID and secret, and the redirect URL to register there.
    apps.get_by_role('button', name='OAuthアプリを追加', exact=True).click()
    dialog.get_by_label('サービス', exact=True).select_option('cloudflare')
    dialog.get_by_label('名前', exact=True).fill('仕事用')
    dialog.get_by_label('クライアントID', exact=True).fill('work-app-id')
    dialog.get_by_label('クライアントシークレット', exact=True).fill('work-app-secret')
    expect(dialog.get_by_text(args.base + '/oauth/callback', exact=True)).to_be_visible()
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'add-app.png'), full_page=True)
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    # Each app is listed under its service, by the name its owner gave it.
    expect(apps.locator('.agent-row').filter(has=page.get_by_text('仕事用', exact=True)).get_by_role('heading', name='Cloudflare', exact=True)).to_be_visible()

    # Connecting through it: the app is chosen in the dialog, and the consent screen is asked by that app.
    asked = {}

    def consent(route):
        values = parse_qs(urlparse(route.request.url).query)
        asked['client_id'] = values['client_id'][0]
        query = {'state': values['state'][0], 'code': 'personal'}
        route.fulfill(status=302, headers={'location': values['redirect_uri'][0] + '?' + urlencode(query)}, body='')

    page.route('https://dash.cloudflare.com/oauth2/auth?*', consent)
    start_connect(page, 'Cloudflare')
    dialog.get_by_label('OAuthアプリ', exact=True).select_option(label='仕事用')
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'connect-through-app.png'), full_page=True)
    dialog.get_by_role('button', name='Cloudflareの画面へ', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    assert asked['client_id'] == 'work-app-id', asked
    page.goto(args.base + '/services', wait_until='networkidle')
    connections = page.locator('[aria-label="サービス"]')
    expect(connections.get_by_text('OAuthアプリ：仕事用', exact=True)).to_be_visible()
    apps.locator('summary').click()
    expect(apps.get_by_text('クライアントID work-app-id・接続 1件', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots and width != 320:
            page.screenshot(path=str(shots / ('apps-desktop.png' if width == 1280 else 'apps-mobile.png')), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # A new secret keeps the connection going.
    row = apps.locator('.agent-row').filter(has=page.get_by_text('仕事用', exact=True))
    row.get_by_role('button', name='シークレットを変更', exact=True).click()
    expect(dialog.get_by_label('クライアントID', exact=True)).to_have_value('work-app-id')
    dialog.get_by_label('クライアントシークレット', exact=True).fill('rotated-secret')
    dialog.get_by_role('button', name='変更', exact=True).click()
    expect(page.get_by_text('変更しました。', exact=True)).to_be_visible()

    # Removing it says what stops, and then stops it: the connection waits to be connected again.
    row.get_by_role('button', name='削除', exact=True).click()
    expect(dialog.get_by_text('このアプリで作った接続が1件あります。削除すると、別のアプリでつなぎ直すまで使えなくなります。', exact=True)).to_be_visible()
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'remove-app.png'), full_page=True)
    dialog.get_by_role('button', name='削除', exact=True).click()
    expect(page.get_by_text('削除しました。1件の接続がつなぎ直し待ちになりました。', exact=True)).to_be_visible()
    expect(connections.get_by_text('接続し直しが必要です', exact=True)).to_be_visible()

    # An AI asks for an app to be registered; the owner types its values, and the AI learns only its id.
    request = page.evaluate("""async () => {
      const made = await (await fetch('/v1/principals', {method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({name: 'UI test agent', agent: true})})).json();
      const key = { ...made, ...await (await fetch('/v1/principals/' + made.principal.id + '/credentials', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({kind: 'key'})})).json() };
      const owner = key.principal.acts_for[0];
      const made = await (await fetch('/v1/requests?as=' + owner, {method: 'POST', headers: {'content-type': 'application/json', authorization: 'Bearer ' + key.token},
        body: JSON.stringify({authorization_details: [{type: 'app', service: 'cloudflare', name: 'メール用'}], binding_message: 'メールの転送を設定できるアプリを使います。',
          steps: ['CloudflareのOAuth clientsでアプリを作ります。']})})).json();
      return {path: '/requests/' + made.request.id, id: made.request.id, token: key.token, owner};
    }""")
    page.goto(args.base + request['path'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='CloudflareのOAuthアプリを登録', exact=True)).to_be_visible()
    expect(page.get_by_label('名前', exact=True)).to_have_value('メール用')
    page.get_by_label('クライアントID', exact=True).fill('mail-app-id')
    page.get_by_label('クライアントシークレット', exact=True).fill('mail-app-secret')
    for width in [1280, 390]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots:
            page.screenshot(path=str(shots / f'app-request-{width}.png'), full_page=True)
    page.get_by_role('button', name='登録する', exact=True).click()
    expect(page.get_by_role('heading', name='OAuthアプリを登録しました', exact=True)).to_be_visible()
    result = page.evaluate("""async (request) => (await (await fetch('/v1/requests/' + request.id + '?as=' + request.owner,
      {headers: {authorization: 'Bearer ' + request.token}})).json()).request""", request)
    assert result['status'] == 'granted' and result['result']['app_id'], result
    assert 'mail-app-secret' not in json.dumps(result)
    assert not errors, errors
    browser.close()
    print('OAuth apps: 追加・アプリを通した接続・シークレットの変更・削除と接続の停止・AIの依頼による登録と、PC・スマートフォンの表示を確認しました。')
