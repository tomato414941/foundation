import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from ui_flows import start_connect
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
    # The way that asks least comes first; pasting a token or using one's own app sit under it.
    dialog = start_connect(page, 'Cloudflare')
    expect(dialog.get_by_role('heading', name='Cloudflareに接続', exact=True)).to_be_visible()
    expect(dialog.get_by_role('button', name='トークンを使う', exact=True)).to_be_visible()
    expect(dialog.get_by_role('button', name='自分のOAuthアプリを使う', exact=True)).to_be_visible()
    if shots:
        page.screenshot(path=str(shots / 'cloudflare-consent.png'), full_page=True)

    authorization = {'deny': True, 'code': 'personal'}

    def consent(route):
        values = parse_qs(urlparse(route.request.url).query)
        assert values['redirect_uri'] == [args.base + '/oauth/callback']
        assert values['code_challenge_method'] == ['S256']
        assert 'offline_access' in values['scope'][0].split(' ')
        assert 'account-settings.read' in values['scope'][0].split(' '), 'what the owner typed is asked for'
        query = {'state': values['state'][0]}
        query.update({'error': 'access_denied'} if authorization['deny'] else {'code': authorization['code']})
        route.fulfill(status=302, headers={'location': values['redirect_uri'][0] + '?' + urlencode(query)}, body='')

    page.route('https://dash.cloudflare.com/oauth2/auth?*', consent)
    dialog.get_by_label('許可する権限（1行に1つ）', exact=True).fill('account-settings.read')
    dialog.get_by_role('button', name='Cloudflareの画面へ', exact=True).click()
    expect(page.get_by_text('接続をキャンセルしました。', exact=True)).to_be_visible()
    authorization['deny'] = False
    page.goto(args.base + '/services', wait_until='networkidle')
    start_connect(page, 'Cloudflare')
    dialog.get_by_label('許可する権限（1行に1つ）', exact=True).fill('account-settings.read')
    dialog.get_by_role('button', name='Cloudflareの画面へ', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    page.goto(args.base + '/services', wait_until='networkidle')
    expect(page.get_by_text('personal@example.test', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
        text = page.locator('body').inner_text()
        for private in ['cf-access-', 'cf-refresh-', 'test-cloudflare-secret']:
            assert private not in text
        if shots and width != 320:
            page.screenshot(path=str(shots / ('cloudflare-desktop.png' if width == 1280 else 'cloudflare-mobile.png')), full_page=True)

    row = page.locator('.agent-row').filter(has=page.get_by_text('personal@example.test', exact=True))
    row.get_by_role('button', name='接続し直す', exact=True).click()
    expect(dialog.get_by_role('heading', name='Cloudflareに接続し直す', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='Cloudflareの画面へ', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    page.goto(args.base + '/services', wait_until='networkidle')
    # A second authorization for the same user has its own local reference.
    first_id = page.evaluate("async () => (await (await fetch('/v1/principals/me/resources?kind=connection')).json()).resources[0].id")
    start_connect(page, 'Cloudflare')
    dialog.get_by_label('許可する権限（1行に1つ）', exact=True).fill('account-settings.read')
    dialog.get_by_role('button', name='Cloudflareの画面へ', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    page.goto(args.base + '/services', wait_until='networkidle')
    expect(page.get_by_text('personal@example.test', exact=True)).to_have_count(2)
    second_id = page.evaluate("async (first) => (await (await fetch('/v1/principals/me/resources?kind=connection')).json()).resources.find(c => c.id !== first).id", first_id)
    row = page.locator('.connection-row').filter(has=page.locator('[data-id="' + first_id + '"]'))

    # The agent asks to reconnect the exact first connection; no real mail or service is used.
    request_path = page.evaluate("""async (id) => {
      const made = await (await fetch('/v1/principals', {method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({name: 'UI test agent', agent: true})})).json();
      const key = { ...made, ...await (await fetch('/v1/principals/' + made.principal.id + '/credentials', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({kind: 'key'})})).json() };
      const owner = key.principal.acts_for[0];
      const response = await fetch('/v1/requests?as=' + owner, {method: 'POST', headers: {'content-type': 'application/json', authorization: 'Bearer ' + key.token},
        body: JSON.stringify({authorization_details: [{type: 'connection', service: 'cloudflare', connection_id: id}], binding_message: '共有アカウントへの接続を更新'})});
      if (response.status !== 201) throw new Error(await response.text());
      return '/requests/' + (await response.json()).request.id;
    }""", first_id)
    authorization['code'] = 'personal-shared'
    page.goto(args.base + request_path, wait_until='networkidle')
    expect(page.get_by_role('heading', name='Cloudflareに接続し直す', exact=True)).to_be_visible()
    expect(page.get_by_text('更新する接続', exact=True)).to_be_visible()
    expect(page.locator('.approval-facts')).to_contain_text('personal@example.test')
    if shots:
        page.screenshot(path=str(shots / 'cloudflare-reconnect-request.png'), full_page=True)
    page.get_by_role('button', name='Cloudflareの画面へ', exact=True).click()
    expect(dialog.get_by_role('heading', name='接続の変更を確認', exact=True)).to_be_visible()
    expect(dialog.get_by_text('変更前：Personal account', exact=False)).to_be_visible()
    expect(dialog.get_by_text('変更後：Shared account', exact=False)).to_be_visible()
    # Refresh keeps the pending review, including its original target.
    page.reload(wait_until='networkidle')
    expect(dialog.get_by_role('heading', name='接続の変更を確認', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'review horizontal overflow'
        if shots:
            page.screenshot(path=str(shots / ('cloudflare-review-' + str(width) + '.png')), full_page=True)
    dialog.get_by_role('button', name='この内容で更新', exact=True).click()
    expect(page.get_by_role('heading', name='接続しました', exact=True)).to_be_visible()
    connections = page.evaluate("async () => (await (await fetch('/v1/principals/me/resources?kind=connection')).json()).resources")
    assert len(connections) == 2
    assert next(c for c in connections if c['id'] == first_id)['facts']['observed_accounts']['items'][0]['name'] == 'Shared account'
    assert next(c for c in connections if c['id'] == second_id)['facts']['observed_accounts']['items'][0]['name'] == 'Personal account'
    page.goto(args.base + '/services', wait_until='networkidle')
    row.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_label('Cloudflare側の許可も取り消す', exact=True)).to_be_checked()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(page.get_by_text('解除しました。', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Cloudflare', exact=True)).to_have_count(1)
    assert not errors, errors
    browser.close()
    print('Cloudflare: 接続・同意拒否・再接続・解除と、PC・スマートフォンの表示を確認しました。')
