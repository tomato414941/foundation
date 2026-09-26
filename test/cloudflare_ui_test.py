import argparse
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
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
    page = browser.new_page(viewport={'width': 1280, 'height': 1000})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/grants', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/login/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    page.goto(args.base + '/grants', wait_until='networkidle')
    expect(page.get_by_role('heading', name='Cloudflare', exact=True)).to_be_visible()
    page.get_by_role('button', name='Cloudflareで接続', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_role('heading', name='Cloudflareに接続', exact=True)).to_be_visible()
    expect(dialog.get_by_text('ドメインの登録・更新には料金がかかります。', exact=False)).to_be_visible()
    if shots:
        page.screenshot(path=str(shots / 'cloudflare-consent.png'), full_page=True)

    authorization = {'deny': True}

    def consent(route):
        values = parse_qs(urlparse(route.request.url).query)
        assert values['redirect_uri'] == [args.base + '/oauth/cloudflare.oauth/callback']
        assert values['code_challenge_method'] == ['S256']
        assert 'offline_access' in values['scope'][0].split(' ')
        query = {'state': values['state'][0]}
        query.update({'error': 'access_denied'} if authorization['deny'] else {'code': 'personal'})
        route.fulfill(status=302, headers={'location': values['redirect_uri'][0] + '?' + urlencode(query)}, body='')

    page.route('https://dash.cloudflare.com/oauth2/auth?*', consent)
    dialog.get_by_role('button', name='Cloudflareで接続', exact=True).click()
    expect(page.get_by_text('登録をキャンセルしました。', exact=True)).to_be_visible()
    authorization['deny'] = False
    page.goto(args.base + '/grants', wait_until='networkidle')
    page.get_by_role('button', name='Cloudflareで接続', exact=True).click()
    dialog.get_by_role('button', name='Cloudflareで接続', exact=True).click()
    expect(page.get_by_text('認証情報を登録しました。', exact=True)).to_be_visible()
    page.goto(args.base + '/grants', wait_until='networkidle')
    expect(page.get_by_role('heading', name='personal@example.test', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
        text = page.locator('body').inner_text()
        for private in ['cf-access-', 'cf-refresh-', 'test-cloudflare-secret']:
            assert private not in text
        if shots and width != 320:
            page.screenshot(path=str(shots / ('cloudflare-desktop.png' if width == 1280 else 'cloudflare-mobile.png')), full_page=True)

    row = page.locator('.agent-row').filter(has=page.get_by_role('heading', name='personal@example.test', exact=True))
    row.get_by_role('button', name='接続し直す', exact=True).click()
    expect(dialog.get_by_role('heading', name='Cloudflareに接続し直す', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='Cloudflareで接続', exact=True).click()
    expect(page.get_by_text('認証情報を登録しました。', exact=True)).to_be_visible()
    page.goto(args.base + '/grants', wait_until='networkidle')
    row.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_label('Cloudflare側の許可も取り消す', exact=True)).to_be_checked()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(page.get_by_text('解除しました。', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Cloudflare', exact=True)).to_be_visible()
    assert not errors, errors
    browser.close()
    print('Cloudflare: 接続・同意拒否・再接続・解除と、PC・スマートフォンの表示を確認しました。')
