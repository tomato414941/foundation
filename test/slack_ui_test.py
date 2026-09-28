import argparse
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from playwright.sync_api import sync_playwright, expect

# Slack, against the fixture server with FOUNDATION_TEST_SLACK=1, where Foundation has no Slack app of its own: the
# owner adds their Slack app, connects a workspace through it with the bot scopes they choose, sees the workspace and
# the scopes Slack gave, and disconnects it. Slack's consent screen is answered here; its Web API is the fixture's fake.
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
    for phrase in ['bot-secret', 'xoxb-', 'client_secret', '実装', '設計意図']:
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
    expect(connect.get_by_role('heading', name='Slack', exact=True)).to_be_visible()
    connect.get_by_role('button', name='Slackで接続', exact=True).click()
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'slack-add-app.png'), full_page=True)
    # With no app yet, connecting starts by adding one: the owner's own Slack app.
    expect(dialog.get_by_role('heading', name='OAuthアプリを追加', exact=True)).to_be_visible()
    expect(dialog.get_by_label('接続先', exact=True)).to_have_value('slack.oauth')
    expect(dialog.get_by_text(args.base + '/oauth/slack.oauth/callback', exact=True)).to_be_visible()
    dialog.get_by_label('名前', exact=True).fill('自分のBot')
    dialog.get_by_label('クライアントID', exact=True).fill('bot-client')
    dialog.get_by_label('クライアントシークレット', exact=True).fill('bot-secret')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()

    # Connecting asks Slack for the bot scopes the owner writes, through that app.
    asked = {}

    def consent(route):
        values = parse_qs(urlparse(route.request.url).query)
        asked.update({key: values[key][0] for key in ['client_id', 'scope']})
        query = {'state': values['state'][0], 'code': 'personal'}
        route.fulfill(status=302, headers={'location': values['redirect_uri'][0] + '?' + urlencode(query)}, body='')

    page.route('https://slack.com/oauth/v2/authorize?*', consent)
    connect.get_by_role('button', name='Slackで接続', exact=True).click()
    expect(dialog.get_by_label('OAuthアプリ', exact=True)).to_have_value(page.evaluate("async () => (await (await fetch('/v1/holdings?kind=app')).json()).holdings.find(app => !app.foundation).id"))
    dialog.get_by_label('許可する権限（1行に1つ）', exact=True).fill('channels:read\nchat:write')
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'slack-connect.png'), full_page=True)
    dialog.get_by_role('button', name='Slackで接続', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    assert asked == {'client_id': 'bot-client', 'scope': 'channels:read,chat:write'}, asked
    page.goto(args.base + '/connections', wait_until='networkidle')
    connections = page.locator('[aria-labelledby="connections-title"]')
    expect(connections.get_by_text('個人のワークスペース', exact=True)).to_be_visible()
    expect(connections.get_by_text('OAuthアプリ：自分のBot', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots and width != 320:
            page.screenshot(path=str(shots / ('slack-desktop.png' if width == 1280 else 'slack-mobile.png')), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Disconnecting takes the bot token back from Slack as well.
    connections.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_label('Slack側の許可も取り消す')).to_be_checked()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(connections.get_by_text('接続済みのサービスはありません。', exact=True)).to_be_visible()
    assert not errors, errors
    browser.close()
    print('Slack: 自分のアプリの追加・Botの権限を選んだ接続・ワークスペースの表示・取り消し付きの解除と、PC・スマートフォンの表示を確認しました。')
