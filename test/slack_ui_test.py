import argparse
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from ui_flows import start_connect
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
    page.goto(args.base + '/services', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/login/confirm?return_to=%2Fservices#token_hash=' + hashlib.sha256(b'owner@example.test').hexdigest() + '&email=owner%40example.test', wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    page.wait_for_url(args.base + '/services')
    page.wait_for_load_state('networkidle')
    dialog = page.get_by_role('dialog')
    connections = page.locator('[aria-label="サービス"]')

    # Slack can be connected two ways; Foundation has no Slack app here, and the choice says so.
    start_connect(page, 'Slack')
    expect(dialog.get_by_text('先にOAuthアプリの登録が要ります。', exact=False)).to_be_visible()
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'slack-ways.png'), full_page=True)

    # A bot token made at Slack: checked with Slack, then kept for the workspace it belongs to.
    dialog.get_by_role('button', name='トークンを入力する').click()
    expect(dialog.get_by_role('link', name='api.slack.com を開く ↗', exact=True)).to_be_visible()
    dialog.get_by_label('Bot User OAuth Token', exact=True).fill('xoxb-work-1-0')
    review(page)
    dialog.get_by_role('button', name='預ける', exact=True).click()
    expect(page.get_by_text('Slackに接続しました。', exact=True)).to_be_visible()
    expect(connections.get_by_text('仕事のワークスペース', exact=True)).to_be_visible()
    expect(connections.get_by_text('トークン', exact=True)).to_be_visible()

    # Logging in instead starts with the owner's own Slack app, then goes on to Slack's consent screen.
    start_connect(page, 'Slack', 'ログインして許可する')
    expect(dialog.get_by_role('heading', name='OAuthアプリを追加', exact=True)).to_be_visible()
    expect(dialog.get_by_label('サービス', exact=True)).to_have_value('slack')
    expect(dialog.get_by_text(args.base + '/oauth/callback', exact=True)).to_be_visible()
    dialog.get_by_label('名前', exact=True).fill('自分のBot')
    dialog.get_by_label('クライアントID', exact=True).fill('bot-client')
    dialog.get_by_label('クライアントシークレット', exact=True).fill('bot-secret')
    dialog.get_by_role('button', name='追加', exact=True).click()
    asked = {}

    def consent(route):
        values = parse_qs(urlparse(route.request.url).query)
        asked.update({key: values[key][0] for key in ['client_id', 'scope']})
        query = {'state': values['state'][0], 'code': 'personal'}
        route.fulfill(status=302, headers={'location': values['redirect_uri'][0] + '?' + urlencode(query)}, body='')

    page.route('https://slack.com/oauth/v2/authorize?*', consent)
    expect(dialog.get_by_role('heading', name='Slackに接続', exact=True)).to_be_visible()
    expect(dialog.get_by_label('OAuthアプリ', exact=True)).to_have_value(page.evaluate("async () => (await (await fetch('/v1/resources?kind=app')).json()).resources.find(app => !app.foundation).id"))
    dialog.get_by_label('許可する権限（1行に1つ）', exact=True).fill('channels:read\nchat:write')
    review(page)
    if shots:
        page.screenshot(path=str(shots / 'slack-connect.png'), full_page=True)
    dialog.get_by_role('button', name='Slackの画面へ', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    assert asked == {'client_id': 'bot-client', 'scope': 'channels:read,chat:write'}, asked
    page.goto(args.base + '/services', wait_until='networkidle')
    expect(connections.get_by_text('個人のワークスペース', exact=True)).to_be_visible()
    expect(connections.get_by_text('OAuthアプリ：自分のBot', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots and width != 320:
            page.screenshot(path=str(shots / ('slack-desktop.png' if width == 1280 else 'slack-mobile.png')), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Disconnecting the one made by consent takes its bot token back from Slack as well.
    connections.locator('.agent-row').filter(has_text='個人のワークスペース').get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_label('Slack側の許可も取り消す')).to_be_checked()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(connections.get_by_text('個人のワークスペース', exact=True)).to_have_count(0)
    expect(connections.get_by_text('仕事のワークスペース', exact=True)).to_be_visible()
    # An AI asks for a Slack token; the owner makes it at Slack and hands it over on the request's page.
    request = page.evaluate("""async () => {
      const key = await (await fetch('/v1/principals', {method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({name: 'UI test agent', actor: true, key: true})})).json();
      const owner = key.principal.acts_for[0].id;
      const made = await (await fetch('/v1/requests?as=' + owner, {method: 'POST', headers: {'content-type': 'application/json', authorization: 'Bearer ' + key.token},
        body: JSON.stringify({kind: 'connect', input: {service: 'slack', auth_scheme: 'token'}, purpose: 'チャンネルに要約を投稿します。',
          steps: ['Slackでアプリを作り、Bot User OAuth Tokenを写します。']})})).json();
      return '/requests/' + made.request.id;
    }""")
    page.goto(args.base + request, wait_until='networkidle')
    expect(page.get_by_role('heading', name='Slackに接続', exact=True)).to_be_visible()
    expect(page.get_by_text('トークンを入力する', exact=True)).to_be_visible()
    page.get_by_label('Bot User OAuth Token', exact=True).fill('xoxb-personal-2-0')
    for width in [1280, 390]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots:
            page.screenshot(path=str(shots / f'slack-token-request-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})
    page.get_by_role('button', name='預ける').click()
    expect(page.get_by_role('heading', name='接続しました', exact=True)).to_be_visible()
    expect(page.get_by_text('個人のワークスペース', exact=True)).to_be_visible()

    # A token kept by hand as a secret becomes Slack's, keeping its name, once Slack confirms it.
    page.goto(args.base + '/secrets', wait_until='networkidle')
    page.get_by_role('button', name='追加', exact=True).click()
    dialog.get_by_label('名前', exact=True).fill('slack/old-bot')
    dialog.get_by_label('値', exact=True).fill('xoxb-work-3-0')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    page.locator('.secret-row').filter(has_text='slack/old-bot').get_by_role('button', name='サービスのトークンにする', exact=True).click()
    dialog.get_by_label('サービス', exact=True).select_option('slack')
    review(page)
    dialog.get_by_role('button', name='確かめて移す', exact=True).click()
    expect(page.get_by_text('slack/old-bot をSlackの接続にしました。', exact=True)).to_be_visible()
    expect(page.get_by_text('シークレットはありません。', exact=True)).to_be_visible()
    assert not errors, errors
    browser.close()
    print('Slack: トークンでの接続・自分のアプリを通した接続・取り消し付きの解除・依頼ページでのトークンの受け渡し・シークレットからの移行と、PC・スマートフォンの表示を確認しました。')
