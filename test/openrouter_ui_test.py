import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from ui_flows import start_connect
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '開発者', '設計意図', 'refresh_token', 'client_secret', 'sk-or-v1-', 'fdn_']:
        assert phrase not in text, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'fdn_session' not in page.evaluate('document.cookie')


with tempfile.TemporaryDirectory(prefix='foundation-openrouter-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, success=True):
        result = subprocess.run(['node', 'cli/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == success, result.stderr + result.stdout
        assert 'sk-or-v1-' not in result.stdout + result.stderr and 'fdn_' not in result.stdout
        return json.loads(result.stdout.split('\n\nKey file')[0]) if success else None

    cli('init', '--name', 'laptop のAI'); approval = cli('join')['request']
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 1050})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(approval['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/signin/confirm?' + urlencode({'return_to': urlparse(page.url).path}) + '#token=' + base64.urlsafe_b64encode(hashlib.sha256(b'owner@example.test').digest()).rstrip(b'=').decode() + '&email=owner%40example.test', wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_load_state('networkidle')
    # The key is approved first; the registration is a separate request with no code.
    page.get_by_label('確認コード', exact=True).fill(approval['user_code'])
    page.get_by_role('button', name='許可する', exact=True).click()
    expect(page.get_by_role('heading', name='アクセスを許可しました', exact=True)).to_be_visible()
    owner_id = cli('api', 'GET', '/v1/principals/me')['acts_for'][0]
    request = cli('api', 'POST', '/v1/requests', '--json', json.dumps({'to': owner_id, 'authorization_details': [{'type': 'connection', 'service': 'openrouter'}], 'binding_message': '接続したキーの情報を確認。モデルは実行しません。'}))['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='OpenRouterに接続', exact=True)).to_be_visible()
    assert page.url == request['verification_uri']
    expect(page.get_by_role('button', name='許可する', exact=True)).to_have_count(0)
    review(page)
    authorization = {'deny': True, 'code': 'personal'}

    def consent(route):
        query = parse_qs(urlparse(route.request.url).query)
        assert query['code_challenge_method'] == ['S256']
        assert 'client_secret' not in query and 'code_verifier' not in query
        callback = query['callback_url'][0]
        assert parse_qs(urlparse(callback).query)['state']
        params = {'error': 'access_denied'} if authorization['deny'] else {'code': authorization['code']}
        route.fulfill(status=302, headers={'location': callback + '&' + urlencode(params)}, body='')

    page.route('https://openrouter.ai/auth?*', consent)
    page.get_by_role('button', name='OpenRouterの画面へ', exact=True).click()
    expect(page.get_by_text('接続をキャンセルしました。', exact=True)).to_be_visible()
    assert cli('api', 'GET', '/v1/principals/' + owner_id + '/resources?kind=connection')['resources'] == []
    authorization['deny'] = False
    page.get_by_role('button', name='OpenRouterの画面へ', exact=True).click()
    expect(page.get_by_role('heading', name='接続しました', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('approval-desktop.png' if width == 1280 else 'approval-mobile.png')), full_page=True)
    connection = cli('api', 'GET', '/v1/requests/' + request['id'])['request']['result']['connection_id']
    command = subprocess.run(['node', 'cli/runtime.mjs', 'exec', '--inputs', json.dumps([{'id': connection, 'output': 'OPENROUTER_API_KEY'}]), '--', 'node', '-e', 'if(!process.env.OPENROUTER_API_KEY)process.exit(2);console.log("ready")'], env=env, capture_output=True, text=True, timeout=15)
    assert command.returncode == 0 and command.stdout.strip() == 'ready', command.stderr

    page.goto(args.base + '/services', wait_until='networkidle')
    section = page.locator('[aria-label="サービス"]')
    assert 'Gmail' not in section.inner_text() and 'メール' not in section.inner_text()
    expect(section.get_by_role('button', name='接続し直す', exact=True)).to_have_count(0)
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1050})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('connections-desktop.png' if width == 1280 else 'connections-mobile.png')), full_page=True)

    page.goto(args.base + '/principals', wait_until='networkidle')
    runtime = page.locator('.agent-row').filter(has_text='laptop のAI')
    runtime.get_by_role('button', name='取り消す', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text('取得済みの外部サービスの認証情報は、接続先で失効させてください。', exact=True)).to_be_visible()
    review(page)
    dialog.get_by_role('button', name='許可を取り消す', exact=True).click()
    expect(dialog).not_to_be_visible()
    cli('api', 'GET', '/v1/principals/' + owner_id + '/resources?kind=connection', success=False)

    page.goto(args.base + '/services', wait_until='networkidle')
    section.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_text('OpenRouter側の許可は残ります。', exact=False)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'disconnect-mobile.png'), full_page=True)
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_text('接続はありません。', exact=True)).to_be_visible()

    # Starting one from the dashboard uses the same flow, and asks for nothing the service decides.
    page.goto(args.base + '/services', wait_until='networkidle')
    dialog = start_connect(page, 'OpenRouter')
    review(page)
    authorization['code'] = 'second'
    dialog.get_by_role('button', name='OpenRouterの画面へ', exact=True).click()
    expect(page.get_by_text('接続しました。', exact=True)).to_be_visible()
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('OpenRouter browser flow passed: signin, PKCE return/cancellation, explicit approval, CLI resume, delivery into a command, runtime revocation, manual key deletion notice, starting one from the dashboard, mobile. No paid API calls.')
