import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '設計意図', '作業報告', 'refresh_token', 'client_secret', 'gcp-access-', 'gcp-refresh-', 'fdn_']:
        assert phrase not in text, phrase
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')


with tempfile.TemporaryDirectory(prefix='foundation-gcp-ui-') as private_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': private_dir + '/key'}

    def cli(*command):
        result = subprocess.run(['node', 'cli/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert all(value not in result.stdout + result.stderr for value in ['gcp-access-', 'gcp-refresh-', 'fdn_'])
        return json.loads(result.stdout.split('\n\nKey file')[0])

    approval = cli('connect', '--name', 'dev-us のAI')['request']
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1000})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(approval['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/login/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()

    request = cli('api', 'POST', '/v1/requests', '--json', json.dumps({'connector': 'gcp.oauth', 'purpose': 'Google Cloudの設定を確認します。リソースの作成や変更はしません。'}))['request']
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='Googleで接続', exact=True)).to_be_visible()
    expect(page.locator('.approval-facts')).to_contain_text('Google Cloudの操作')
    expect(page.get_by_text('特定のプロジェクトには限定されません。操作により料金が発生する場合があります。', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots and width == 390:
            page.screenshot(path=str(shots / 'gcp-request-mobile.png'), full_page=True)

    authorization = {'deny': True, 'account': 'personal'}

    def consent(route):
        values = parse_qs(urlparse(route.request.url).query)
        assert values['code_challenge_method'] == ['S256']
        assert values['access_type'] == ['offline']
        assert 'https://www.googleapis.com/auth/cloud-platform' in values['scope'][0]
        redirect = values['redirect_uri'][0]
        assert redirect == args.base + '/oauth/gcp.oauth/callback'
        query = {'state': values['state'][0]}
        query.update({'error': 'access_denied'} if authorization['deny'] else {'code': authorization['account']})
        route.fulfill(status=302, headers={'location': redirect + '?' + urlencode(query)}, body='')

    page.route('https://accounts.google.com/o/oauth2/v2/auth?*', consent)
    page.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_text('登録をキャンセルしました。', exact=True)).to_be_visible()
    authorization['deny'] = False
    page.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_role('heading', name='登録しました', exact=True)).to_be_visible()
    review(page)
    connection = cli('api', 'GET', '/v1/requests/' + request['id'])['request']['result']['connection_id']
    saved = cli('api', 'POST', '/v1/functions/connection.credentials', '--json', json.dumps({'connection_id': connection, 'save': {'CLOUDSDK_AUTH_ACCESS_TOKEN': 'cloud token'}}))
    assert saved['facts']['iam_checked'] is False
    assert saved['facts']['missing_scopes'] == []
    assert saved['saved'][0]['name'] == 'cloud token'

    # If gcloud is installed, prove it consumes the delivered token against a local fake API.
    # No existing gcloud configuration, credentials, or real Google API is used.
    gcloud = shutil.which('gcloud')
    if gcloud:
        calls = []

        class CloudApi(BaseHTTPRequestHandler):
            def do_GET(self):
                valid = self.headers.get('authorization') == 'Bearer gcp-access-personal-0'
                calls.append((self.path, valid))
                self.send_response(200 if valid else 401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'projects': [{'projectId': 'foundation-fixture', 'name': 'Foundation fixture', 'projectNumber': '123', 'lifecycleState': 'ACTIVE'}]}).encode())

            def log_message(self, *unused):
                pass

        cloud = ThreadingHTTPServer(('127.0.0.1', 0), CloudApi)
        thread = threading.Thread(target=cloud.serve_forever, daemon=True)
        thread.start()
        isolated = {key: value for key, value in env.items() if not key.startswith(('CLOUDSDK_', 'GOOGLE_'))}
        isolated.update({'CLOUDSDK_CONFIG': private_dir + '/gcloud', 'CLOUDSDK_CORE_DISABLE_USAGE_REPORTING': 'true',
                         'CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK': 'true',
                         'CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDRESOURCEMANAGER': 'http://127.0.0.1:' + str(cloud.server_port) + '/'})
        try:
            command = subprocess.run(['node', 'cli/runtime.mjs', 'exec', 'CLOUDSDK_AUTH_ACCESS_TOKEN=cloud token', '--', gcloud,
                                      'projects', 'list', '--project=foundation-fixture', '--format=value(projectId)', '--quiet'],
                                     env=isolated, capture_output=True, text=True, timeout=30)
            assert command.returncode == 0, command.stderr
            assert command.stdout.strip() == 'foundation-fixture', command.stdout
            assert calls and all(valid and path.startswith('/v1/projects') for path, valid in calls)
            assert 'gcp-access-' not in command.stdout + command.stderr
        finally:
            cloud.shutdown()
            cloud.server_close()
            thread.join()

    page.goto(args.base + '/connections', wait_until='networkidle')
    add = page.locator('.agent-row').filter(has=page.get_by_role('heading', name='Google Cloud', exact=True))
    add.get_by_role('button', name='Googleで接続', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text('特定のプロジェクトには限定されません。', exact=False)).to_be_visible()
    review(page)
    authorization['account'] = 'work'
    dialog.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_text('認証情報を登録しました。', exact=True)).to_be_visible()
    page.goto(args.base + '/connections', wait_until='networkidle')
    expect(page.get_by_role('heading', name='personal@example.test', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='work@example.test', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots and width != 320:
            page.screenshot(path=str(shots / ('gcp-desktop.png' if width == 1280 else 'gcp-mobile.png')), full_page=True)

    row = page.locator('.agent-row').filter(has=page.get_by_role('heading', name='personal@example.test', exact=True))
    row.get_by_role('button', name='接続し直す', exact=True).click()
    authorization['account'] = 'personal'
    dialog.get_by_role('button', name='Googleで接続', exact=True).click()
    expect(page.get_by_text('認証情報を登録しました。', exact=True)).to_be_visible()
    page.goto(args.base + '/connections', wait_until='networkidle')
    row.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_text('他のGoogle接続も使えなくなる場合があります。', exact=False)).to_be_visible()
    review(page)
    dialog.get_by_label('Google Cloud側の許可も取り消す').uncheck()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_role('heading', name='work@example.test', exact=True)).to_be_visible()
    page.goto(args.base + '/secrets', wait_until='networkidle')
    expect(page.get_by_role('heading', name='cloud token', exact=True)).to_be_visible()
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('GCP browser flow passed: approval URL, cancellation, connection, multiple accounts, reconnection, disconnection, CLI delivery, desktop/mobile.'
          + (' Native gcloud used only the local fake API.' if gcloud else ' Native gcloud check skipped (not installed).'))
