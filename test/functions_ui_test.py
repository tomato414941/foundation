import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
SECRET = 'tok-functions-ui-fixture'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '開発者', '設計意図', 'fdn_', SECRET]:
        assert phrase not in text, phrase


with tempfile.TemporaryDirectory(prefix='foundation-functions-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, ok=True):
        result = subprocess.run(['node', 'cli/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=30, input='')
        if ok:
            assert result.returncode == 0, result.stderr
        return result.stdout

    approval = json.loads(cli('connect', '--name', 'dev-us のAI').split('\n\nKey file')[0])['request']
    browser = p.chromium.launch(headless=True)
    page = browser.new_context(viewport={'width': 1280, 'height': 1000}).new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(approval['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    page.goto(args.base + '/login/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()

    # Nothing run yet: the page lists what Foundation can do, and says so.
    page.goto(args.base + '/functions', wait_until='networkidle')
    expect(page.get_by_role('heading', name='ファンクション', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='HTTPS リクエスト', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='接続の認証情報', exact=True)).to_be_visible()
    expect(page.get_by_text('まだ実行されていません。', exact=True)).to_be_visible()
    review(page)

    # The key sends one request through Foundation (the fixture reaches no real host, so it fails), and the owner sees the record.
    cli('api', 'PUT', '/v1/secrets?name=api%20token&secret=true', '--json', json.dumps(SECRET))
    cli('api', 'POST', '/v1/functions/http.request', '--json', json.dumps({'url': 'https://api.example.test/v1/items', 'headers': {'authorization': 'Bearer {{foundation:api token}}'}}), ok=False)
    page.reload(wait_until='networkidle')
    row = page.locator('.record-table tbody tr').first
    expect(row).to_contain_text('dev-us のAI')
    expect(row).to_contain_text('HTTPS リクエスト')
    expect(row).to_contain_text('GET api.example.test')
    expect(row).to_contain_text('失敗')
    review(page)
    page.screenshot(path=str(shots / 'functions.png'), full_page=True)
    for width in [390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width == 390:
            page.screenshot(path=str(shots / 'functions-mobile.png'), full_page=True)
    assert not errors, errors
    browser.close()
print('Functions screen passed: what Foundation does on a key\'s behalf, and the record of one run without its inputs.')
