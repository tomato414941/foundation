import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
SECRET = 'ghp_kept-ui-fixture-value'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    small = page.evaluate("""() => [...document.querySelectorAll('p, label, button, small, dt, dd, h2, h3')]
      .filter(el => el.checkVisibility() && parseFloat(getComputedStyle(el).fontSize) < 14)
      .map(el => el.tagName + ': ' + el.textContent.slice(0, 30))""")
    assert not small, small
    text = page.locator('body').inner_text()
    for phrase in ['実装', '開発者', '設計意図', 'fdn_', 'renewal']:
        assert phrase not in text, phrase


with tempfile.TemporaryDirectory(prefix='foundation-storage-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, stdin=None):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15, input=stdin or '')
        assert result.returncode == 0, result.stderr
        assert SECRET not in result.stdout + result.stderr
        return json.loads(result.stdout.split('\n\nKey file')[0])

    # Everything but connect and exec is plain HTTP, which is how an agent uses it.
    def api(method, path, body=None, headers=None):
        request = urllib.request.Request(args.base + path, method=method, data=body,
                                         headers={'authorization': 'Bearer ' + key, **(headers or {})})
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read() or b'{}')

    approval = cli('connect', '--name', 'dev-us のAI')['request']
    key = open(key_dir + '/runtime-key').read().strip()
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1000})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(approval['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    page.goto(args.base + '/auth/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()

    # Nothing kept yet, and the page says so.
    page.goto(args.base, wait_until='networkidle')
    expect(page.get_by_role('heading', name='シークレット', exact=True)).to_be_visible()
    expect(page.get_by_text('まだ何も預かっていません。', exact=False)).to_be_visible()
    review(page)

    # The key keeps two things, with no request and no approval: one handed to a command, one only read back.
    api('PUT', '/v1/secrets/github/token?env=GH_TOKEN&secret=true', SECRET.encode(), {'content-type': 'text/plain'})
    api('PUT', '/v1/secrets/release/expo-v3', json.dumps({'step': 'レビュー待ち'}).encode(), {'content-type': 'application/json'})
    page.reload(wait_until='networkidle')

    github = page.locator('[aria-labelledby="github-title"]')
    release = page.locator('[aria-labelledby="release-title"]')
    expect(github.get_by_role('heading', name='token', exact=True)).to_be_visible()
    expect(github.get_by_text('GH_TOKEN として渡す', exact=True)).to_be_visible()
    expect(release.get_by_role('heading', name='expo-v3', exact=True)).to_be_visible()
    expect(release.get_by_text('渡さない', exact=True)).to_be_visible()
    expect(github.get_by_text('dev-us のAI', exact=False).first).to_be_visible()
    assert SECRET not in page.locator('body').inner_text(), 'what is kept is never on the page itself'

    review(page)
    page.screenshot(path=str(shots / 'kept-desktop.png'), full_page=True)

    # The owner can fetch anything they keep, including what the key itself may not read back.
    opened = page.request.get(args.base + '/api/secrets/github%2Ftoken')
    assert opened.status == 200 and opened.text() == SECRET
    dialog = page.get_by_role('dialog')

    for width in [390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width == 390:
            page.screenshot(path=str(shots / 'kept-mobile.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Removing one takes it away from the key too.
    release.get_by_role('button', name='削除', exact=True).click()
    expect(dialog.get_by_role('heading', name='release/expo-v3 を削除しますか？', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert [row['path'] for row in api('GET', '/v1/secrets')['secrets']] == ['github/token']

    github.get_by_role('button', name='削除', exact=True).click()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_text('まだ何も預かっていません。', exact=False)).to_be_visible()
    assert api('GET', '/v1/secrets')['secrets'] == []
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Storage screen passed: what a key kept with no request, how each is handed over, fetching it as the owner, and removal reaching the key.')
