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


with tempfile.TemporaryDirectory(prefix='foundation-kept-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, stdin=None):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15, input=stdin)
        assert result.returncode == 0, result.stderr
        assert SECRET not in result.stdout + result.stderr
        return json.loads(result.stdout)

    approval = cli('connect', '--name', 'dev-us のAI')['request']
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

    # Both panels say so when the key has kept nothing.
    page.goto(args.base, wait_until='networkidle')
    expect(page.locator('#kept-title')).to_have_text('AIが預けた値')
    expect(page.locator('#documents-title')).to_have_text('AIの記録')
    expect(page.get_by_text('AIが預けた値はありません。', exact=True)).to_be_visible()
    review(page)

    # The key keeps a value and writes a document, with no request and no approval.
    cli('keep', '--service', 'GitHub', '--value', 'GH_TOKEN=' + SECRET)
    cli('write', 'release/expo-v3', stdin=json.dumps({'step': 'レビュー待ち', 'pull_request': 42}))
    page.reload(wait_until='networkidle')

    kept = page.locator('[aria-labelledby="kept-title"]')
    expect(kept.get_by_role('heading', name='GitHub', exact=True)).to_be_visible()
    expect(kept.get_by_text('GH_TOKEN', exact=True)).to_be_visible()
    expect(kept.get_by_text('dev-us のAI', exact=False)).to_be_visible()
    assert SECRET not in page.locator('body').inner_text(), 'the value itself is not on the page until asked for'

    documents = page.locator('[aria-labelledby="documents-title"]')
    expect(documents.get_by_role('heading', name='release / expo-v3', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'kept-desktop.png'), full_page=True)

    # The owner looks inside each.
    kept.get_by_role('button', name='中身を見る', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text(SECRET, exact=True)).to_be_visible()
    review(page)
    dialog.get_by_role('button', name='閉じる', exact=True).click()

    documents.get_by_role('button', name='中身を見る', exact=True).click()
    expect(dialog.get_by_text('レビュー待ち', exact=False)).to_be_visible()
    review(page)
    dialog.get_by_role('button', name='閉じる', exact=True).click()

    for width in [390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width == 390:
            page.screenshot(path=str(shots / 'kept-mobile.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Removing one takes it away from the key too.
    documents.get_by_role('button', name='削除', exact=True).click()
    expect(dialog.get_by_role('heading', name='release / expo-v3 を削除しますか？', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_text('AIの記録はありません。', exact=True)).to_be_visible()
    assert cli('documents')['documents'] == []

    kept.get_by_role('button', name='削除', exact=True).click()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert cli('values')['values'] == []
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Kept storage screens passed: both panels, what a key kept with no request, looking inside, and removal reaching the key.')
