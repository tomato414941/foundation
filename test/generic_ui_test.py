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
SECRET = 'sk-ant-fixture-value'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '開発者', '設計意図', 'fdn_', SECRET]:
        assert phrase not in text, phrase


with tempfile.TemporaryDirectory(prefix='foundation-generic-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command):
        result = subprocess.run(['node', 'src/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15)
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
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/auth/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()

    # The owner declares a key of their own: which service it belongs to, where it is made, and the value's name.
    page.goto(args.base, wait_until='networkidle')
    dialog = page.get_by_role('dialog')
    page.get_by_role('button', name='キーを登録', exact=True).click()
    dialog.get_by_label('サービス', exact=True).fill('Anthropic')
    dialog.get_by_label('キーの作成ページ', exact=True).fill('https://console.anthropic.com/settings/keys')
    dialog.get_by_label('変数名', exact=True).fill('ANTHROPIC_API_KEY')
    value = dialog.get_by_label('値', exact=True)
    expect(value).to_have_attribute('type', 'password')
    value.fill(SECRET)
    review(page)
    page.screenshot(path=str(shots / 'declare.png'), full_page=True)
    dialog.get_by_role('button', name='登録する', exact=True).click()
    expect(dialog).not_to_be_visible()

    section = page.locator('[aria-labelledby="anthropic-title"]')
    expect(section.locator('#anthropic-title')).to_have_text('Anthropic')
    expect(section.locator('.credential-heading h3')).to_have_text('Anthropic')
    expect(section.get_by_text('ANTHROPIC_API_KEY', exact=True)).to_be_visible()
    review(page)
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('declared-desktop.png' if width == 1280 else 'declared-mobile.png')), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    credential = cli('credentials')['credentials'][0]
    assert credential['service'] == 'Anthropic'
    assert credential['variables'] == ['ANTHROPIC_API_KEY']
    run = subprocess.run(['node', 'src/runtime.mjs', 'exec', credential['id'], '--', 'node', '-e', 'if(process.env.ANTHROPIC_API_KEY!==process.argv[1])process.exit(2);console.log("ready")', SECRET], env=env, capture_output=True, text=True, timeout=15)
    assert run.returncode == 0 and run.stdout.strip() == 'ready', run.stderr

    # The owner moves it to another service; the section follows the name they chose.
    section.get_by_role('button', name='編集', exact=True).click()
    dialog.get_by_label('サービス', exact=True).fill('Claude')
    dialog.get_by_role('button', name='保存', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.locator('[aria-labelledby="anthropic-title"]')).to_have_count(0)
    expect(page.locator('#claude-title')).to_have_text('Claude')
    assert cli('credentials')['credentials'][0]['service'] == 'Claude'
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Owner-declared key flow passed: declaration form, masked value, delivery under the declared name, and moving it to another service.')
